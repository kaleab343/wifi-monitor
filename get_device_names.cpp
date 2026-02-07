// Simple but Effective Device Name Discovery
// Uses: NetBIOS queries + Enhanced hostname resolution
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <thread>
#include "device_database.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

struct DeviceInfo {
    std::string ip;
    std::string mac;
    std::string manufacturer;
    std::string deviceType;
    std::string hostname;
    std::string realName;  // Best available name
    std::string username;
    std::string osInfo;
    bool isRouter;
    int priority;
};

std::map<std::string, DeviceInfo> allDevices;

std::string MacToString(BYTE* mac) {
    std::stringstream ss;
    for (int i = 0; i < 6; i++) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setfill('0') << std::setw(2) 
           << std::uppercase << (int)mac[i];
    }
    return ss.str();
}

// NetBIOS Name Query - Works great for Windows devices
std::string GetNetBIOSName(const std::string& ip) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return "";
    
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(137);
    inet_pton(AF_INET, ip.c_str(), &server.sin_addr);
    
    // NetBIOS Name Query packet (status query)
    unsigned char query[] = {
        0xA2, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4B, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
        0x00, 0x01
    };
    
    DWORD timeout = 50;  // Reduced to 50ms for maximum speed
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    if (sendto(sock, (char*)query, sizeof(query), 0, (struct sockaddr*)&server, sizeof(server)) > 0) {
        char buffer[512];
        int recvLen = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        
        if (recvLen > 56) {
            // Extract computer name from NetBIOS response
            std::string name;
            for (int i = 56; i < 71 && i < recvLen; i++) {
                if (buffer[i] >= 32 && buffer[i] <= 126 && buffer[i] != ' ') {
                    name += buffer[i];
                }
            }
            
            closesocket(sock);
            
            if (!name.empty()) {
                // Trim trailing spaces
                size_t end = name.find_last_not_of(" \t\r\n");
                if (end != std::string::npos) {
                    name = name.substr(0, end + 1);
                }
                return name;
            }
        }
    }
    
    closesocket(sock);
    return "";
}

// Enhanced DNS reverse lookup with retry
std::string GetHostnameEnhanced(const char* ipStr) {
    struct sockaddr_in sa;
    char hostname[256] = {0};
    
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ipStr, &sa.sin_addr);
    
    // Try reverse DNS (works for some devices)
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, sizeof(hostname), 
                    NULL, 0, NI_NAMEREQD) == 0) {
        if (strlen(hostname) > 0 && strcmp(hostname, ipStr) != 0) {
            // Remove domain suffix if present
            std::string name(hostname);
            size_t dotPos = name.find('.');
            if (dotPos != std::string::npos) {
                name = name.substr(0, dotPos);
            }
            return name;
        }
    }
    
    // Try without NI_NAMEREQD flag
    memset(hostname, 0, sizeof(hostname));
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, sizeof(hostname), 
                    NULL, 0, 0) == 0) {
        if (strlen(hostname) > 0 && strcmp(hostname, ipStr) != 0) {
            std::string name(hostname);
            size_t dotPos = name.find('.');
            if (dotPos != std::string::npos) {
                name = name.substr(0, dotPos);
            }
            return name;
        }
    }
    
    return "";
}

std::string ExtractUsername(const std::string& deviceName) {
    if (deviceName.empty()) return "";
    
    // Pattern: "DESKTOP-USERNAME", "USERNAME-PC", etc.
    size_t dashPos = deviceName.find('-');
    if (dashPos != std::string::npos && dashPos > 0) {
        std::string part1 = deviceName.substr(0, dashPos);
        std::string part2 = deviceName.substr(dashPos + 1);
        
        // Make uppercase for comparison
        std::transform(part1.begin(), part1.end(), part1.begin(), ::toupper);
        std::transform(part2.begin(), part2.end(), part2.begin(), ::toupper);
        
        if (part1 == "DESKTOP" || part1 == "LAPTOP" || part1 == "PC" || part1 == "WORKSTATION") {
            return deviceName.substr(dashPos + 1);
        }
        if (part2 == "PC" || part2 == "LAPTOP" || part2 == "DESKTOP") {
            return deviceName.substr(0, dashPos);
        }
    }
    
    // Pattern: "iPhone de John" or "iPad de Marie"
    size_t dePos = deviceName.find(" de ");
    if (dePos != std::string::npos) {
        return deviceName.substr(dePos + 4);
    }
    
    // Pattern: "Johns-iPhone" or "Maries-iPad"
    if (deviceName.find("iPhone") != std::string::npos || deviceName.find("iPad") != std::string::npos) {
        size_t iphonePos = deviceName.find("iPhone");
        size_t ipadPos = deviceName.find("iPad");
        size_t pos = (iphonePos != std::string::npos) ? iphonePos : ipadPos;
        
        if (pos > 0 && deviceName[pos-1] == '-') {
            return deviceName.substr(0, pos-1);
        }
    }
    
    return "";
}

std::string GuessOS(const DeviceInfo& dev) {
    std::string name = dev.realName;
    std::transform(name.begin(), name.end(), name.begin(), ::toupper);
    
    if (name.find("IPHONE") != std::string::npos) return "iOS";
    if (name.find("IPAD") != std::string::npos) return "iPadOS";
    if (name.find("ANDROID") != std::string::npos) return "Android";
    if (name.find("DESKTOP") != std::string::npos || name.find("-PC") != std::string::npos) return "Windows";
    if (name.find("MACBOOK") != std::string::npos || name.find("IMAC") != std::string::npos) return "macOS";
    
    // Guess from manufacturer
    if (dev.manufacturer == "Apple") return "iOS/macOS";
    if (dev.manufacturer == "Samsung" || dev.manufacturer == "Huawei" || dev.manufacturer == "Xiaomi") 
        return "Android";
    if (dev.manufacturer == "Intel" || dev.manufacturer == "Dell" || dev.manufacturer == "HP" || 
        dev.manufacturer == "Lenovo") 
        return "Windows";
    
    return "Unknown";
}

void QuickPing(const std::string& ip) {
    IPAddr destIP = inet_addr(ip.c_str());
    ULONG macAddr[2];
    ULONG macAddrLen = 6;
    SendARP(destIP, 0, macAddr, &macAddrLen);
}

void DeepScan(const std::string& baseIP) {
    std::vector<std::thread> threads;
    // Faster: scan only first 20 IPs in parallel
    for (int i = 1; i <= 20; i++) {
        threads.push_back(std::thread(QuickPing, baseIP + "." + std::to_string(i)));
    }
    for (auto& t : threads) if (t.joinable()) t.join();
}

std::string GetLocalIP() {
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    
    struct addrinfo* result = NULL;
    struct addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    
    if (getaddrinfo(hostname, NULL, &hints, &result) == 0) {
        for (struct addrinfo* ptr = result; ptr != NULL; ptr = ptr->ai_next) {
            if (ptr->ai_family == AF_INET) {
                struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)ptr->ai_addr;
                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, ipStr, INET_ADDRSTRLEN);
                
                if (strncmp(ipStr, "192.168.1.", 10) == 0) {
                    freeaddrinfo(result);
                    return std::string(ipStr);
                }
            }
        }
        freeaddrinfo(result);
    }
    return "192.168.1.4";
}

std::string GetLocalMAC(const std::string& targetIP) {
    ULONG outBufLen = 15000;
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
    
    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
    }
    
    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            if (std::string(pAdapter->IpAddressList.IpAddress.String) == targetIP) {
                std::stringstream ss;
                for (UINT i = 0; i < pAdapter->AddressLength; i++) {
                    if (i > 0) ss << ":";
                    ss << std::hex << std::setfill('0') << std::setw(2) 
                       << std::uppercase << (int)pAdapter->Address[i];
                }
                free(pAdapterInfo);
                return ss.str();
            }
            pAdapter = pAdapter->Next;
        }
    }
    free(pAdapterInfo);
    return "";
}

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    std::string localIP = GetLocalIP();
    std::string baseIP = localIP.substr(0, localIP.find_last_of('.'));
    
    // Suppress verbose output for speed
    // std::cerr << "Device Name Discovery - NetBIOS + DNS" << std::endl;
    // std::cerr << "Scanning: " << baseIP << ".0/24" << std::endl << std::endl;
    
    // Deep scan
    DeepScan(baseIP);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Add This PC
    std::string localMAC = GetLocalMAC(localIP);
    if (!localMAC.empty()) {
        DeviceInfo thisPC;
        thisPC.ip = localIP;
        thisPC.mac = localMAC;
        
        char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
        DWORD size = sizeof(computerName);
        GetComputerNameA(computerName, &size);
        
        thisPC.realName = std::string(computerName);
        thisPC.hostname = thisPC.realName;
        thisPC.manufacturer = GetManufacturer(localMAC);
        thisPC.deviceType = "This Computer";
        thisPC.username = computerName;
        thisPC.osInfo = "Windows";
        thisPC.isRouter = false;
        thisPC.priority = 2;
        
        allDevices[localMAC] = thisPC;
    }
    
    // Scan ARP table
    PMIB_IPNETTABLE pIpNetTable = NULL;
    DWORD dwSize = 0;
    GetIpNetTable(NULL, &dwSize, FALSE);
    pIpNetTable = (MIB_IPNETTABLE*)malloc(dwSize);
    
    if (pIpNetTable && GetIpNetTable(pIpNetTable, &dwSize, FALSE) == NO_ERROR) {
        for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
            MIB_IPNETROW* pRow = &pIpNetTable->table[i];
            
            BYTE firstOctet = (pRow->dwAddr) & 0xFF;
            bool isMulticast = (firstOctet >= 224 && firstOctet <= 239);
            bool isBroadcast = (pRow->dwAddr == 0xFFFFFFFF);
            bool isInvalidMAC = true;
            
            for (int j = 0; j < 6; j++) {
                if (pRow->bPhysAddr[j] != 0x00 && pRow->bPhysAddr[j] != 0xFF) {
                    isInvalidMAC = false;
                    break;
                }
            }
            
            if (isMulticast || isBroadcast || isInvalidMAC) continue;
            
            struct in_addr ipAddr;
            ipAddr.S_un.S_addr = pRow->dwAddr;
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ipAddr, ipStr, INET_ADDRSTRLEN);
            
            std::string ip(ipStr);
            if (ip.substr(0, 8) != "192.168.") continue;
            
            std::string mac = MacToString(pRow->bPhysAddr);
            if (mac == localMAC) continue;
            
            if (allDevices.find(mac) == allDevices.end()) {
                DeviceInfo dev;
                dev.ip = ip;
                dev.mac = mac;
                dev.manufacturer = GetManufacturer(mac);
                dev.deviceType = GetDeviceType(mac);
                dev.isRouter = (ip == "192.168.1.1" || ip == "192.168.0.1");
                dev.priority = dev.isRouter ? 0 : 3;
                
                // Try NetBIOS first (best for Windows) - suppress verbose output
                dev.realName = GetNetBIOSName(ip);
                
                if (dev.realName.empty()) {
                    // Fallback to DNS
                    dev.realName = GetHostnameEnhanced(ipStr);
                }
                
                dev.hostname = dev.realName.empty() ? "" : dev.realName;
                dev.username = ExtractUsername(dev.realName);
                dev.osInfo = GuessOS(dev);
                
                allDevices[mac] = dev;
            }
        }
    }
    
    if (pIpNetTable) free(pIpNetTable);
    
    // Output JSON
    std::vector<DeviceInfo> sortedDevices;
    for (auto& pair : allDevices) {
        sortedDevices.push_back(pair.second);
    }
    
    std::sort(sortedDevices.begin(), sortedDevices.end(), 
        [](const DeviceInfo& a, const DeviceInfo& b) {
            return a.priority < b.priority;
        });
    
    std::cout << "[" << std::endl;
    
    for (size_t i = 0; i < sortedDevices.size(); i++) {
        if (i > 0) std::cout << "," << std::endl;
        
        const DeviceInfo& dev = sortedDevices[i];
        
        std::cout << "  {" << std::endl;
        std::cout << "    \"ip\": \"" << dev.ip << "\"," << std::endl;
        std::cout << "    \"mac\": \"" << dev.mac << "\"," << std::endl;
        std::cout << "    \"manufacturer\": \"" << dev.manufacturer << "\"," << std::endl;
        std::cout << "    \"device_type\": \"" << dev.deviceType << "\"," << std::endl;
        std::cout << "    \"hostname\": \"" << dev.realName << "\"," << std::endl;
        std::cout << "    \"username\": \"" << dev.username << "\"," << std::endl;
        std::cout << "    \"os\": \"" << dev.osInfo << "\"," << std::endl;
        std::cout << "    \"is_router\": " << (dev.isRouter ? "true" : "false") << std::endl;
        std::cout << "  }";
    }
    
    std::cout << std::endl << "]" << std::endl;
    
    // std::cerr << "\nFound " << allDevices.size() << " devices" << std::endl;
    
    WSACleanup();
    return 0;
}
