// Enhanced Device Scanner with Detailed Information
// Shows: IP, MAC, Manufacturer, Device Type, Hostname, Username
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
#include <chrono>
#include <ctime>
#include "device_database.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

struct DetailedDeviceInfo {
    std::string ip;
    std::string mac;
    std::string manufacturer;
    std::string deviceType;
    std::string hostname;
    std::string username;
    std::string osInfo;
    bool isRouter;
    int priority;
    int seenCount;
};

std::map<std::string, DetailedDeviceInfo> allDevices;

std::string MacToString(BYTE* mac) {
    std::stringstream ss;
    for (int i = 0; i < 6; i++) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setfill('0') << std::setw(2) 
           << std::uppercase << (int)mac[i];
    }
    return ss.str();
}

std::string GetEnhancedHostname(const char* ipStr) {
    struct sockaddr_in sa;
    char hostname[256] = {0};
    
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ipStr, &sa.sin_addr);
    
    // Try reverse DNS lookup
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, sizeof(hostname), 
                    NULL, 0, NI_NOFQDN) == 0) {
        if (strcmp(hostname, ipStr) != 0 && strlen(hostname) > 0) {
            return std::string(hostname);
        }
    }
    
    // Try NetBIOS name resolution (Windows)
    char netbiosName[256] = {0};
    DWORD size = sizeof(netbiosName);
    
    // This is a simplified approach - in production you'd use NetBIOS API
    return std::string(hostname);
}

std::string ExtractUsernameFromHostname(const std::string& hostname) {
    // Try to extract username from hostname patterns like:
    // "DESKTOP-USERNAME", "USERNAME-PC", "USERNAME-LAPTOP", etc.
    
    if (hostname.empty()) return "";
    
    // Check for common patterns
    size_t dashPos = hostname.find('-');
    if (dashPos != std::string::npos) {
        std::string part1 = hostname.substr(0, dashPos);
        std::string part2 = hostname.substr(dashPos + 1);
        
        // If first part is generic, second part might be username
        if (part1 == "DESKTOP" || part1 == "LAPTOP" || part1 == "PC") {
            return part2;
        }
        
        // If second part is generic, first part might be username
        if (part2 == "PC" || part2 == "LAPTOP" || part2 == "DESKTOP") {
            return part1;
        }
    }
    
    // Check for patterns like "iPhone-de-username"
    if (hostname.find("iPhone") != std::string::npos || 
        hostname.find("iPad") != std::string::npos) {
        size_t lastDash = hostname.find_last_of('-');
        if (lastDash != std::string::npos) {
            return hostname.substr(lastDash + 1);
        }
    }
    
    return "";
}

std::string GuessOSFromHostname(const std::string& hostname, const std::string& manufacturer) {
    if (hostname.find("iPhone") != std::string::npos) return "iOS";
    if (hostname.find("iPad") != std::string::npos) return "iPadOS";
    if (hostname.find("android") != std::string::npos) return "Android";
    if (hostname.find("DESKTOP") != std::string::npos) return "Windows";
    if (hostname.find("MacBook") != std::string::npos) return "macOS";
    
    // Guess from manufacturer
    if (manufacturer == "Apple") return "iOS/macOS";
    if (manufacturer == "Samsung" || manufacturer == "Huawei" || manufacturer == "Xiaomi") 
        return "Android";
    if (manufacturer == "Intel" || manufacturer == "Dell" || manufacturer == "HP" || 
        manufacturer == "Lenovo") 
        return "Windows/Linux";
    
    return "Unknown";
}

void QuickPing(const std::string& ip) {
    IPAddr destIP = inet_addr(ip.c_str());
    ULONG macAddr[2];
    ULONG macAddrLen = 6;
    SendARP(destIP, 0, macAddr, &macAddrLen);
}

void DeepScanNetwork(const std::string& baseIP) {
    std::vector<std::thread> threads;
    
    for (int i = 1; i <= 50; i++) {
        std::string ip = baseIP + "." + std::to_string(i);
        threads.push_back(std::thread(QuickPing, ip));
        
        if (threads.size() >= 10) {
            for (auto& t : threads) {
                if (t.joinable()) t.join();
            }
            threads.clear();
        }
    }
    
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
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
            std::string ip = pAdapter->IpAddressList.IpAddress.String;
            if (ip == targetIP) {
                std::stringstream macStream;
                for (UINT i = 0; i < pAdapter->AddressLength; i++) {
                    if (i > 0) macStream << ":";
                    macStream << std::hex << std::setfill('0') << std::setw(2) 
                             << std::uppercase << (int)pAdapter->Address[i];
                }
                free(pAdapterInfo);
                return macStream.str();
            }
            pAdapter = pAdapter->Next;
        }
    }
    
    free(pAdapterInfo);
    return "";
}

void ScanDevices() {
    std::string localIP = GetLocalIP();
    std::string baseIP = localIP.substr(0, localIP.find_last_of('.'));
    
    std::cerr << "Scanning network: " << baseIP << ".0/24" << std::endl;
    
    // Deep scan
    DeepScanNetwork(baseIP);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Add this PC
    std::string localMAC = GetLocalMAC(localIP);
    if (!localMAC.empty()) {
        DetailedDeviceInfo thisPC;
        thisPC.ip = localIP;
        thisPC.mac = localMAC;
        
        char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
        DWORD size = sizeof(computerName);
        GetComputerNameA(computerName, &size);
        
        thisPC.hostname = std::string(computerName);
        thisPC.manufacturer = GetManufacturer(localMAC);
        thisPC.deviceType = "This Computer";
        thisPC.username = computerName; // On Windows, computer name often contains username
        thisPC.osInfo = "Windows";
        thisPC.isRouter = false;
        thisPC.priority = 2;
        thisPC.seenCount = 1;
        
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
            
            bool isMulticastMAC = (pRow->bPhysAddr[0] == 0x01 && pRow->bPhysAddr[1] == 0x00);
            
            if (!isMulticast && !isBroadcast && !isInvalidMAC && !isMulticastMAC) {
                struct in_addr ipAddr;
                ipAddr.S_un.S_addr = pRow->dwAddr;
                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ipAddr, ipStr, INET_ADDRSTRLEN);
                
                std::string ip(ipStr);
                if (ip.substr(0, 8) != "192.168.") continue;
                
                std::string mac = MacToString(pRow->bPhysAddr);
                if (mac == localMAC) continue; // Skip this PC
                
                if (allDevices.find(mac) == allDevices.end()) {
                    DetailedDeviceInfo dev;
                    dev.ip = ip;
                    dev.mac = mac;
                    dev.manufacturer = GetManufacturer(mac);
                    dev.deviceType = GetDeviceType(mac);
                    dev.hostname = GetEnhancedHostname(ipStr);
                    dev.username = ExtractUsernameFromHostname(dev.hostname);
                    dev.osInfo = GuessOSFromHostname(dev.hostname, dev.manufacturer);
                    dev.isRouter = (ip == "192.168.1.1" || ip == "192.168.0.1");
                    dev.priority = dev.isRouter ? 0 : 3;
                    dev.seenCount = 1;
                    
                    allDevices[mac] = dev;
                }
            }
        }
    }
    
    if (pIpNetTable) free(pIpNetTable);
    
    std::cerr << "Found " << allDevices.size() << " devices" << std::endl;
}

void OutputJSON() {
    std::vector<DetailedDeviceInfo> sortedDevices;
    for (auto& pair : allDevices) {
        sortedDevices.push_back(pair.second);
    }
    
    std::sort(sortedDevices.begin(), sortedDevices.end(), 
        [](const DetailedDeviceInfo& a, const DetailedDeviceInfo& b) {
            return a.priority < b.priority;
        });
    
    std::cout << "[" << std::endl;
    
    for (size_t i = 0; i < sortedDevices.size(); i++) {
        if (i > 0) std::cout << "," << std::endl;
        
        const DetailedDeviceInfo& dev = sortedDevices[i];
        
        std::cout << "  {" << std::endl;
        std::cout << "    \"ip\": \"" << dev.ip << "\"," << std::endl;
        std::cout << "    \"mac\": \"" << dev.mac << "\"," << std::endl;
        std::cout << "    \"manufacturer\": \"" << dev.manufacturer << "\"," << std::endl;
        std::cout << "    \"device_type\": \"" << dev.deviceType << "\"," << std::endl;
        std::cout << "    \"hostname\": \"" << dev.hostname << "\"," << std::endl;
        std::cout << "    \"username\": \"" << dev.username << "\"," << std::endl;
        std::cout << "    \"os\": \"" << dev.osInfo << "\"," << std::endl;
        std::cout << "    \"is_router\": " << (dev.isRouter ? "true" : "false") << std::endl;
        std::cout << "  }";
    }
    
    std::cout << std::endl << "]" << std::endl;
}

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    ScanDevices();
    OutputJSON();
    
    WSACleanup();
    return 0;
}
