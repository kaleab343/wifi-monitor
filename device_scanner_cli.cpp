// Simple CLI tool to export device list as JSON for Python
// MIT License
// Copyright (c) 2026 NetWatch Pro Contributors
// https://opensource.org/licenses/MIT

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <algorithm>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

struct DeviceInfo {
    std::string ip;
    std::string mac;
    std::string hostname;
    std::string type;
    bool isRouter;
    int priority; // For sorting: 0=router, 2=this PC, 3=others
};

void QuickPing(const std::string& ip) {
    // Quick ARP request (faster than ICMP)
    IPAddr destIP = inet_addr(ip.c_str());
    ULONG macAddr[2];
    ULONG macAddrLen = 6;
    SendARP(destIP, 0, macAddr, &macAddrLen);
}

void DeepScanNetwork(const std::string& baseIP) {
    // Scan common IP range (1-50) in parallel for speed
    std::vector<std::thread> threads;
    
    for (int i = 1; i <= 50; i++) {
        std::string ip = baseIP + "." + std::to_string(i);
        threads.push_back(std::thread(QuickPing, ip));
        
        // Process in batches of 10 to avoid overwhelming
        if (threads.size() >= 10) {
            for (auto& t : threads) {
                if (t.joinable()) t.join();
            }
            threads.clear();
        }
    }
    
    // Wait for remaining threads
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
}

std::string GetDeviceType(BYTE* mac) {
    // Apple
    if (mac[0] == 0xF0 && mac[1] == 0x18 && mac[2] == 0x98) return "iPhone/iPad";
    if (mac[0] == 0x3C && mac[1] == 0x22 && mac[2] == 0xFB) return "iPhone";
    
    // Samsung
    if (mac[0] == 0x28 && mac[1] == 0xF0 && mac[2] == 0x76) return "Samsung Phone";
    if (mac[0] == 0xE8 && mac[1] == 0x50 && mac[2] == 0x8B) return "Samsung TV";
    
    // Huawei
    if (mac[0] == 0xE0 && mac[1] == 0x51 && mac[2] == 0xD8) return "Huawei Phone";
    
    // Laptop/PC
    if (mac[0] == 0x04 && mac[1] == 0xD6 && mac[2] == 0xAA) return "Laptop/PC";
    
    // Router
    if (mac[0] == 0x00 && mac[1] == 0x4C && mac[2] == 0xE5) return "WiFi Router";
    
    return "Unknown Device";
}

std::string GetHostname(const char* ipStr) {
    struct sockaddr_in sa;
    char hostname[256];
    
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ipStr, &sa.sin_addr);
    
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, sizeof(hostname), NULL, 0, NI_NOFQDN) == 0) {
        if (strcmp(hostname, ipStr) != 0 && strlen(hostname) > 0) {
            return std::string(hostname);
        }
    }
    return "";
}

std::string GetLocalMAC() {
    ULONG outBufLen = 15000;
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
    
    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
    }
    
    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            // Type 71 = WiFi, Type 6 = Ethernet
            if (pAdapter->Type == 71 || pAdapter->Type == 6) {
                std::string ip = pAdapter->IpAddressList.IpAddress.String;
                // Match the adapter with 192.168.1.x IP
                if (ip != "0.0.0.0" && ip.substr(0, 10) == "192.168.1.") {
                    std::stringstream macStream;
                    for (UINT i = 0; i < pAdapter->AddressLength; i++) {
                        if (i > 0) macStream << ":";
                        macStream << std::hex << std::setfill('0') << std::setw(2) 
                                 << std::uppercase << (int)pAdapter->Address[i];
                    }
                    free(pAdapterInfo);
                    return macStream.str();
                }
            }
            pAdapter = pAdapter->Next;
        }
    }
    
    free(pAdapterInfo);
    return "";
}

std::string GetLocalIP() {
    ULONG outBufLen = 15000;
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
    
    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
    }
    
    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            // Type 71 = WiFi, Type 6 = Ethernet
            if (pAdapter->Type == 71 || pAdapter->Type == 6) {
                std::string ip = pAdapter->IpAddressList.IpAddress.String;
                // Prioritize 192.168.1.x network
                if (ip != "0.0.0.0" && ip.substr(0, 10) == "192.168.1.") {
                    free(pAdapterInfo);
                    return ip;
                }
            }
            pAdapter = pAdapter->Next;
        }
    }
    
    free(pAdapterInfo);
    return "";
}

int main() {
    // Initialize Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    // Get local PC info
    std::string localIP = GetLocalIP();
    std::string localMAC = GetLocalMAC();
    
    // Get computer name
    char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
    std::string hostname(computerName);
    
    // Determine base IP for deep scan
    std::string baseIP = "192.168.1";
    if (!localIP.empty()) {
        size_t lastDot = localIP.find_last_of('.');
        if (lastDot != std::string::npos) {
            baseIP = localIP.substr(0, lastDot);
        }
    }
    
    // Deep scan the network to populate ARP table
    DeepScanNetwork(baseIP);
    
    // Small delay to let ARP table update
    Sleep(500);
    
    // Collect all devices
    std::vector<DeviceInfo> allDevices;
    
    // Add This PC
    if (!localIP.empty() && !localMAC.empty()) {
        DeviceInfo thisPC;
        thisPC.ip = localIP;
        thisPC.mac = localMAC;
        thisPC.hostname = hostname.empty() ? "This PC" : hostname + " (This PC)";
        thisPC.type = "This Computer";
        thisPC.isRouter = false;
        thisPC.priority = 2; // This PC comes after router
        allDevices.push_back(thisPC);
    }
    
    // Get devices from ARP table
    PMIB_IPNETTABLE pIpNetTable = NULL;
    DWORD dwSize = 0;
    GetIpNetTable(NULL, &dwSize, FALSE);
    pIpNetTable = (MIB_IPNETTABLE*)malloc(dwSize);
    
    if (pIpNetTable && GetIpNetTable(pIpNetTable, &dwSize, FALSE) == NO_ERROR) {
        for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
            MIB_IPNETROW* pRow = &pIpNetTable->table[i];
            
            // Filter valid entries
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
            
            if ((pRow->dwType == MIB_IPNET_TYPE_DYNAMIC || pRow->dwType == MIB_IPNET_TYPE_STATIC) &&
                !isMulticast && !isBroadcast && !isInvalidMAC && !isMulticastMAC) {
                
                struct in_addr ipAddr;
                ipAddr.S_un.S_addr = pRow->dwAddr;
                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ipAddr, ipStr, INET_ADDRSTRLEN);
                
                std::stringstream macStream;
                for (int j = 0; j < 6; j++) {
                    if (j > 0) macStream << ":";
                    macStream << std::hex << std::setfill('0') << std::setw(2) 
                             << std::uppercase << (int)pRow->bPhysAddr[j];
                }
                
                std::string mac = macStream.str();
                
                // Skip if it's the local MAC (already added)
                if (mac == localMAC) continue;
                
                DeviceInfo dev;
                dev.ip = ipStr;
                dev.mac = mac;
                dev.hostname = GetHostname(ipStr);
                dev.type = GetDeviceType(pRow->bPhysAddr);
                dev.isRouter = (strcmp(ipStr, "192.168.1.1") == 0 || strcmp(ipStr, "192.168.0.1") == 0);
                dev.priority = dev.isRouter ? 0 : 3; // Router=0, ThisPC=2, Others=3
                
                allDevices.push_back(dev);
            }
        }
    }
    
    if (pIpNetTable) free(pIpNetTable);
    
    // Sort devices: Router first (0), This PC (1), Others (2)
    std::sort(allDevices.begin(), allDevices.end(), 
        [](const DeviceInfo& a, const DeviceInfo& b) {
            return a.priority < b.priority;
        });
    
    // Output sorted JSON
    std::cout << "[" << std::endl;
    
    for (size_t i = 0; i < allDevices.size(); i++) {
        if (i > 0) std::cout << "," << std::endl;
        
        const DeviceInfo& dev = allDevices[i];
        std::cout << "  {" << std::endl;
        std::cout << "    \"ip\": \"" << dev.ip << "\"," << std::endl;
        std::cout << "    \"mac\": \"" << dev.mac << "\"," << std::endl;
        std::cout << "    \"hostname\": \"" << dev.hostname << "\"," << std::endl;
        std::cout << "    \"type\": \"" << dev.type << "\"," << std::endl;
        std::cout << "    \"is_router\": " << (dev.isRouter ? "true" : "false") << std::endl;
        std::cout << "  }";
    }
    
    std::cout << std::endl << "]" << std::endl;
    
    WSACleanup();
    return 0;
}
