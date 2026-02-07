// Passive Device Discovery - Monitors ARP table changes over time
// No admin privileges required - uses ARP table monitoring
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>
#include <set>
#include <vector>
#include <algorithm>
#include <thread>
#include <chrono>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

struct DeviceInfo {
    std::string ip;
    std::string mac;
    std::string hostname;
    std::string type;
    bool isRouter;
    time_t firstSeen;
    time_t lastSeen;
    int seenCount;
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

std::string GetDeviceType(BYTE* mac) {
    if (mac[0] == 0x00 && mac[1] == 0x4C && mac[2] == 0xE5) return "WiFi Router";
    if (mac[0] == 0xE0 && mac[1] == 0x51 && mac[2] == 0xD8) return "Huawei Phone";
    if (mac[0] == 0xF0 && mac[1] == 0x18 && mac[2] == 0x98) return "iPhone/iPad";
    if (mac[0] == 0x3C && mac[1] == 0x22 && mac[2] == 0xFB) return "iPhone";
    if (mac[0] == 0x28 && mac[1] == 0xF0 && mac[2] == 0x76) return "Samsung Phone";
    if (mac[0] == 0x34 && mac[1] == 0x02 && mac[2] == 0x86) return "Samsung Device";
    if (mac[0] == 0x3C && mac[1] == 0x6A && mac[2] == 0xA7) return "Laptop/PC";
    return "Network Device";
}

void MonitorARPTable(int durationSeconds) {
    std::cerr << "Monitoring ARP table for " << durationSeconds << " seconds..." << std::endl;
    std::cerr << "Watching for device activity..." << std::endl << std::endl;
    
    time_t startTime = time(nullptr);
    int scanCount = 0;
    
    while (time(nullptr) - startTime < durationSeconds) {
        scanCount++;
        
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
                    
                    // Only 192.168.x.x networks
                    std::string ip(ipStr);
                    if (ip.substr(0, 8) != "192.168.") continue;
                    
                    std::string mac = MacToString(pRow->bPhysAddr);
                    
                    // New device discovered
                    if (allDevices.find(mac) == allDevices.end()) {
                        DeviceInfo dev;
                        dev.ip = ip;
                        dev.mac = mac;
                        dev.hostname = GetHostname(ipStr);
                        dev.type = GetDeviceType(pRow->bPhysAddr);
                        dev.isRouter = (ip == "192.168.1.1" || ip == "192.168.0.1");
                        dev.firstSeen = time(nullptr);
                        dev.lastSeen = time(nullptr);
                        dev.seenCount = 1;
                        
                        allDevices[mac] = dev;
                        
                        std::cerr << "✓ New device: " << ip << " (" << mac << ") - " 
                                  << dev.type << std::endl;
                    } else {
                        // Update existing device
                        allDevices[mac].lastSeen = time(nullptr);
                        allDevices[mac].seenCount++;
                        
                        // Update IP if changed
                        if (allDevices[mac].ip != ip) {
                            std::cerr << "  IP changed: " << mac << " from " 
                                      << allDevices[mac].ip << " to " << ip << std::endl;
                            allDevices[mac].ip = ip;
                        }
                    }
                }
            }
        }
        
        if (pIpNetTable) free(pIpNetTable);
        
        // Wait 500ms between scans
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    std::cerr << "\nMonitoring complete. Performed " << scanCount << " scans." << std::endl;
    std::cerr << "Discovered " << allDevices.size() << " unique devices." << std::endl;
}

void OutputJSON() {
    // Sort: Router first, then by IP
    std::vector<DeviceInfo> sortedDevices;
    for (auto& pair : allDevices) {
        sortedDevices.push_back(pair.second);
    }
    
    std::sort(sortedDevices.begin(), sortedDevices.end(), 
        [](const DeviceInfo& a, const DeviceInfo& b) {
            if (a.isRouter != b.isRouter) return a.isRouter;
            return a.ip < b.ip;
        });
    
    std::cout << "[" << std::endl;
    
    for (size_t i = 0; i < sortedDevices.size(); i++) {
        if (i > 0) std::cout << "," << std::endl;
        
        const DeviceInfo& dev = sortedDevices[i];
        
        std::cout << "  {" << std::endl;
        std::cout << "    \"ip\": \"" << dev.ip << "\"," << std::endl;
        std::cout << "    \"mac\": \"" << dev.mac << "\"," << std::endl;
        std::cout << "    \"hostname\": \"" << dev.hostname << "\"," << std::endl;
        std::cout << "    \"type\": \"" << dev.type << "\"," << std::endl;
        std::cout << "    \"is_router\": " << (dev.isRouter ? "true" : "false") << "," << std::endl;
        std::cout << "    \"seen_count\": " << dev.seenCount << std::endl;
        std::cout << "  }";
    }
    
    std::cout << std::endl << "]" << std::endl;
}

int main(int argc, char* argv[]) {
    int duration = 10; // Default 10 seconds
    
    if (argc > 1) {
        duration = atoi(argv[1]);
    }
    
    std::cerr << "=== Passive Network Device Monitor ===" << std::endl;
    std::cerr << "No admin privileges required!" << std::endl;
    std::cerr << std::endl;
    
    MonitorARPTable(duration);
    
    std::cerr << std::endl;
    OutputJSON();
    
    return 0;
}
