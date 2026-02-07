// Simple CLI tool to export device list as JSON for Python
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

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

int main() {
    // Output JSON format for Python
    std::cout << "[" << std::endl;
    
    PMIB_IPNETTABLE pIpNetTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal = GetIpNetTable(NULL, &dwSize, FALSE);
    
    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        pIpNetTable = (MIB_IPNETTABLE*)malloc(dwSize);
    }
    
    if (pIpNetTable == NULL) {
        std::cout << "]" << std::endl;
        return 1;
    }
    
    dwRetVal = GetIpNetTable(pIpNetTable, &dwSize, FALSE);
    
    if (dwRetVal == NO_ERROR) {
        bool firstDevice = true;
        
        for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
            MIB_IPNETROW* pRow = &pIpNetTable->table[i];
            
            // Filter valid entries
            BYTE firstOctet = (pRow->dwAddr) & 0xFF;
            bool isMulticast = (firstOctet >= 224 && firstOctet <= 239);
            bool isBroadcast = (pRow->dwAddr == 0xFFFFFFFF);
            bool isZero = (pRow->dwAddr == 0);
            
            bool isInvalidMAC = true;
            for (int j = 0; j < 6; j++) {
                if (pRow->bPhysAddr[j] != 0x00 && pRow->bPhysAddr[j] != 0xFF) {
                    isInvalidMAC = false;
                    break;
                }
            }
            
            bool isMulticastMAC = (pRow->bPhysAddr[0] == 0x01 && 
                                   pRow->bPhysAddr[1] == 0x00 && 
                                   pRow->bPhysAddr[2] == 0x5E);
            
            if ((pRow->dwType == MIB_IPNET_TYPE_DYNAMIC || pRow->dwType == MIB_IPNET_TYPE_STATIC) &&
                !isMulticast && !isBroadcast && !isZero && !isInvalidMAC && !isMulticastMAC) {
                
                // Convert IP
                struct in_addr ipAddr;
                ipAddr.S_un.S_addr = pRow->dwAddr;
                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ipAddr, ipStr, INET_ADDRSTRLEN);
                
                // Convert MAC
                std::stringstream macStream;
                for (int j = 0; j < 6; j++) {
                    if (j > 0) macStream << ":";
                    macStream << std::hex << std::setfill('0') << std::setw(2) 
                             << std::uppercase << (int)pRow->bPhysAddr[j];
                }
                
                std::string deviceType = GetDeviceType(pRow->bPhysAddr);
                std::string hostname = GetHostname(ipStr);
                
                // Check if router
                bool isGateway = (strcmp(ipStr, "192.168.1.1") == 0 || 
                                 strcmp(ipStr, "192.168.0.1") == 0);
                
                // Output JSON
                if (!firstDevice) {
                    std::cout << "," << std::endl;
                }
                firstDevice = false;
                
                std::cout << "  {" << std::endl;
                std::cout << "    \"ip\": \"" << ipStr << "\"," << std::endl;
                std::cout << "    \"mac\": \"" << macStream.str() << "\"," << std::endl;
                std::cout << "    \"hostname\": \"" << (hostname.empty() ? "" : hostname) << "\"," << std::endl;
                std::cout << "    \"type\": \"" << deviceType << "\"," << std::endl;
                std::cout << "    \"is_router\": " << (isGateway ? "true" : "false") << std::endl;
                std::cout << "  }";
            }
        }
    }
    
    std::cout << std::endl << "]" << std::endl;
    
    if (pIpNetTable != NULL) {
        free(pIpNetTable);
    }
    
    return 0;
}
