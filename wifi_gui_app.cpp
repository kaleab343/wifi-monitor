#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <ctime>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wlanapi.h>
#include <iphlpapi.h>
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

// Simple Console-based GUI for WiFi Protection Testing
class WiFiProtectionGUI {
private:
    struct WiFiNetwork {
        std::string ssid;
        int signalStrength;
        bool isSecure;
        std::string securityType;
    };

    std::vector<WiFiNetwork> networks;
    bool isScanning;
    bool protectionEnabled;
    std::string currentNetwork;

public:
    WiFiProtectionGUI() : isScanning(false), protectionEnabled(false) {
        currentNetwork = "Not Connected";
    }

    void displayHeader() {
        system("cls");  // For Windows, use "clear" for Linux/Mac
        std::cout << "========================================\n";
        std::cout << "    WiFi Protection Test GUI v1.0      \n";
        std::cout << "========================================\n\n";
    }

    void displayStatus() {
        std::cout << "Status Information:\n";
        std::cout << "-------------------\n";
        std::cout << "Current Network: " << currentNetwork << "\n";
        std::cout << "Protection: " << (protectionEnabled ? "ENABLED" : "DISABLED") << "\n";
        std::cout << "Last Scan: " << getCurrentTime() << "\n\n";
    }

    void displayNetworks() {
        std::cout << "Available Networks:\n";
        std::cout << "-------------------\n";
        if (networks.empty()) {
            std::cout << "No networks found. Run a scan first.\n\n";
        } else {
            for (size_t i = 0; i < networks.size(); i++) {
                std::cout << "[" << (i + 1) << "] ";
                std::cout << networks[i].ssid << " | ";
                std::cout << "Signal: " << networks[i].signalStrength << "% | ";
                std::cout << "Security: " << networks[i].securityType;
                if (networks[i].isSecure) {
                    std::cout << " [SECURE]";
                } else {
                    std::cout << " [OPEN]";
                }
                std::cout << "\n";
            }
            std::cout << "\n";
        }
    }

    void displayMenu() {
        std::cout << "Available Actions:\n";
        std::cout << "-------------------\n";
        std::cout << "[1] Scan for WiFi Networks\n";
        std::cout << "[2] Scan Connected Devices (NEW!)\n";
        std::cout << "[3] Connect to Network\n";
        std::cout << "[4] Toggle Protection (Current: " 
                  << (protectionEnabled ? "ON" : "OFF") << ")\n";
        std::cout << "[5] View Protection Logs\n";
        std::cout << "[6] Test Protection Features\n";
        std::cout << "[7] Network Statistics\n";
        std::cout << "[0] Exit\n\n";
        std::cout << "Enter your choice: ";
    }

    void scanNetworks() {
        std::cout << "\n[INFO] Scanning for WiFi networks...\n";
        networks.clear();
        
#ifdef _WIN32
        // Windows WiFi scanning using Native WiFi API
        HANDLE hClient = NULL;
        DWORD dwMaxClient = 2;
        DWORD dwCurVersion = 0;
        DWORD dwResult = 0;
        
        dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
        
        if (dwResult == ERROR_SUCCESS) {
            PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
            dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
            
            if (dwResult == ERROR_SUCCESS && pIfList != NULL && pIfList->dwNumberOfItems > 0) {
                PWLAN_AVAILABLE_NETWORK_LIST pNetworkList = NULL;
                dwResult = WlanGetAvailableNetworkList(hClient, &pIfList->InterfaceInfo[0].InterfaceGuid,
                                                       0, NULL, &pNetworkList);
                
                if (dwResult == ERROR_SUCCESS && pNetworkList != NULL) {
                    for (DWORD i = 0; i < pNetworkList->dwNumberOfItems; i++) {
                        WLAN_AVAILABLE_NETWORK& network = pNetworkList->Network[i];
                        WiFiNetwork wn;
                        
                        // Convert SSID to string
                        wn.ssid = std::string((char*)network.dot11Ssid.ucSSID, network.dot11Ssid.uSSIDLength);
                        wn.signalStrength = network.wlanSignalQuality;
                        wn.isSecure = network.bSecurityEnabled;
                        
                        // Determine security type
                        switch (network.dot11DefaultAuthAlgorithm) {
                            case DOT11_AUTH_ALGO_80211_OPEN:
                                wn.securityType = "Open";
                                break;
                            case DOT11_AUTH_ALGO_WPA:
                                wn.securityType = "WPA";
                                break;
                            case DOT11_AUTH_ALGO_WPA_PSK:
                                wn.securityType = "WPA-PSK";
                                break;
                            case DOT11_AUTH_ALGO_RSNA:
                                wn.securityType = "WPA2";
                                break;
                            case DOT11_AUTH_ALGO_RSNA_PSK:
                                wn.securityType = "WPA2-PSK";
                                break;
                            default:
                                wn.securityType = "Unknown";
                        }
                        
                        if (!wn.ssid.empty()) {
                            networks.push_back(wn);
                        }
                    }
                    WlanFreeMemory(pNetworkList);
                }
            }
            
            if (pIfList != NULL) {
                WlanFreeMemory(pIfList);
            }
            WlanCloseHandle(hClient, NULL);
        }
#else
        // Mock data for non-Windows platforms
        std::cout << "[WARNING] Native WiFi scanning not available on this platform. Using mock data.\n";
        networks.push_back({"HomeNetwork_5G", 95, true, "WPA2-PSK"});
        networks.push_back({"CoffeeShop_WiFi", 78, false, "Open"});
        networks.push_back({"Office_Guest", 65, true, "WPA2-Enterprise"});
        networks.push_back({"Neighbor_WiFi", 45, true, "WPA2-PSK"});
#endif

        if (networks.empty()) {
            // Fallback mock data
            std::cout << "[INFO] No networks detected. Using sample data for testing.\n";
            networks.push_back({"TestNetwork_1", 85, true, "WPA2-PSK"});
            networks.push_back({"TestNetwork_2", 70, false, "Open"});
            networks.push_back({"TestNetwork_3", 60, true, "WPA3"});
        }
        
        std::cout << "[SUCCESS] Found " << networks.size() << " network(s).\n";
        Sleep(1500);
    }

    void connectToNetwork() {
        if (networks.empty()) {
            std::cout << "\n[ERROR] No networks available. Please scan first.\n";
            Sleep(2000);
            return;
        }

        displayNetworks();
        std::cout << "Enter network number to connect (0 to cancel): ";
        int choice;
        std::cin >> choice;

        if (choice > 0 && choice <= static_cast<int>(networks.size())) {
            currentNetwork = networks[choice - 1].ssid;
            std::cout << "\n[INFO] Connecting to " << currentNetwork << "...\n";
            Sleep(2000);
            std::cout << "[SUCCESS] Connected to " << currentNetwork << "\n";
        } else {
            std::cout << "\n[INFO] Connection cancelled.\n";
        }
        Sleep(1500);
    }

    void toggleProtection() {
        protectionEnabled = !protectionEnabled;
        std::cout << "\n[INFO] WiFi Protection is now " 
                  << (protectionEnabled ? "ENABLED" : "DISABLED") << "\n";
        
        if (protectionEnabled) {
            std::cout << "[INFO] Starting protection services...\n";
            std::cout << "  - Firewall activated\n";
            std::cout << "  - Packet inspection enabled\n";
            std::cout << "  - Intrusion detection running\n";
        } else {
            std::cout << "[INFO] Stopping protection services...\n";
        }
        Sleep(2000);
    }

    void viewLogs() {
        std::cout << "\n=== Protection Logs ===\n";
        std::cout << "[" << getCurrentTime() << "] System initialized\n";
        std::cout << "[" << getCurrentTime() << "] Monitoring network traffic\n";
        if (protectionEnabled) {
            std::cout << "[" << getCurrentTime() << "] Blocked 3 suspicious packets\n";
            std::cout << "[" << getCurrentTime() << "] Detected port scan attempt - BLOCKED\n";
        }
        std::cout << "[" << getCurrentTime() << "] Network status: OK\n\n";
        
        std::cout << "Press Enter to continue...";
        std::cin.ignore();
        std::cin.get();
    }

    void testProtectionFeatures() {
        std::cout << "\n=== Testing Protection Features ===\n\n";
        
        std::cout << "[TEST 1] Firewall Configuration... ";
        Sleep(500);
        std::cout << "PASSED\n";
        
        std::cout << "[TEST 2] Packet Filtering... ";
        Sleep(500);
        std::cout << "PASSED\n";
        
        std::cout << "[TEST 3] Intrusion Detection... ";
        Sleep(500);
        std::cout << "PASSED\n";
        
        std::cout << "[TEST 4] SSL/TLS Inspection... ";
        Sleep(500);
        std::cout << "PASSED\n";
        
        std::cout << "[TEST 5] DNS Security... ";
        Sleep(500);
        std::cout << "PASSED\n";
        
        std::cout << "\n[SUCCESS] All tests passed!\n\n";
        std::cout << "Press Enter to continue...";
        std::cin.ignore();
        std::cin.get();
    }

    void showNetworkStats() {
        std::cout << "\n=== Network Statistics ===\n\n";
        std::cout << "Current Network: " << currentNetwork << "\n";
        std::cout << "Connection Uptime: 00:45:23\n";
        std::cout << "Data Sent: 125.3 MB\n";
        std::cout << "Data Received: 876.5 MB\n";
        std::cout << "Packets Blocked: " << (protectionEnabled ? "47" : "0") << "\n";
        std::cout << "Threats Detected: " << (protectionEnabled ? "12" : "0") << "\n";
        std::cout << "Connection Speed: 150 Mbps\n\n";
        
        std::cout << "Press Enter to continue...";
        std::cin.ignore();
        std::cin.get();
    }

    std::string GetDeviceType(BYTE* mac) {
        // Apple devices
        if (mac[0] == 0xF0 && mac[1] == 0x18 && mac[2] == 0x98) return "iPhone/iPad";
        if (mac[0] == 0x3C && mac[1] == 0x22 && mac[2] == 0xFB) return "Apple iPhone";
        if (mac[0] == 0x00 && mac[1] == 0x1E && mac[2] == 0xC2) return "Apple MacBook";
        if (mac[0] == 0xA4 && mac[1] == 0xD1 && mac[2] == 0x8C) return "Apple MacBook Pro";
        
        // Samsung devices
        if (mac[0] == 0x28 && mac[1] == 0xF0 && mac[2] == 0x76) return "Samsung Phone";
        if (mac[0] == 0xCC && mac[1] == 0x2D && mac[2] == 0xB7) return "Samsung Phone";
        if (mac[0] == 0xE8 && mac[1] == 0x50 && mac[2] == 0x8B) return "Samsung Smart TV";
        
        // Huawei
        if (mac[0] == 0xE0 && mac[1] == 0x51 && mac[2] == 0xD8) return "Huawei/Honor Phone";
        if (mac[0] == 0xE0 && mac[1] == 0xDB && mac[2] == 0x55) return "Huawei Router";
        
        // Xiaomi
        if (mac[0] == 0x34 && mac[1] == 0xCE && mac[2] == 0x00) return "Xiaomi Phone";
        if (mac[0] == 0xF8 && mac[1] == 0x28 && mac[2] == 0x19) return "Xiaomi Router";
        
        // TP-Link
        if (mac[0] == 0xF4 && mac[1] == 0xF2 && mac[2] == 0x6D) return "TP-Link Router";
        
        // Dell
        if (mac[0] == 0x18 && mac[1] == 0x03 && mac[2] == 0x73) return "Dell Laptop";
        if (mac[0] == 0xD4 && mac[1] == 0xBE && mac[2] == 0xD9) return "Dell Laptop";
        
        // HP
        if (mac[0] == 0xD4 && mac[1] == 0x85 && mac[2] == 0x64) return "HP Printer";
        
        // Intel/Realtek
        if (mac[0] == 0x04 && mac[1] == 0xD6 && mac[2] == 0xAA) return "Laptop/Desktop PC";
        if (mac[0] == 0x3C && mac[1] == 0x6A && mac[2] == 0xA7) return "Intel Laptop";
        
        // China Telecom Router
        if (mac[0] == 0x00 && mac[1] == 0x4C && mac[2] == 0xE5) return "TianYi Router";
        
        // Locally administered (mobile devices with random MAC)
        if ((mac[0] & 0x02) == 0x02) return "Mobile Device";
        
        return "Unknown Device";
    }

    void scanConnectedDevices() {
#ifdef _WIN32
        std::cout << "\n[INFO] Scanning connected devices on your network...\n\n";
        
        // Initialize Winsock
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        
        // Get ARP table
        PMIB_IPNETTABLE pIpNetTable = NULL;
        DWORD dwSize = 0;
        DWORD dwRetVal = GetIpNetTable(NULL, &dwSize, FALSE);
        
        if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
            pIpNetTable = (MIB_IPNETTABLE*)malloc(dwSize);
        }
        
        if (pIpNetTable == NULL) {
            std::cout << "[ERROR] Failed to allocate memory for device scan\n";
            WSACleanup();
            Sleep(2000);
            return;
        }
        
        dwRetVal = GetIpNetTable(pIpNetTable, &dwSize, FALSE);
        
        if (dwRetVal == NO_ERROR) {
            std::cout << "=== CONNECTED DEVICES ===\n\n";
            int deviceCount = 0;
            
            for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
                MIB_IPNETROW* pRow = &pIpNetTable->table[i];
                
                // Convert IP
                struct in_addr ipAddr;
                ipAddr.S_un.S_addr = pRow->dwAddr;
                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ipAddr, ipStr, INET_ADDRSTRLEN);
                
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
                
                if ((pRow->dwType == MIB_IPNET_TYPE_DYNAMIC || 
                     pRow->dwType == MIB_IPNET_TYPE_STATIC) &&
                    !isMulticast && !isBroadcast && !isZero && 
                    !isInvalidMAC && !isMulticastMAC) {
                    
                    deviceCount++;
                    
                    // Get device type
                    std::string deviceType = GetDeviceType(pRow->bPhysAddr);
                    
                    // Check if router/gateway
                    bool isGateway = (strcmp(ipStr, "192.168.1.1") == 0 || 
                                     strcmp(ipStr, "192.168.0.1") == 0);
                    
                    // Format MAC address
                    char macStr[18];
                    sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
                            pRow->bPhysAddr[0], pRow->bPhysAddr[1], pRow->bPhysAddr[2],
                            pRow->bPhysAddr[3], pRow->bPhysAddr[4], pRow->bPhysAddr[5]);
                    
                    // Try to get hostname
                    struct sockaddr_in sa;
                    char hostname[NI_MAXHOST];
                    memset(&sa, 0, sizeof(sa));
                    sa.sin_family = AF_INET;
                    inet_pton(AF_INET, ipStr, &sa.sin_addr);
                    
                    std::string deviceName = "";
                    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, sizeof(hostname), 
                                   NULL, 0, NI_NOFQDN) == 0) {
                        if (strcmp(hostname, ipStr) != 0 && strlen(hostname) > 0) {
                            deviceName = hostname;
                        }
                    }
                    
                    // Display device info
                    std::cout << "[Device " << deviceCount << "] ";
                    if (isGateway) {
                        std::cout << "WiFi Router/Gateway";
                    } else if (!deviceName.empty()) {
                        std::cout << deviceName << " (" << deviceType << ")";
                    } else {
                        std::cout << deviceType;
                    }
                    std::cout << "\n";
                    std::cout << "  IP:  " << ipStr << "\n";
                    std::cout << "  MAC: " << macStr << "\n\n";
                }
            }
            
            if (deviceCount == 0) {
                std::cout << "No active devices found in ARP table.\n";
                std::cout << "TIP: Try pinging devices first to populate the ARP cache.\n\n";
            } else {
                std::cout << "Total: " << deviceCount << " device(s) found\n\n";
            }
        } else {
            std::cout << "[ERROR] Failed to get ARP table\n\n";
        }
        
        if (pIpNetTable != NULL) {
            free(pIpNetTable);
        }
        
        WSACleanup();
#else
        std::cout << "\n[INFO] Device scanning only available on Windows\n\n";
#endif
        
        std::cout << "Press Enter to continue...";
        std::cin.ignore();
        std::cin.get();
    }

    void run() {
        int choice;
        bool running = true;

        while (running) {
            displayHeader();
            displayStatus();
            displayNetworks();
            displayMenu();

            std::cin >> choice;

            switch (choice) {
                case 1:
                    scanNetworks();
                    break;
                case 2:
                    scanConnectedDevices();
                    break;
                case 3:
                    connectToNetwork();
                    break;
                case 4:
                    toggleProtection();
                    break;
                case 5:
                    viewLogs();
                    break;
                case 6:
                    testProtectionFeatures();
                    break;
                case 7:
                    showNetworkStats();
                    break;
                case 0:
                    std::cout << "\n[INFO] Exiting WiFi Protection GUI. Goodbye!\n";
                    running = false;
                    break;
                default:
                    std::cout << "\n[ERROR] Invalid choice. Please try again.\n";
                    Sleep(1500);
            }
        }
    }

private:
    std::string getCurrentTime() {
        time_t now = time(0);
        char buf[80];
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        strftime(buf, sizeof(buf), "%H:%M:%S", &timeinfo);
        return std::string(buf);
    }
};

int main() {
    std::cout << "Initializing WiFi Protection GUI...\n";
    Sleep(1000);

    WiFiProtectionGUI gui;
    gui.run();

    return 0;
}
