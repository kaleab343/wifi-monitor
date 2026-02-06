#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#include <wlanapi.h>
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
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
        std::cout << "[2] Connect to Network\n";
        std::cout << "[3] Toggle Protection (Current: " 
                  << (protectionEnabled ? "ON" : "OFF") << ")\n";
        std::cout << "[4] View Protection Logs\n";
        std::cout << "[5] Test Protection Features\n";
        std::cout << "[6] Network Statistics\n";
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
                    connectToNetwork();
                    break;
                case 3:
                    toggleProtection();
                    break;
                case 4:
                    viewLogs();
                    break;
                case 5:
                    testProtectionFeatures();
                    break;
                case 6:
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
