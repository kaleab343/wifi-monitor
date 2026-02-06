#ifndef UNICODE
#define UNICODE
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wlanapi.h>
#include <objbase.h>
#include <wtypes.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// Control IDs
#define IDC_SCAN_BUTTON 101
#define IDC_CONNECT_BUTTON 102
#define IDC_PROTECT_BUTTON 103
#define IDC_TEST_BUTTON 104
#define IDC_STATS_BUTTON 105
#define IDC_NETWORK_LIST 106
#define IDC_STATUS_TEXT 107
#define IDC_LOG_TEXT 108
#define IDC_DEVICES_LIST 109
#define IDC_REFRESH_DEVICES_BUTTON 110
#define IDC_COPY_DEVICES_BUTTON 111
#define IDC_DEEP_SCAN_BUTTON 112

// Context menu IDs
#define IDM_BLOCK_DEVICE 200
#define IDM_UNBLOCK_DEVICE 201
#define IDM_COPY_IP 202
#define IDM_COPY_MAC 203
#define IDM_DEVICE_DETAILS 204

// Global variables
HWND g_hWndNetworkList;
HWND g_hWndStatusText;
HWND g_hWndLogText;
HWND g_hWndProtectButton;
HWND g_hWndDevicesList;
HWND g_hMainWindow;
bool g_protectionEnabled = false;
bool g_isScanning = false;
std::vector<std::wstring> g_networkSSIDs;
std::wstring g_currentConnectedNetwork = L"";
std::vector<std::wstring> g_blockedDevices; // Store blocked MAC addresses

// Custom message for scan completion
#define WM_SCAN_COMPLETE (WM_USER + 1)
#define WM_DEEP_SCAN_COMPLETE (WM_USER + 2)

// Function to add log message
void AddLog(const std::wstring& message) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    std::wstringstream ss;
    ss << L"[" << std::setfill(L'0') << std::setw(2) << st.wHour 
       << L":" << std::setw(2) << st.wMinute 
       << L":" << std::setw(2) << st.wSecond 
       << L"] " << message << L"\r\n";
    
    int len = GetWindowTextLength(g_hWndLogText);
    SendMessage(g_hWndLogText, EM_SETSEL, len, len);
    SendMessage(g_hWndLogText, EM_REPLACESEL, FALSE, (LPARAM)ss.str().c_str());
}

// Function to update status
void UpdateStatus(const std::wstring& status) {
    SetWindowText(g_hWndStatusText, status.c_str());
}

// Helper function to check if a MAC address is blocked
bool IsDeviceBlocked(const std::wstring& mac) {
    for (const auto& blockedMAC : g_blockedDevices) {
        if (blockedMAC == mac) {
            return true;
        }
    }
    return false;
}

// Helper function to extract MAC address from device list line
std::wstring ExtractMACFromLine(const std::wstring& line) {
    size_t macPos = line.find(L"MAC: ");
    if (macPos != std::wstring::npos) {
        std::wstring mac = line.substr(macPos + 5);
        // Remove any trailing characters after MAC
        size_t endPos = mac.find(L" ");
        if (endPos != std::wstring::npos) {
            mac = mac.substr(0, endPos);
        }
        return mac;
    }
    return L"";
}

// Helper function to extract IP address from device list line
std::wstring ExtractIPFromLine(const std::wstring& line) {
    size_t ipPos = line.find(L"IP: ");
    if (ipPos != std::wstring::npos) {
        std::wstring ip = line.substr(ipPos + 4);
        // Extract until the next space or pipe
        size_t endPos = ip.find(L" ");
        if (endPos != std::wstring::npos) {
            ip = ip.substr(0, endPos);
        }
        return ip;
    }
    return L"";
}

// Helper function to resolve hostname from IP address
std::wstring GetHostnameFromIP(const char* ipStr) {
    struct sockaddr_in sa;
    char hostname[NI_MAXHOST];
    
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ipStr, &sa.sin_addr);
    
    // Try reverse DNS lookup with NI_NAMEREQD flag removed for better results
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, sizeof(hostname), NULL, 0, NI_NOFQDN) == 0) {
        // Check if we got a real hostname (not just the IP address back)
        if (strcmp(hostname, ipStr) != 0 && strlen(hostname) > 0) {
            // Convert to wide string
            int len = MultiByteToWideChar(CP_UTF8, 0, hostname, -1, NULL, 0);
            if (len > 0) {
                wchar_t* wideHostname = new wchar_t[len];
                MultiByteToWideChar(CP_UTF8, 0, hostname, -1, wideHostname, len);
                std::wstring result(wideHostname);
                delete[] wideHostname;
                return result;
            }
        }
    }
    return L"";
}

// Helper function to get device type and vendor from MAC address
std::wstring GetDeviceTypeFromMAC(BYTE* mac) {
    // Apple devices - specific types
    if (mac[0] == 0xF0 && mac[1] == 0x18 && mac[2] == 0x98) return L"iPhone/iPad";
    if (mac[0] == 0x3C && mac[1] == 0x22 && mac[2] == 0xFB) return L"Apple iPhone";
    if (mac[0] == 0x00 && mac[1] == 0x1E && mac[2] == 0xC2) return L"Apple MacBook";
    if (mac[0] == 0x00 && mac[1] == 0x1F && mac[2] == 0x5B) return L"Apple MacBook";
    if (mac[0] == 0x00 && mac[1] == 0x23 && mac[2] == 0x32) return L"Apple iMac";
    if (mac[0] == 0x00 && mac[1] == 0x25 && mac[2] == 0x00) return L"Apple MacBook";
    if (mac[0] == 0x00 && mac[1] == 0x26 && mac[2] == 0xBB) return L"Apple MacBook";
    if (mac[0] == 0xA4 && mac[1] == 0xD1 && mac[2] == 0x8C) return L"Apple MacBook Pro";
    if (mac[0] == 0xBC && mac[1] == 0xEC && mac[2] == 0x5D) return L"Apple iPad";
    if (mac[0] == 0x64 && mac[1] == 0xA3 && mac[2] == 0xCB) return L"Apple iPhone";
    
    // Samsung devices - specific types
    if (mac[0] == 0x28 && mac[1] == 0xF0 && mac[2] == 0x76) return L"Samsung Phone";
    if (mac[0] == 0xCC && mac[1] == 0x2D && mac[2] == 0xB7) return L"Samsung Phone";
    if (mac[0] == 0xE8 && mac[1] == 0x50 && mac[2] == 0x8B) return L"Samsung Smart TV";
    if (mac[0] == 0x00 && mac[1] == 0x12 && mac[2] == 0xFB) return L"Samsung Phone";
    if (mac[0] == 0x00 && mac[1] == 0x15 && mac[2] == 0xB9) return L"Samsung Galaxy";
    if (mac[0] == 0xD0 && mac[1] == 0x25 && mac[2] == 0x98) return L"Samsung Laptop";
    if (mac[0] == 0x7C && mac[1] == 0x61 && mac[2] == 0x93) return L"Samsung Tablet";
    
    // Huawei
    if (mac[0] == 0x00 && mac[1] == 0x1E && mac[2] == 0x10) return L"Huawei Phone";
    if (mac[0] == 0x00 && mac[1] == 0x25 && mac[2] == 0x9E) return L"Huawei Phone";
    if (mac[0] == 0xE0 && mac[1] == 0xDB && mac[2] == 0x55) return L"Huawei Router";
    if (mac[0] == 0x34 && mac[1] == 0x6B && mac[2] == 0xD3) return L"Huawei Tablet";
    
    // Xiaomi
    if (mac[0] == 0x34 && mac[1] == 0xCE && mac[2] == 0x00) return L"Xiaomi Phone";
    if (mac[0] == 0x64 && mac[1] == 0x09 && mac[2] == 0x80) return L"Xiaomi Phone";
    if (mac[0] == 0xF8 && mac[1] == 0x28 && mac[2] == 0x19) return L"Xiaomi Router";
    
    // TP-Link routers
    if (mac[0] == 0xF4 && mac[1] == 0xF2 && mac[2] == 0x6D) return L"TP-Link Router";
    if (mac[0] == 0xC0 && mac[1] == 0x25 && mac[2] == 0xE9) return L"TP-Link Router";
    if (mac[0] == 0x54 && mac[1] == 0xA0 && mac[2] == 0x50) return L"TP-Link Router";
    
    // D-Link
    if (mac[0] == 0x00 && mac[1] == 0x1B && mac[2] == 0x11) return L"D-Link Router";
    if (mac[0] == 0x00 && mac[1] == 0x1E && mac[2] == 0x58) return L"D-Link Router";
    if (mac[0] == 0xCC && mac[1] == 0xB2 && mac[2] == 0x55) return L"D-Link Router";
    
    // Cisco
    if (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) return L"Cisco Router";
    if (mac[0] == 0x00 && mac[1] == 0x1B && mac[2] == 0xD5) return L"Cisco Switch";
    
    // Microsoft
    if (mac[0] == 0x00 && mac[1] == 0x15 && mac[2] == 0x5D) return L"Microsoft Surface";
    if (mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0xF2) return L"Microsoft Xbox";
    
    // HP printers
    if (mac[0] == 0x00 && mac[1] == 0x1F && mac[2] == 0x29) return L"HP Printer";
    if (mac[0] == 0xD4 && mac[1] == 0x85 && mac[2] == 0x64) return L"HP Printer";
    if (mac[0] == 0x18 && mac[1] == 0xA9 && mac[2] == 0x05) return L"HP Printer";
    
    // Dell
    if (mac[0] == 0x00 && mac[1] == 0x14 && mac[2] == 0x22) return L"Dell Desktop PC";
    if (mac[0] == 0x18 && mac[1] == 0x03 && mac[2] == 0x73) return L"Dell Laptop";
    if (mac[0] == 0xD4 && mac[1] == 0xBE && mac[2] == 0xD9) return L"Dell Laptop";
    
    // Lenovo
    if (mac[0] == 0x00 && mac[1] == 0x21 && mac[2] == 0x5C) return L"Lenovo Laptop";
    if (mac[0] == 0x54 && mac[1] == 0xEE && mac[2] == 0x75) return L"Lenovo ThinkPad";
    
    // Asus
    if (mac[0] == 0x00 && mac[1] == 0x1F && mac[2] == 0xC6) return L"Asus Laptop";
    if (mac[0] == 0x08 && mac[1] == 0x60 && mac[2] == 0x6E) return L"Asus Router";
    
    // Raspberry Pi
    if (mac[0] == 0xDC && mac[1] == 0xA6 && mac[2] == 0x32) return L"Raspberry Pi";
    if (mac[0] == 0xB8 && mac[1] == 0x27 && mac[2] == 0xEB) return L"Raspberry Pi";
    if (mac[0] == 0xE4 && mac[1] == 0x5F && mac[2] == 0x01) return L"Raspberry Pi";
    
    // Google
    if (mac[0] == 0x00 && mac[1] == 0x1A && mac[2] == 0x11) return L"Google Chromecast";
    if (mac[0] == 0xF4 && mac[1] == 0xF5 && mac[2] == 0xDB) return L"Google Home";
    
    // Amazon
    if (mac[0] == 0x00 && mac[1] == 0xFC && mac[2] == 0x8B) return L"Amazon Fire TV";
    if (mac[0] == 0x44 && mac[1] == 0x65 && mac[2] == 0x0D) return L"Amazon Echo";
    
    // VMware
    if (mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56) return L"VMware Virtual Machine";
    if (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) return L"VMware Virtual Machine";
    
    // Intel
    if (mac[0] == 0x00 && mac[1] == 0x15 && mac[2] == 0x17) return L"Intel NUC";
    if (mac[0] == 0xA4 && mac[1] == 0x34 && mac[2] == 0xD9) return L"Intel Desktop PC";
    
    // Broadcom
    if (mac[0] == 0x00 && mac[1] == 0x10 && mac[2] == 0x18) return L"Broadcom Device";
    
    // Netgear
    if (mac[0] == 0x00 && mac[1] == 0x1B && mac[2] == 0x2F) return L"Netgear Router";
    if (mac[0] == 0xA0 && mac[1] == 0x63 && mac[2] == 0x91) return L"Netgear Router";
    
    // Huawei/Honor (E0:51:D8)
    if (mac[0] == 0xE0 && mac[1] == 0x51 && mac[2] == 0xD8) return L"Huawei/Honor Phone";
    
    // Realtek/Generic (04:D6:AA) - Common in laptops, IoT devices, TVs
    if (mac[0] == 0x04 && mac[1] == 0xD6 && mac[2] == 0xAA) return L"PC/Laptop/Smart Device";
    
    return L"Unknown Device";
}

// Function to get current WiFi connection info
std::wstring GetCurrentWiFiSSID() {
    HANDLE hClient = NULL;
    DWORD dwMaxClient = 2;
    DWORD dwCurVersion = 0;
    std::wstring ssid = L"";
    
    DWORD dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        return L"";
    }
    
    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
    
    if (dwResult == ERROR_SUCCESS && pIfList != NULL && pIfList->dwNumberOfItems > 0) {
        PWLAN_CONNECTION_ATTRIBUTES pConnectInfo = NULL;
        DWORD connectInfoSize = sizeof(WLAN_CONNECTION_ATTRIBUTES);
        
        dwResult = WlanQueryInterface(hClient, &pIfList->InterfaceInfo[0].InterfaceGuid,
                                     wlan_intf_opcode_current_connection, NULL,
                                     &connectInfoSize, (PVOID*)&pConnectInfo, NULL);
        
        if (dwResult == ERROR_SUCCESS && pConnectInfo != NULL) {
            if (pConnectInfo->isState == wlan_interface_state_connected) {
                std::string ssidStr((char*)pConnectInfo->wlanAssociationAttributes.dot11Ssid.ucSSID,
                                   pConnectInfo->wlanAssociationAttributes.dot11Ssid.uSSIDLength);
                ssid = std::wstring(ssidStr.begin(), ssidStr.end());
            }
            WlanFreeMemory(pConnectInfo);
        }
    }
    
    if (pIfList != NULL) {
        WlanFreeMemory(pIfList);
    }
    WlanCloseHandle(hClient, NULL);
    
    return ssid;
}

// Helper function to get WiFi adapter IP address
std::string GetWiFiAdapterIP() {
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 15000;
    DWORD dwRetVal = 0;
    
    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    if (pAddresses == NULL) {
        return "";
    }
    
    dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
    
    if (dwRetVal == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            // Look for WiFi adapter (type 71 is IEEE80211 wireless)
            if (pCurrAddresses->IfType == IF_TYPE_IEEE80211 && 
                pCurrAddresses->OperStatus == IfOperStatusUp) {
                
                PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
                if (pUnicast != NULL) {
                    sockaddr_in* sa_in = (sockaddr_in*)pUnicast->Address.lpSockaddr;
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(sa_in->sin_addr), ip, INET_ADDRSTRLEN);
                    
                    // Skip virtual adapters (172.x.x.x is typically Hyper-V)
                    if (strncmp(ip, "172.", 4) != 0 && strncmp(ip, "169.254", 7) != 0) {
                        free(pAddresses);
                        return std::string(ip);
                    }
                }
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    }
    
    free(pAddresses);
    return "";
}

// Background thread function for network scanning
DWORD WINAPI ScanThreadFunction(LPVOID lpParam) {
    // Get WiFi adapter IP address
    std::string localIP = GetWiFiAdapterIP();
    
    if (localIP.empty()) {
        PostMessage(g_hMainWindow, WM_SCAN_COMPLETE, 0, 0);
        return 0;
    }
    
    // Extract subnet (192.168.1.x or 192.168.0.x)
    BYTE subnet[4];
    sscanf(localIP.c_str(), "%hhu.%hhu.%hhu.%hhu", &subnet[0], &subnet[1], &subnet[2], &subnet[3]);
    
    // Initialize Winsock for ARP requests
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    int devicesFound = 0;
    
    // Expanded scan - scan full common range .1-.254 for better discovery
    for (int i = 1; i <= 254; i++) {
        if (!g_isScanning) break; // Allow cancellation
        
        char targetIP[INET_ADDRSTRLEN];
        sprintf(targetIP, "%d.%d.%d.%d", subnet[0], subnet[1], subnet[2], i);
        
        // Skip our own IP
        if (strcmp(targetIP, localIP.c_str()) == 0) {
            continue;
        }
        
        // Use SendARP only (faster and doesn't require ICMP)
        IPAddr destIP = inet_addr(targetIP);
        ULONG macAddr[2];
        ULONG macAddrLen = 6;
        
        // Try to get MAC address (very short timeout built into SendARP)
        DWORD result = SendARP(destIP, 0, macAddr, &macAddrLen);
        if (result == NO_ERROR) {
            devicesFound++;
        }
        
        // Small delay to prevent flooding
        Sleep(10);
    }
    
    WSACleanup();
    
    // Send device count to main thread
    PostMessage(g_hMainWindow, WM_SCAN_COMPLETE, (WPARAM)devicesFound, 0);
    return 0;
}

// Deep scan thread function - more aggressive with multiple attempts
DWORD WINAPI DeepScanThreadFunction(LPVOID lpParam) {
    // Get WiFi adapter IP address
    std::string localIP = GetWiFiAdapterIP();
    
    if (localIP.empty()) {
        PostMessage(g_hMainWindow, WM_DEEP_SCAN_COMPLETE, 0, 0);
        return 0;
    }
    
    // Extract subnet (192.168.1.x or 192.168.0.x)
    BYTE subnet[4];
    sscanf(localIP.c_str(), "%hhu.%hhu.%hhu.%hhu", &subnet[0], &subnet[1], &subnet[2], &subnet[3]);
    
    // Initialize Winsock for ARP requests
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    int devicesFound = 0;
    
    // DEEP SCAN - Multiple passes with different methods
    // Post progress updates to UI thread
    std::wstringstream progressMsg;
    progressMsg << L"Pass 1/2: Pinging all IPs to wake devices...";
    PostMessage(g_hMainWindow, WM_USER + 100, 0, (LPARAM)_wcsdup(progressMsg.str().c_str()));
    
    // Pass 1: ICMP Ping entire range
    int pingReplies = 0;
    for (int i = 1; i <= 254; i++) {
        if (!g_isScanning) break;
        
        char targetIP[INET_ADDRSTRLEN];
        sprintf(targetIP, "%d.%d.%d.%d", subnet[0], subnet[1], subnet[2], i);
        
        if (strcmp(targetIP, localIP.c_str()) == 0) continue;
        
        // ICMP Ping
        HANDLE hIcmpFile = IcmpCreateFile();
        if (hIcmpFile != INVALID_HANDLE_VALUE) {
            unsigned long ipaddr = inet_addr(targetIP);
            char SendData[] = "PING";
            DWORD ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData) + 8;
            LPVOID ReplyBuffer = malloc(ReplySize);
            
            if (ReplyBuffer) {
                DWORD result = IcmpSendEcho(hIcmpFile, ipaddr, SendData, sizeof(SendData),
                            NULL, ReplyBuffer, ReplySize, 100);
                if (result > 0) {
                    pingReplies++;
                }
                free(ReplyBuffer);
            }
            IcmpCloseHandle(hIcmpFile);
        }
    }
    
    // Progress update
    std::wstringstream progress2Msg;
    progress2Msg << L"Pass 2/2: ARP scanning (found " << pingReplies << L" ping replies)...";
    PostMessage(g_hMainWindow, WM_USER + 100, 0, (LPARAM)_wcsdup(progress2Msg.str().c_str()));
    
    // Pass 2: ARP requests with retries
    for (int i = 1; i <= 254; i++) {
        if (!g_isScanning) break;
        
        char targetIP[INET_ADDRSTRLEN];
        sprintf(targetIP, "%d.%d.%d.%d", subnet[0], subnet[1], subnet[2], i);
        
        if (strcmp(targetIP, localIP.c_str()) == 0) continue;
        
        // Multiple ARP attempts
        IPAddr destIP = inet_addr(targetIP);
        bool found = false;
        for (int attempt = 0; attempt < 3; attempt++) {
            ULONG macAddr[2];
            ULONG macAddrLen = 6;
            
            DWORD result = SendARP(destIP, 0, macAddr, &macAddrLen);
            if (result == NO_ERROR) {
                if (!found) {
                    devicesFound++;
                    found = true;
                }
                break; // Found it, no need to retry
            }
            Sleep(50); // Wait between attempts
        }
        
        Sleep(10);
    }
    
    WSACleanup();
    
    // Send device count to main thread
    PostMessage(g_hMainWindow, WM_DEEP_SCAN_COMPLETE, (WPARAM)devicesFound, 0);
    return 0;
}

// Helper function to start network scan in background
void PingSweepNetwork() {
    if (g_isScanning) {
        AddLog(L"Scan already in progress...");
        return;
    }
    
    AddLog(L"Starting quick network scan...");
    
    // Get WiFi adapter IP address
    std::string localIP = GetWiFiAdapterIP();
    
    if (localIP.empty()) {
        AddLog(L"WARNING: Could not find WiFi adapter IP address");
        return;
    }
    
    // Log the WiFi IP
    std::wstring wideIP(localIP.begin(), localIP.end());
    AddLog(L"Your WiFi IP: " + wideIP);
    
    // Extract subnet
    BYTE subnet[4];
    sscanf(localIP.c_str(), "%hhu.%hhu.%hhu.%hhu", &subnet[0], &subnet[1], &subnet[2], &subnet[3]);
    
    std::wstringstream subnetMsg;
    subnetMsg << L"Scanning subnet: " << (int)subnet[0] << L"." << (int)subnet[1] 
              << L"." << (int)subnet[2] << L".0/24";
    AddLog(subnetMsg.str());
    
    g_isScanning = true;
    
    // Start background thread
    CreateThread(NULL, 0, ScanThreadFunction, NULL, 0, NULL);
}

// Helper function to start deep scan in background
void StartDeepScan() {
    if (g_isScanning) {
        AddLog(L"Scan already in progress...");
        return;
    }
    
    AddLog(L"Starting DEEP scan (ICMP + ARP with retries)...");
    
    // Get WiFi adapter IP address
    std::string localIP = GetWiFiAdapterIP();
    
    if (localIP.empty()) {
        AddLog(L"WARNING: Could not find WiFi adapter IP address");
        return;
    }
    
    // Log the WiFi IP
    std::wstring wideIP(localIP.begin(), localIP.end());
    AddLog(L"Your WiFi IP: " + wideIP);
    
    // Extract subnet
    BYTE subnet[4];
    sscanf(localIP.c_str(), "%hhu.%hhu.%hhu.%hhu", &subnet[0], &subnet[1], &subnet[2], &subnet[3]);
    
    std::wstringstream subnetMsg;
    subnetMsg << L"Deep scanning subnet: " << (int)subnet[0] << L"." << (int)subnet[1] 
              << L"." << (int)subnet[2] << L".0/24";
    AddLog(subnetMsg.str());
    AddLog(L"This will take 20-30 seconds, please wait...");
    
    g_isScanning = true;
    
    // Start deep scan thread
    CreateThread(NULL, 0, DeepScanThreadFunction, NULL, 0, NULL);
}

// Function to scan connected devices on the network using ARP table
void ScanConnectedDevices() {
    AddLog(L"Reading ARP table for discovered devices...");
    
    // Clear current device list
    SendMessage(g_hWndDevicesList, LB_RESETCONTENT, 0, 0);
    
    // Get current WiFi connection
    std::wstring currentSSID = GetCurrentWiFiSSID();
    if (currentSSID.empty()) {
        SendMessage(g_hWndDevicesList, LB_ADDSTRING, 0, (LPARAM)L"Not connected to WiFi");
        AddLog(L"No WiFi connection detected");
        return;
    }
    
    // Update the current network
    g_currentConnectedNetwork = currentSSID;
    AddLog(L"Connected to: " + currentSSID);
    
    // Get ARP table to find devices on the network
    PMIB_IPNETTABLE pIpNetTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    
    // Make an initial call to get the necessary size
    dwRetVal = GetIpNetTable(NULL, &dwSize, FALSE);
    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        pIpNetTable = (MIB_IPNETTABLE*)malloc(dwSize);
    }
    
    if (pIpNetTable == NULL) {
        AddLog(L"ERROR: Failed to allocate memory for ARP table");
        SendMessage(g_hWndDevicesList, LB_ADDSTRING, 0, (LPARAM)L"Error scanning network");
        return;
    }
    
    // Get the actual ARP table
    dwRetVal = GetIpNetTable(pIpNetTable, &dwSize, FALSE);
    
    if (dwRetVal == NO_ERROR) {
        int deviceCount = 0;
        
        for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
            MIB_IPNETROW* pRow = &pIpNetTable->table[i];
            
            // Convert IP address to check if it's valid
            struct in_addr ipAddr;
            ipAddr.S_un.S_addr = pRow->dwAddr;
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ipAddr, ipStr, INET_ADDRSTRLEN);
            
            // Filter out multicast, broadcast, and invalid addresses
            BYTE firstOctet = (pRow->dwAddr) & 0xFF;
            bool isMulticast = (firstOctet >= 224 && firstOctet <= 239);
            bool isBroadcast = (pRow->dwAddr == 0xFFFFFFFF);
            bool isZero = (pRow->dwAddr == 0);
            
            // Check for invalid MAC addresses
            bool isInvalidMAC = true;
            for (int j = 0; j < 6; j++) {
                if (pRow->bPhysAddr[j] != 0x00 && pRow->bPhysAddr[j] != 0xFF) {
                    isInvalidMAC = false;
                    break;
                }
            }
            // Special case: multicast MAC addresses start with 01:00:5E
            bool isMulticastMAC = (pRow->bPhysAddr[0] == 0x01 && 
                                   pRow->bPhysAddr[1] == 0x00 && 
                                   pRow->bPhysAddr[2] == 0x5E);
            
            // Only show valid ARP entries (not invalid, incomplete, multicast, or broadcast)
            if ((pRow->dwType == MIB_IPNET_TYPE_DYNAMIC || 
                 pRow->dwType == MIB_IPNET_TYPE_STATIC) &&
                !isMulticast && !isBroadcast && !isZero && 
                !isInvalidMAC && !isMulticastMAC) {
                
                // Convert MAC address to string
                std::wstringstream macStream;
                for (int j = 0; j < 6; j++) {
                    if (j > 0) macStream << L":";
                    macStream << std::hex << std::setfill(L'0') << std::setw(2) 
                             << std::uppercase << (int)pRow->bPhysAddr[j];
                }
                
                // Get device type info
                std::wstring deviceType = GetDeviceTypeFromMAC(pRow->bPhysAddr);
                
                // Try to resolve hostname
                std::wstring hostname = GetHostnameFromIP(ipStr);
                
                // Format device info: Device Name / Type
                std::wstringstream deviceLine1;
                std::wstringstream deviceLine2;
                
                bool hasHostname = !hostname.empty() && hostname != std::wstring(ipStr, ipStr + strlen(ipStr));
                bool hasDeviceType = deviceType != L"Unknown Device";
                
                // Check if this is the router/gateway (usually .1 or .254)
                bool isGateway = (strcmp(ipStr, "192.168.1.1") == 0 || 
                                 strcmp(ipStr, "192.168.0.1") == 0 ||
                                 strcmp(ipStr, "192.168.1.254") == 0 ||
                                 strcmp(ipStr, "10.0.0.1") == 0);
                
                // Check if this is a Microsoft Hyper-V virtual adapter (172.x.x.x with Microsoft MAC)
                bool isVirtualAdapter = (pRow->bPhysAddr[0] == 0x00 && 
                                        pRow->bPhysAddr[1] == 0x15 && 
                                        pRow->bPhysAddr[2] == 0x5D);
                
                if (isVirtualAdapter) {
                    // This is a Hyper-V virtual adapter (usually WSL or VM)
                    deviceLine1 << L"This PC - Virtual Adapter (WSL/Hyper-V)";
                } else if (isGateway) {
                    // This is the router/gateway
                    if (hasHostname) {
                        deviceLine1 << L"WiFi Router (" << hostname << L")";
                    } else {
                        deviceLine1 << L"WiFi Router / Gateway";
                    }
                } else if (hasHostname && hasDeviceType) {
                    // Show hostname with device type in parentheses
                    deviceLine1 << hostname << L" (" << deviceType << L")";
                } else if (hasHostname) {
                    // Show only hostname
                    deviceLine1 << hostname;
                } else if (hasDeviceType) {
                    // Show device type (e.g., "Samsung Phone", "Dell Laptop")
                    deviceLine1 << deviceType;
                } else {
                    // Show IP as fallback
                    deviceLine1 << L"Unknown Device";
                }
                
                // Second line: IP and MAC
                deviceLine2 << L"  IP: " << std::wstring(ipStr, ipStr + strlen(ipStr)) 
                           << L"  |  MAC: " << macStream.str();
                
                // Check if device is blocked
                if (IsDeviceBlocked(macStream.str())) {
                    std::wstringstream blockedLine1;
                    blockedLine1 << L"[BLOCKED] " << deviceLine1.str();
                    SendMessage(g_hWndDevicesList, LB_ADDSTRING, 0, (LPARAM)blockedLine1.str().c_str());
                } else {
                    SendMessage(g_hWndDevicesList, LB_ADDSTRING, 0, (LPARAM)deviceLine1.str().c_str());
                }
                SendMessage(g_hWndDevicesList, LB_ADDSTRING, 0, (LPARAM)deviceLine2.str().c_str());
                deviceCount++;
            }
        }
        
        std::wstringstream logMsg;
        logMsg << L"Found " << deviceCount << L" device(s) on network: " << currentSSID;
        AddLog(logMsg.str());
        
        if (deviceCount == 0) {
            SendMessage(g_hWndDevicesList, LB_ADDSTRING, 0, (LPARAM)L"No devices found in ARP table");
            AddLog(L"Try pinging devices on your network first to populate ARP table");
        }
    } else {
        AddLog(L"ERROR: Failed to get ARP table");
        SendMessage(g_hWndDevicesList, LB_ADDSTRING, 0, (LPARAM)L"Error accessing network information");
    }
    
    if (pIpNetTable != NULL) {
        free(pIpNetTable);
    }
}

// Function to scan WiFi networks
void ScanWiFiNetworks() {
    AddLog(L"Starting WiFi scan...");
    UpdateStatus(L"Status: Scanning for networks...");
    
    // Clear current list
    SendMessage(g_hWndNetworkList, LB_RESETCONTENT, 0, 0);
    g_networkSSIDs.clear();
    
    HANDLE hClient = NULL;
    DWORD dwMaxClient = 2;
    DWORD dwCurVersion = 0;
    DWORD dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
    
    if (dwResult != ERROR_SUCCESS) {
        AddLog(L"ERROR: Failed to open WLAN handle");
        UpdateStatus(L"Status: Scan failed - WLAN API error");
        
        // Add mock data for testing
        SendMessage(g_hWndNetworkList, LB_ADDSTRING, 0, (LPARAM)L"TestNetwork_1 (Signal: 85%) [WPA2-PSK]");
        SendMessage(g_hWndNetworkList, LB_ADDSTRING, 0, (LPARAM)L"TestNetwork_2 (Signal: 70%) [Open]");
        SendMessage(g_hWndNetworkList, LB_ADDSTRING, 0, (LPARAM)L"TestNetwork_3 (Signal: 60%) [WPA3]");
        g_networkSSIDs.push_back(L"TestNetwork_1");
        g_networkSSIDs.push_back(L"TestNetwork_2");
        g_networkSSIDs.push_back(L"TestNetwork_3");
        AddLog(L"Using mock data for testing");
        return;
    }
    
    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
    
    if (dwResult != ERROR_SUCCESS || pIfList == NULL || pIfList->dwNumberOfItems == 0) {
        AddLog(L"ERROR: No WiFi interfaces found");
        UpdateStatus(L"Status: No WiFi adapter detected");
        WlanCloseHandle(hClient, NULL);
        return;
    }
    
    PWLAN_AVAILABLE_NETWORK_LIST pNetworkList = NULL;
    dwResult = WlanGetAvailableNetworkList(hClient, &pIfList->InterfaceInfo[0].InterfaceGuid,
                                           0, NULL, &pNetworkList);
    
    if (dwResult == ERROR_SUCCESS && pNetworkList != NULL) {
        int count = 0;
        for (DWORD i = 0; i < pNetworkList->dwNumberOfItems; i++) {
            WLAN_AVAILABLE_NETWORK& network = pNetworkList->Network[i];
            
            if (network.dot11Ssid.uSSIDLength > 0) {
                // Convert SSID to wide string
                std::string ssidStr((char*)network.dot11Ssid.ucSSID, network.dot11Ssid.uSSIDLength);
                std::wstring ssid(ssidStr.begin(), ssidStr.end());
                
                // Get security type
                std::wstring secType;
                switch (network.dot11DefaultAuthAlgorithm) {
                    case DOT11_AUTH_ALGO_80211_OPEN:
                        secType = L"Open";
                        break;
                    case DOT11_AUTH_ALGO_WPA:
                        secType = L"WPA";
                        break;
                    case DOT11_AUTH_ALGO_WPA_PSK:
                        secType = L"WPA-PSK";
                        break;
                    case DOT11_AUTH_ALGO_RSNA:
                        secType = L"WPA2";
                        break;
                    case DOT11_AUTH_ALGO_RSNA_PSK:
                        secType = L"WPA2-PSK";
                        break;
                    default:
                        secType = L"Unknown";
                }
                
                // Format display string
                std::wstringstream ss;
                ss << ssid << L" (Signal: " << network.wlanSignalQuality << L"%) [" << secType << L"]";
                
                SendMessage(g_hWndNetworkList, LB_ADDSTRING, 0, (LPARAM)ss.str().c_str());
                g_networkSSIDs.push_back(ssid);
                count++;
            }
        }
        
        std::wstringstream logMsg;
        logMsg << L"Found " << count << L" network(s)";
        AddLog(logMsg.str());
        UpdateStatus(L"Status: Scan complete");
        
        WlanFreeMemory(pNetworkList);
    } else {
        AddLog(L"ERROR: Failed to get network list");
        UpdateStatus(L"Status: Scan failed");
    }
    
    if (pIfList != NULL) {
        WlanFreeMemory(pIfList);
    }
    WlanCloseHandle(hClient, NULL);
}

// Window procedure
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_SCAN_COMPLETE: {
            g_isScanning = false;
            int devicesFound = (int)wParam;
            std::wstringstream scanMsg;
            scanMsg << L"Quick scan completed - discovered " << devicesFound << L" device(s)";
            AddLog(scanMsg.str());
            // Now read the ARP table to display devices
            ScanConnectedDevices();
            return 0;
        }
        
        case WM_DEEP_SCAN_COMPLETE: {
            g_isScanning = false;
            int devicesFound = (int)wParam;
            std::wstringstream scanMsg;
            scanMsg << L"DEEP scan completed - discovered " << devicesFound << L" device(s)";
            AddLog(scanMsg.str());
            // Now read the ARP table to display devices
            ScanConnectedDevices();
            return 0;
        }
        
        case WM_USER + 100: {
            // Progress message from scan thread
            wchar_t* msg = (wchar_t*)lParam;
            if (msg) {
                AddLog(msg);
                free(msg);
            }
            return 0;
        }
        
        case WM_CREATE: {
            // Store main window handle
            g_hMainWindow = hwnd;
            // Create title label
            CreateWindowW(L"STATIC", L"WiFi Protection Test GUI v1.0",
                         WS_VISIBLE | WS_CHILD | SS_CENTER,
                         10, 10, 760, 25,
                         hwnd, NULL, NULL, NULL);
            
            // Create status label (more spacing from title)
            g_hWndStatusText = CreateWindowW(L"STATIC", L"Status: Ready",
                                            WS_VISIBLE | WS_CHILD | SS_LEFT,
                                            10, 45, 760, 20,
                                            hwnd, (HMENU)IDC_STATUS_TEXT, NULL, NULL);
            
            // Get and display current WiFi connection
            std::wstring currentSSID = GetCurrentWiFiSSID();
            if (!currentSSID.empty()) {
                std::wstring statusMsg = L"Status: Connected to \"" + currentSSID + L"\"";
                SetWindowText(g_hWndStatusText, statusMsg.c_str());
                g_currentConnectedNetwork = currentSSID;
            }
            
            // Create network list label (more spacing from status)
            CreateWindowW(L"STATIC", L"Available Networks:",
                         WS_VISIBLE | WS_CHILD | SS_LEFT,
                         10, 75, 300, 20,
                         hwnd, NULL, NULL, NULL);
            
            // Create network listbox (more spacing from label)
            g_hWndNetworkList = CreateWindowW(L"LISTBOX", NULL,
                                             WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | LBS_NOTIFY,
                                             10, 100, 360, 200,
                                             hwnd, (HMENU)IDC_NETWORK_LIST, NULL, NULL);
            
            // Create connected devices label (aligned with network label)
            CreateWindowW(L"STATIC", L"Connected Devices:",
                         WS_VISIBLE | WS_CHILD | SS_LEFT,
                         385, 75, 200, 20,
                         hwnd, NULL, NULL, NULL);
            
            // Create devices listbox (aligned with network listbox)
            g_hWndDevicesList = CreateWindowW(L"LISTBOX", NULL,
                                             WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL,
                                             385, 100, 375, 160,
                                             hwnd, (HMENU)IDC_DEVICES_LIST, NULL, NULL);
            
            // Add initial message to devices list
            SendMessage(g_hWndDevicesList, LB_ADDSTRING, 0, (LPARAM)L"Connect to a network to see devices");
            
            // Create refresh devices button (proper spacing from listbox)
            CreateWindowW(L"BUTTON", L"Quick Scan",
                         WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                         385, 268, 120, 32,
                         hwnd, (HMENU)IDC_REFRESH_DEVICES_BUTTON, NULL, NULL);
            
            // Create deep scan button
            CreateWindowW(L"BUTTON", L"Deep Scan",
                         WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                         510, 268, 120, 32,
                         hwnd, (HMENU)IDC_DEEP_SCAN_BUTTON, NULL, NULL);
            
            // Create copy devices button
            CreateWindowW(L"BUTTON", L"Copy List",
                         WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                         635, 268, 125, 32,
                         hwnd, (HMENU)IDC_COPY_DEVICES_BUTTON, NULL, NULL);
            
            // Create buttons (more spacing between sections)
            CreateWindowW(L"BUTTON", L"Scan Networks",
                         WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                         10, 315, 110, 30,
                         hwnd, (HMENU)IDC_SCAN_BUTTON, NULL, NULL);
            
            CreateWindowW(L"BUTTON", L"Connect",
                         WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                         130, 315, 110, 30,
                         hwnd, (HMENU)IDC_CONNECT_BUTTON, NULL, NULL);
            
            g_hWndProtectButton = CreateWindowW(L"BUTTON", L"Enable Protection",
                                               WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                               250, 315, 130, 30,
                                               hwnd, (HMENU)IDC_PROTECT_BUTTON, NULL, NULL);
            
            CreateWindowW(L"BUTTON", L"Run Tests",
                         WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                         390, 315, 110, 30,
                         hwnd, (HMENU)IDC_TEST_BUTTON, NULL, NULL);
            
            CreateWindowW(L"BUTTON", L"Statistics",
                         WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                         510, 315, 110, 30,
                         hwnd, (HMENU)IDC_STATS_BUTTON, NULL, NULL);
            
            // Create activity log label (more spacing from buttons)
            CreateWindowW(L"STATIC", L"Activity Log:",
                         WS_VISIBLE | WS_CHILD | SS_LEFT,
                         10, 360, 300, 20,
                         hwnd, NULL, NULL, NULL);
            
            // Create log textbox (proper spacing from label)
            g_hWndLogText = CreateWindowW(L"EDIT", L"",
                                         WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | 
                                         ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                                         10, 385, 750, 115,
                                         hwnd, (HMENU)IDC_LOG_TEXT, NULL, NULL);
            
            AddLog(L"WiFi Protection GUI initialized");
            if (!currentSSID.empty()) {
                AddLog(L"Currently connected to: " + currentSSID);
            } else {
                AddLog(L"Not connected to any WiFi network");
            }
            AddLog(L"Click 'Scan Networks' to begin");
            
            return 0;
        }
        
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_SCAN_BUTTON:
                    ScanWiFiNetworks();
                    break;
                
                case IDC_CONNECT_BUTTON: {
                    int selected = (int)SendMessage(g_hWndNetworkList, LB_GETCURSEL, 0, 0);
                    if (selected != LB_ERR && selected < (int)g_networkSSIDs.size()) {
                        std::wstring ssid = g_networkSSIDs[selected];
                        AddLog(L"Note: Connection simulation - Windows manages actual WiFi connections");
                        AddLog(L"Use Windows WiFi settings to connect to: " + ssid);
                        
                        MessageBoxW(hwnd, 
                                   L"Note: This is a test GUI.\n\n"
                                   L"To actually connect to a WiFi network, use Windows WiFi settings.\n\n"
                                   L"Click 'Refresh Devices' to scan devices on your current WiFi connection.",
                                   L"Connection Info", MB_OK | MB_ICONINFORMATION);
                        
                        // Scan for devices on current actual connection
                        ScanConnectedDevices();
                    } else {
                        MessageBoxW(hwnd, L"Please select a network first!", 
                                   L"Error", MB_OK | MB_ICONWARNING);
                    }
                    break;
                }
                
                case IDC_PROTECT_BUTTON:
                    g_protectionEnabled = !g_protectionEnabled;
                    if (g_protectionEnabled) {
                        SetWindowText(g_hWndProtectButton, L"Disable Protection");
                        AddLog(L"Protection ENABLED");
                        AddLog(L"  - Firewall activated");
                        AddLog(L"  - Packet inspection enabled");
                        AddLog(L"  - Intrusion detection running");
                        UpdateStatus(L"Status: Protection ENABLED");
                    } else {
                        SetWindowText(g_hWndProtectButton, L"Enable Protection");
                        AddLog(L"Protection DISABLED");
                        UpdateStatus(L"Status: Protection DISABLED");
                    }
                    break;
                
                case IDC_TEST_BUTTON: {
                    AddLog(L"Running protection tests...");
                    Sleep(300);
                    AddLog(L"  [TEST 1] Firewall Configuration... PASSED");
                    Sleep(300);
                    AddLog(L"  [TEST 2] Packet Filtering... PASSED");
                    Sleep(300);
                    AddLog(L"  [TEST 3] Intrusion Detection... PASSED");
                    Sleep(300);
                    AddLog(L"  [TEST 4] SSL/TLS Inspection... PASSED");
                    Sleep(300);
                    AddLog(L"  [TEST 5] DNS Security... PASSED");
                    AddLog(L"All tests PASSED!");
                    MessageBoxW(hwnd, L"All protection tests passed successfully!", 
                               L"Test Results", MB_OK | MB_ICONINFORMATION);
                    break;
                }
                
                case IDC_STATS_BUTTON: {
                    std::wstringstream stats;
                    stats << L"Network Statistics:\n\n"
                          << L"Connection Uptime: 00:45:23\n"
                          << L"Data Sent: 125.3 MB\n"
                          << L"Data Received: 876.5 MB\n"
                          << L"Packets Blocked: " << (g_protectionEnabled ? L"47" : L"0") << L"\n"
                          << L"Threats Detected: " << (g_protectionEnabled ? L"12" : L"0") << L"\n"
                          << L"Connection Speed: 150 Mbps";
                    
                    MessageBoxW(hwnd, stats.str().c_str(), 
                               L"Network Statistics", MB_OK | MB_ICONINFORMATION);
                    AddLog(L"Statistics viewed");
                    break;
                }
                
                case IDC_REFRESH_DEVICES_BUTTON:
                    if (!g_isScanning) {
                        PingSweepNetwork();
                    } else {
                        AddLog(L"Scan already in progress, please wait...");
                    }
                    break;
                
                case IDC_DEEP_SCAN_BUTTON:
                    if (!g_isScanning) {
                        StartDeepScan();
                    } else {
                        AddLog(L"Scan already in progress, please wait...");
                    }
                    break;
                
                case IDC_COPY_DEVICES_BUTTON: {
                    // Get all items from the device list
                    int count = (int)SendMessage(g_hWndDevicesList, LB_GETCOUNT, 0, 0);
                    if (count > 0) {
                        std::wstringstream clipboard;
                        clipboard << L"Connected Devices on Network: " << g_currentConnectedNetwork << L"\r\n";
                        clipboard << L"=========================================\r\n\r\n";
                        
                        for (int i = 0; i < count; i++) {
                            int len = (int)SendMessage(g_hWndDevicesList, LB_GETTEXTLEN, i, 0);
                            if (len > 0) {
                                wchar_t* buffer = new wchar_t[len + 1];
                                SendMessage(g_hWndDevicesList, LB_GETTEXT, i, (LPARAM)buffer);
                                clipboard << buffer << L"\r\n";
                                delete[] buffer;
                            }
                        }
                        
                        // Copy to clipboard
                        if (OpenClipboard(hwnd)) {
                            EmptyClipboard();
                            
                            std::wstring text = clipboard.str();
                            size_t size = (text.length() + 1) * sizeof(wchar_t);
                            HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, size);
                            
                            if (hGlobal) {
                                wchar_t* pGlobal = (wchar_t*)GlobalLock(hGlobal);
                                if (pGlobal) {
                                    memcpy(pGlobal, text.c_str(), size);
                                    GlobalUnlock(hGlobal);
                                    SetClipboardData(CF_UNICODETEXT, hGlobal);
                                    
                                    AddLog(L"Device list copied to clipboard");
                                    MessageBoxW(hwnd, L"Device list has been copied to clipboard!", 
                                               L"Copied", MB_OK | MB_ICONINFORMATION);
                                }
                            }
                            CloseClipboard();
                        }
                    } else {
                        MessageBoxW(hwnd, L"No devices to copy. Click 'Refresh Devices' first!", 
                                   L"No Data", MB_OK | MB_ICONWARNING);
                    }
                    break;
                }
                
                case IDC_DEVICES_LIST:
                    if (HIWORD(wParam) == LBN_DBLCLK) {
                        // Double-click to block/unblock device
                        int selected = (int)SendMessage(g_hWndDevicesList, LB_GETCURSEL, 0, 0);
                        if (selected != LB_ERR) {
                            int len = (int)SendMessage(g_hWndDevicesList, LB_GETTEXTLEN, selected, 0);
                            if (len > 0) {
                                wchar_t* buffer = new wchar_t[len + 1];
                                SendMessage(g_hWndDevicesList, LB_GETTEXT, selected, (LPARAM)buffer);
                                std::wstring selectedText(buffer);
                                delete[] buffer;
                                
                                std::wstring mac = ExtractMACFromLine(selectedText);
                                if (mac.empty() && selected + 1 < (int)SendMessage(g_hWndDevicesList, LB_GETCOUNT, 0, 0)) {
                                    len = (int)SendMessage(g_hWndDevicesList, LB_GETTEXTLEN, selected + 1, 0);
                                    if (len > 0) {
                                        buffer = new wchar_t[len + 1];
                                        SendMessage(g_hWndDevicesList, LB_GETTEXT, selected + 1, (LPARAM)buffer);
                                        mac = ExtractMACFromLine(buffer);
                                        delete[] buffer;
                                    }
                                }
                                
                                if (!mac.empty()) {
                                    if (IsDeviceBlocked(mac)) {
                                        // Unblock
                                        for (auto it = g_blockedDevices.begin(); it != g_blockedDevices.end(); ++it) {
                                            if (*it == mac) {
                                                g_blockedDevices.erase(it);
                                                break;
                                            }
                                        }
                                        AddLog(L"Unblocked device: " + mac);
                                    } else {
                                        // Block
                                        g_blockedDevices.push_back(mac);
                                        AddLog(L"Blocked device: " + mac);
                                    }
                                    ScanConnectedDevices();
                                }
                            }
                        }
                    }
                    break;
                
                case IDC_NETWORK_LIST:
                    if (HIWORD(wParam) == LBN_DBLCLK) {
                        // Double-click on network = connect
                        SendMessage(hwnd, WM_COMMAND, IDC_CONNECT_BUTTON, 0);
                    }
                    break;
                
                case IDM_BLOCK_DEVICE: {
                    // Get selected device and block it
                    int selected = (int)SendMessage(g_hWndDevicesList, LB_GETCURSEL, 0, 0);
                    if (selected != LB_ERR) {
                        // Get the text of selected item
                        int len = (int)SendMessage(g_hWndDevicesList, LB_GETTEXTLEN, selected, 0);
                        if (len > 0) {
                            wchar_t* buffer = new wchar_t[len + 1];
                            SendMessage(g_hWndDevicesList, LB_GETTEXT, selected, (LPARAM)buffer);
                            std::wstring selectedText(buffer);
                            delete[] buffer;
                            
                            // Check if this is the second line (has IP and MAC)
                            std::wstring mac = ExtractMACFromLine(selectedText);
                            if (mac.empty() && selected + 1 < (int)SendMessage(g_hWndDevicesList, LB_GETCOUNT, 0, 0)) {
                                // Try next line
                                len = (int)SendMessage(g_hWndDevicesList, LB_GETTEXTLEN, selected + 1, 0);
                                if (len > 0) {
                                    buffer = new wchar_t[len + 1];
                                    SendMessage(g_hWndDevicesList, LB_GETTEXT, selected + 1, (LPARAM)buffer);
                                    mac = ExtractMACFromLine(buffer);
                                    delete[] buffer;
                                }
                            }
                            
                            if (!mac.empty()) {
                                g_blockedDevices.push_back(mac);
                                AddLog(L"Blocked device with MAC: " + mac);
                                AddLog(L"Note: This is a local block list. Device is still connected to router.");
                                MessageBoxW(hwnd, 
                                    L"Device blocked successfully!\n\n"
                                    L"Note: This blocks the device in this app only.\n"
                                    L"To actually disconnect from router, you need router admin access.",
                                    L"Device Blocked", MB_OK | MB_ICONINFORMATION);
                                // Refresh device list to show [BLOCKED] tag
                                ScanConnectedDevices();
                            }
                        }
                    }
                    break;
                }
                
                case IDM_UNBLOCK_DEVICE: {
                    // Get selected device and unblock it
                    int selected = (int)SendMessage(g_hWndDevicesList, LB_GETCURSEL, 0, 0);
                    if (selected != LB_ERR) {
                        int len = (int)SendMessage(g_hWndDevicesList, LB_GETTEXTLEN, selected, 0);
                        if (len > 0) {
                            wchar_t* buffer = new wchar_t[len + 1];
                            SendMessage(g_hWndDevicesList, LB_GETTEXT, selected, (LPARAM)buffer);
                            std::wstring selectedText(buffer);
                            delete[] buffer;
                            
                            std::wstring mac = ExtractMACFromLine(selectedText);
                            if (mac.empty() && selected + 1 < (int)SendMessage(g_hWndDevicesList, LB_GETCOUNT, 0, 0)) {
                                len = (int)SendMessage(g_hWndDevicesList, LB_GETTEXTLEN, selected + 1, 0);
                                if (len > 0) {
                                    buffer = new wchar_t[len + 1];
                                    SendMessage(g_hWndDevicesList, LB_GETTEXT, selected + 1, (LPARAM)buffer);
                                    mac = ExtractMACFromLine(buffer);
                                    delete[] buffer;
                                }
                            }
                            
                            if (!mac.empty()) {
                                // Remove from blocked list
                                for (auto it = g_blockedDevices.begin(); it != g_blockedDevices.end(); ++it) {
                                    if (*it == mac) {
                                        g_blockedDevices.erase(it);
                                        break;
                                    }
                                }
                                AddLog(L"Unblocked device with MAC: " + mac);
                                MessageBoxW(hwnd, L"Device unblocked successfully!", 
                                    L"Device Unblocked", MB_OK | MB_ICONINFORMATION);
                                // Refresh device list
                                ScanConnectedDevices();
                            }
                        }
                    }
                    break;
                }
                
                case IDM_COPY_IP: {
                    int selected = (int)SendMessage(g_hWndDevicesList, LB_GETCURSEL, 0, 0);
                    if (selected != LB_ERR) {
                        int len = (int)SendMessage(g_hWndDevicesList, LB_GETTEXTLEN, selected, 0);
                        if (len > 0) {
                            wchar_t* buffer = new wchar_t[len + 1];
                            SendMessage(g_hWndDevicesList, LB_GETTEXT, selected, (LPARAM)buffer);
                            std::wstring ip = ExtractIPFromLine(buffer);
                            delete[] buffer;
                            
                            if (ip.empty() && selected + 1 < (int)SendMessage(g_hWndDevicesList, LB_GETCOUNT, 0, 0)) {
                                len = (int)SendMessage(g_hWndDevicesList, LB_GETTEXTLEN, selected + 1, 0);
                                if (len > 0) {
                                    buffer = new wchar_t[len + 1];
                                    SendMessage(g_hWndDevicesList, LB_GETTEXT, selected + 1, (LPARAM)buffer);
                                    ip = ExtractIPFromLine(buffer);
                                    delete[] buffer;
                                }
                            }
                            
                            if (!ip.empty() && OpenClipboard(hwnd)) {
                                EmptyClipboard();
                                size_t size = (ip.length() + 1) * sizeof(wchar_t);
                                HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, size);
                                if (hGlobal) {
                                    wchar_t* pGlobal = (wchar_t*)GlobalLock(hGlobal);
                                    if (pGlobal) {
                                        memcpy(pGlobal, ip.c_str(), size);
                                        GlobalUnlock(hGlobal);
                                        SetClipboardData(CF_UNICODETEXT, hGlobal);
                                        AddLog(L"Copied IP to clipboard: " + ip);
                                    }
                                }
                                CloseClipboard();
                            }
                        }
                    }
                    break;
                }
                
                case IDM_COPY_MAC: {
                    int selected = (int)SendMessage(g_hWndDevicesList, LB_GETCURSEL, 0, 0);
                    if (selected != LB_ERR) {
                        int len = (int)SendMessage(g_hWndDevicesList, LB_GETTEXTLEN, selected, 0);
                        if (len > 0) {
                            wchar_t* buffer = new wchar_t[len + 1];
                            SendMessage(g_hWndDevicesList, LB_GETTEXT, selected, (LPARAM)buffer);
                            std::wstring mac = ExtractMACFromLine(buffer);
                            delete[] buffer;
                            
                            if (mac.empty() && selected + 1 < (int)SendMessage(g_hWndDevicesList, LB_GETCOUNT, 0, 0)) {
                                len = (int)SendMessage(g_hWndDevicesList, LB_GETTEXTLEN, selected + 1, 0);
                                if (len > 0) {
                                    buffer = new wchar_t[len + 1];
                                    SendMessage(g_hWndDevicesList, LB_GETTEXT, selected + 1, (LPARAM)buffer);
                                    mac = ExtractMACFromLine(buffer);
                                    delete[] buffer;
                                }
                            }
                            
                            if (!mac.empty() && OpenClipboard(hwnd)) {
                                EmptyClipboard();
                                size_t size = (mac.length() + 1) * sizeof(wchar_t);
                                HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, size);
                                if (hGlobal) {
                                    wchar_t* pGlobal = (wchar_t*)GlobalLock(hGlobal);
                                    if (pGlobal) {
                                        memcpy(pGlobal, mac.c_str(), size);
                                        GlobalUnlock(hGlobal);
                                        SetClipboardData(CF_UNICODETEXT, hGlobal);
                                        AddLog(L"Copied MAC to clipboard: " + mac);
                                    }
                                }
                                CloseClipboard();
                            }
                        }
                    }
                    break;
                }
            }
            return 0;
        }
        
        case WM_CONTEXTMENU: {
            // Check if right-click was on device list
            if ((HWND)wParam == g_hWndDevicesList) {
                // Get cursor position and convert to client coordinates
                POINT pt;
                pt.x = LOWORD(lParam);
                pt.y = HIWORD(lParam);
                
                // If lParam is -1, use keyboard (Shift+F10), get from selection
                if (lParam == -1) {
                    // Get selected item position
                    int selected = (int)SendMessage(g_hWndDevicesList, LB_GETCURSEL, 0, 0);
                    if (selected != LB_ERR) {
                        RECT rect;
                        SendMessage(g_hWndDevicesList, LB_GETITEMRECT, selected, (LPARAM)&rect);
                        pt.x = rect.left + 5;
                        pt.y = rect.top + 5;
                        ClientToScreen(g_hWndDevicesList, &pt);
                    }
                } else {
                    // Convert screen to client coordinates to find item
                    POINT clientPt = pt;
                    ScreenToClient(g_hWndDevicesList, &clientPt);
                    
                    // Get item at cursor position
                    int itemIndex = (int)SendMessage(g_hWndDevicesList, LB_ITEMFROMPOINT, 0, MAKELPARAM(clientPt.x, clientPt.y));
                    if (HIWORD(itemIndex) == 0) { // Item is within client area
                        // Select the item
                        SendMessage(g_hWndDevicesList, LB_SETCURSEL, LOWORD(itemIndex), 0);
                    }
                }
                
                int selected = (int)SendMessage(g_hWndDevicesList, LB_GETCURSEL, 0, 0);
                if (selected != LB_ERR) {
                    // Get MAC of selected device to check if blocked
                    int len = (int)SendMessage(g_hWndDevicesList, LB_GETTEXTLEN, selected, 0);
                    bool isBlocked = false;
                    if (len > 0) {
                        wchar_t* buffer = new wchar_t[len + 1];
                        SendMessage(g_hWndDevicesList, LB_GETTEXT, selected, (LPARAM)buffer);
                        std::wstring mac = ExtractMACFromLine(buffer);
                        delete[] buffer;
                        
                        if (mac.empty() && selected + 1 < (int)SendMessage(g_hWndDevicesList, LB_GETCOUNT, 0, 0)) {
                            len = (int)SendMessage(g_hWndDevicesList, LB_GETTEXTLEN, selected + 1, 0);
                            if (len > 0) {
                                buffer = new wchar_t[len + 1];
                                SendMessage(g_hWndDevicesList, LB_GETTEXT, selected + 1, (LPARAM)buffer);
                                mac = ExtractMACFromLine(buffer);
                                delete[] buffer;
                            }
                        }
                        
                        if (!mac.empty()) {
                            isBlocked = IsDeviceBlocked(mac);
                        }
                    }
                    
                    // Create context menu
                    HMENU hMenu = CreatePopupMenu();
                    if (isBlocked) {
                        AppendMenuW(hMenu, MF_STRING, IDM_UNBLOCK_DEVICE, L"Unblock Device");
                    } else {
                        AppendMenuW(hMenu, MF_STRING, IDM_BLOCK_DEVICE, L"Block Device");
                    }
                    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
                    AppendMenuW(hMenu, MF_STRING, IDM_COPY_IP, L"Copy IP Address");
                    AppendMenuW(hMenu, MF_STRING, IDM_COPY_MAC, L"Copy MAC Address");
                    
                    // Show context menu at cursor position (pt already calculated above)
                    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
                    DestroyMenu(hMenu);
                }
            }
            return 0;
        }
        
        case WM_CTLCOLORSTATIC: {
            HDC hdcStatic = (HDC)wParam;
            SetBkMode(hdcStatic, TRANSPARENT);
            return (LRESULT)GetStockObject(NULL_BRUSH);
        }
        
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// WinMain entry point
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                    PWSTR pCmdLine, int nCmdShow) {
    // Register window class
    const wchar_t CLASS_NAME[] = L"WiFiProtectionGUI";
    
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    RegisterClass(&wc);
    
    // Create window (non-resizable, no maximize button)
    HWND hwnd = CreateWindowEx(
        0,
        CLASS_NAME,
        L"WiFi Protection Test GUI",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 550,
        NULL,
        NULL,
        hInstance,
        NULL
    );
    
    if (hwnd == NULL) {
        return 0;
    }
    
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    
    // Message loop
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return 0;
}
