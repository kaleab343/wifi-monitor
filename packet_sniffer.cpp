// Passive Network Device Discovery using Packet Sniffing
// Captures ARP, DHCP, and DNS packets to identify all devices
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// Ethernet header
struct EthernetHeader {
    unsigned char dest[6];
    unsigned char src[6];
    unsigned short type;
};

// ARP packet structure
struct ARPPacket {
    unsigned short hardwareType;
    unsigned short protocolType;
    unsigned char hardwareSize;
    unsigned char protocolSize;
    unsigned short opcode;
    unsigned char senderMAC[6];
    unsigned char senderIP[4];
    unsigned char targetMAC[6];
    unsigned char targetIP[4];
};

struct DeviceInfo {
    std::string mac;
    std::string ip;
    std::string hostname;
    time_t lastSeen;
    int packetCount;
};

std::map<std::string, DeviceInfo> discoveredDevices;

std::string MacToString(unsigned char* mac) {
    std::stringstream ss;
    for (int i = 0; i < 6; i++) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setfill('0') << std::setw(2) 
           << std::uppercase << (int)mac[i];
    }
    return ss.str();
}

std::string IPToString(unsigned char* ip) {
    std::stringstream ss;
    ss << (int)ip[0] << "." << (int)ip[1] << "." << (int)ip[2] << "." << (int)ip[3];
    return ss.str();
}

void ProcessARPPacket(unsigned char* packet, int size) {
    EthernetHeader* ethHeader = (EthernetHeader*)packet;
    ARPPacket* arpPacket = (ARPPacket*)(packet + sizeof(EthernetHeader));
    
    // Check if it's an ARP reply or request
    unsigned short opcode = ntohs(arpPacket->opcode);
    
    if (opcode == 1 || opcode == 2) { // ARP Request or Reply
        std::string mac = MacToString(arpPacket->senderMAC);
        std::string ip = IPToString(arpPacket->senderIP);
        
        // Filter out invalid IPs
        if (ip != "0.0.0.0" && ip.substr(0, 8) == "192.168.") {
            if (discoveredDevices.find(mac) == discoveredDevices.end()) {
                DeviceInfo device;
                device.mac = mac;
                device.ip = ip;
                device.hostname = "";
                device.lastSeen = time(nullptr);
                device.packetCount = 1;
                discoveredDevices[mac] = device;
                
                std::cerr << "New device discovered: " << ip << " (" << mac << ")" << std::endl;
            } else {
                discoveredDevices[mac].lastSeen = time(nullptr);
                discoveredDevices[mac].packetCount++;
                
                // Update IP if changed
                if (discoveredDevices[mac].ip != ip) {
                    discoveredDevices[mac].ip = ip;
                }
            }
        }
    }
}

// Promiscuous mode raw socket capture
void CapturePackets(int durationSeconds) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    // Create raw socket
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Failed to create socket. Error: " << WSAGetLastError() << std::endl;
        std::cerr << "Note: This requires administrator privileges!" << std::endl;
        return;
    }
    
    // Get local IP
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    
    struct addrinfo* result = NULL;
    struct addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    
    std::string localIP = "192.168.1.1";
    if (getaddrinfo(hostname, NULL, &hints, &result) == 0) {
        for (struct addrinfo* ptr = result; ptr != NULL; ptr = ptr->ai_next) {
            if (ptr->ai_family == AF_INET) {
                struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)ptr->ai_addr;
                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, ipStr, INET_ADDRSTRLEN);
                
                if (strncmp(ipStr, "192.168.", 8) == 0) {
                    localIP = ipStr;
                    break;
                }
            }
        }
        freeaddrinfo(result);
    }
    
    // Bind to local interface
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    inet_pton(AF_INET, localIP.c_str(), &addr.sin_addr);
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed. Error: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        return;
    }
    
    // Enable promiscuous mode
    DWORD dwValue = 1;
    if (ioctlsocket(sock, SIO_RCVALL, &dwValue) == SOCKET_ERROR) {
        std::cerr << "Failed to set promiscuous mode. Error: " << WSAGetLastError() << std::endl;
        std::cerr << "Run as Administrator!" << std::endl;
        closesocket(sock);
        return;
    }
    
    std::cerr << "Listening on " << localIP << " in promiscuous mode..." << std::endl;
    std::cerr << "Capturing packets for " << durationSeconds << " seconds..." << std::endl;
    
    // Set timeout
    DWORD timeout = durationSeconds * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    // Capture packets
    unsigned char buffer[65536];
    time_t startTime = time(nullptr);
    int packetCount = 0;
    
    while (time(nullptr) - startTime < durationSeconds) {
        int recvSize = recv(sock, (char*)buffer, sizeof(buffer), 0);
        
        if (recvSize > 0) {
            packetCount++;
            
            // Check if it's an ARP packet (EtherType 0x0806)
            if (recvSize >= sizeof(EthernetHeader)) {
                EthernetHeader* ethHeader = (EthernetHeader*)buffer;
                unsigned short etherType = ntohs(ethHeader->type);
                
                if (etherType == 0x0806) { // ARP
                    ProcessARPPacket(buffer, recvSize);
                }
            }
        }
    }
    
    std::cerr << "\nCapture complete. Processed " << packetCount << " packets." << std::endl;
    std::cerr << "Found " << discoveredDevices.size() << " unique devices." << std::endl;
    
    closesocket(sock);
    WSACleanup();
}

std::string GetDeviceType(const std::string& mac) {
    // OUI-based device type detection
    std::string oui = mac.substr(0, 8);
    
    if (oui == "00:4C:E5") return "WiFi Router";
    if (oui == "E0:51:D8") return "Huawei Phone";
    if (oui == "F0:18:98" || oui == "3C:22:FB" || oui == "AC:DE:48") return "iPhone/iPad";
    if (oui == "28:F0:76" || oui == "34:02:86") return "Samsung Device";
    if (oui == "3C:6A:A7") return "Laptop/PC";
    
    return "Network Device";
}

void OutputJSON() {
    std::cout << "[" << std::endl;
    
    bool first = true;
    for (auto& pair : discoveredDevices) {
        if (!first) std::cout << "," << std::endl;
        first = false;
        
        DeviceInfo& dev = pair.second;
        bool isRouter = (dev.ip == "192.168.1.1" || dev.ip == "192.168.0.1");
        
        std::cout << "  {" << std::endl;
        std::cout << "    \"ip\": \"" << dev.ip << "\"," << std::endl;
        std::cout << "    \"mac\": \"" << dev.mac << "\"," << std::endl;
        std::cout << "    \"hostname\": \"" << dev.hostname << "\"," << std::endl;
        std::cout << "    \"type\": \"" << GetDeviceType(dev.mac) << "\"," << std::endl;
        std::cout << "    \"is_router\": " << (isRouter ? "true" : "false") << "," << std::endl;
        std::cout << "    \"packets\": " << dev.packetCount << std::endl;
        std::cout << "  }";
    }
    
    std::cout << std::endl << "]" << std::endl;
}

int main(int argc, char* argv[]) {
    int duration = 5; // Default 5 seconds
    
    if (argc > 1) {
        duration = atoi(argv[1]);
    }
    
    std::cerr << "=== Passive Network Device Discovery ===" << std::endl;
    std::cerr << "Capturing network packets to discover devices..." << std::endl;
    std::cerr << std::endl;
    
    CapturePackets(duration);
    
    std::cerr << std::endl;
    OutputJSON();
    
    return 0;
}
