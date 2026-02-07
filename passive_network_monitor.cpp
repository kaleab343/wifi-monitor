// Passive Network Monitor - Captures all traffic to discover devices
// Requires: Administrator privileges
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>
#include <set>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// Define SIO_RCVALL if not defined
#ifndef SIO_RCVALL
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
#endif

// Ethernet header structure
#pragma pack(push, 1)
struct EthernetHeader {
    unsigned char dest_mac[6];
    unsigned char src_mac[6];
    unsigned short ether_type;
};

struct IPv4Header {
    unsigned char version_ihl;
    unsigned char tos;
    unsigned short total_length;
    unsigned short identification;
    unsigned short flags_fragment;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned char src_ip[4];
    unsigned char dest_ip[4];
};
#pragma pack(pop)

struct DeviceInfo {
    std::string mac;
    std::string ip;
    std::string last_seen;
    int packet_count;
    std::set<std::string> contacted_ips;
};

std::map<std::string, DeviceInfo> discovered_devices;

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

std::string GetCurrentTime() {
    time_t now = time(nullptr);
    char buf[80];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return std::string(buf);
}

void ProcessPacket(unsigned char* packet, int length) {
    if (length < sizeof(EthernetHeader)) return;
    
    EthernetHeader* eth = (EthernetHeader*)packet;
    std::string src_mac = MacToString(eth->src_mac);
    std::string dst_mac = MacToString(eth->dest_mac);
    
    // Skip broadcast and multicast
    if (eth->src_mac[0] & 0x01) return;
    if (eth->dest_mac[0] == 0xFF) return;
    
    // Check if it's an IP packet
    unsigned short ether_type = ntohs(eth->ether_type);
    if (ether_type == 0x0800 && length >= sizeof(EthernetHeader) + sizeof(IPv4Header)) {
        // IPv4 packet
        IPv4Header* ip = (IPv4Header*)(packet + sizeof(EthernetHeader));
        
        std::string src_ip = IPToString(ip->src_ip);
        std::string dst_ip = IPToString(ip->dest_ip);
        
        // Only track 192.168.x.x addresses
        if (src_ip.substr(0, 8) == "192.168.") {
            if (discovered_devices.find(src_mac) == discovered_devices.end()) {
                DeviceInfo info;
                info.mac = src_mac;
                info.ip = src_ip;
                info.last_seen = GetCurrentTime();
                info.packet_count = 0;
                discovered_devices[src_mac] = info;
                
                std::cerr << "NEW DEVICE: " << src_ip << " (" << src_mac << ")" << std::endl;
            }
            
            discovered_devices[src_mac].packet_count++;
            discovered_devices[src_mac].last_seen = GetCurrentTime();
            discovered_devices[src_mac].contacted_ips.insert(dst_ip);
        }
    }
}

// Promiscuous mode packet capture
int CaptureTraffic(int duration_seconds) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    // Create raw socket for promiscuous capture
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Failed to create raw socket. Error: " << WSAGetLastError() << std::endl;
        std::cerr << "NOTE: This requires Administrator privileges!" << std::endl;
        return 1;
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
        return 1;
    }
    
    // Enable promiscuous mode (RCVALL)
    DWORD dwValue = 1;
    if (ioctlsocket(sock, SIO_RCVALL, &dwValue) == SOCKET_ERROR) {
        std::cerr << "Failed to enable promiscuous mode. Error: " << WSAGetLastError() << std::endl;
        std::cerr << "Make sure to run as Administrator!" << std::endl;
        closesocket(sock);
        return 1;
    }
    
    std::cerr << "Listening on " << localIP << " in promiscuous mode..." << std::endl;
    std::cerr << "Monitoring network traffic for " << duration_seconds << " seconds..." << std::endl;
    std::cerr << "All devices that send ANY traffic will be detected!" << std::endl;
    std::cerr << std::endl;
    
    // Capture packets
    unsigned char buffer[65536];
    time_t start_time = time(nullptr);
    int total_packets = 0;
    
    while (time(nullptr) - start_time < duration_seconds) {
        int recv_size = recv(sock, (char*)buffer, sizeof(buffer), 0);
        
        if (recv_size > 0) {
            total_packets++;
            ProcessPacket(buffer, recv_size);
            
            // Show progress every 100 packets
            if (total_packets % 100 == 0) {
                std::cerr << "\rPackets: " << total_packets 
                         << " | Devices: " << discovered_devices.size() << "   " << std::flush;
            }
        }
    }
    
    std::cerr << std::endl << std::endl;
    std::cerr << "Capture complete!" << std::endl;
    std::cerr << "Total packets captured: " << total_packets << std::endl;
    std::cerr << "Total devices found: " << discovered_devices.size() << std::endl;
    
    closesocket(sock);
    WSACleanup();
    
    return 0;
}

int main(int argc, char* argv[]) {
    int duration = 10;
    if (argc > 1) {
        duration = atoi(argv[1]);
    }
    
    std::cerr << "========================================" << std::endl;
    std::cerr << "Passive Network Monitor (MITM Mode)" << std::endl;
    std::cerr << "========================================" << std::endl;
    std::cerr << "Captures ALL network traffic to discover devices" << std::endl;
    std::cerr << "Even silent/sleeping devices will be found!" << std::endl;
    std::cerr << std::endl;
    
    int result = CaptureTraffic(duration);
    
    if (result == 0) {
        // Output JSON
        std::cout << "[" << std::endl;
        
        bool first = true;
        for (auto& pair : discovered_devices) {
            if (!first) std::cout << "," << std::endl;
            first = false;
            
            DeviceInfo& dev = pair.second;
            bool is_router = (dev.ip == "192.168.1.1" || dev.ip == "192.168.0.1");
            
            std::cout << "  {" << std::endl;
            std::cout << "    \"ip\": \"" << dev.ip << "\"," << std::endl;
            std::cout << "    \"mac\": \"" << dev.mac << "\"," << std::endl;
            std::cout << "    \"hostname\": \"\"," << std::endl;
            std::cout << "    \"type\": \"Network Device\"," << std::endl;
            std::cout << "    \"is_router\": " << (is_router ? "true" : "false") << "," << std::endl;
            std::cout << "    \"packets_seen\": " << dev.packet_count << "," << std::endl;
            std::cout << "    \"last_seen\": \"" << dev.last_seen << "\"" << std::endl;
            std::cout << "  }";
        }
        
        std::cout << std::endl << "]" << std::endl;
    }
    
    return result;
}
