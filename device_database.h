// Enhanced Device Identification Database
// Maps MAC OUI to manufacturer and device types
#ifndef DEVICE_DATABASE_H
#define DEVICE_DATABASE_H

#include <string>
#include <map>

struct ManufacturerInfo {
    std::string name;
    std::string commonDevices;
};

// Extended OUI database
std::map<std::string, ManufacturerInfo> ouiDatabase = {
    // Apple
    {"00:03:93", {"Apple", "Mac/iPhone/iPad"}},
    {"00:0A:27", {"Apple", "iPhone/iPad"}},
    {"00:0A:95", {"Apple", "AirPort/Mac"}},
    {"00:0D:93", {"Apple", "Mac"}},
    {"00:10:FA", {"Apple", "Mac/iPhone"}},
    {"00:11:24", {"Apple", "Mac/iPhone/iPad"}},
    {"00:14:51", {"Apple", "Mac"}},
    {"00:16:CB", {"Apple", "Mac/iPhone"}},
    {"00:17:F2", {"Apple", "Mac/iPhone/iPad"}},
    {"00:19:E3", {"Apple", "Mac"}},
    {"00:1B:63", {"Apple", "Mac/iPhone"}},
    {"00:1C:B3", {"Apple", "Mac"}},
    {"00:1D:4F", {"Apple", "Mac/iPhone"}},
    {"00:1E:52", {"Apple", "Mac"}},
    {"00:1F:5B", {"Apple", "Mac/iPhone/iPad"}},
    {"00:1F:F3", {"Apple", "Mac"}},
    {"00:21:E9", {"Apple", "Mac/iPhone"}},
    {"00:22:41", {"Apple", "Mac"}},
    {"00:23:12", {"Apple", "Mac/iPhone/iPad"}},
    {"00:23:32", {"Apple", "Mac"}},
    {"00:23:6C", {"Apple", "Mac/iPhone"}},
    {"00:23:DF", {"Apple", "Mac"}},
    {"00:24:36", {"Apple", "Mac/iPhone/iPad"}},
    {"00:25:00", {"Apple", "Mac"}},
    {"00:25:4B", {"Apple", "Mac/iPhone"}},
    {"00:25:BC", {"Apple", "Mac"}},
    {"00:26:08", {"Apple", "Mac/iPhone/iPad"}},
    {"00:26:4A", {"Apple", "Mac"}},
    {"00:26:B0", {"Apple", "Mac/iPhone"}},
    {"00:26:BB", {"Apple", "Mac"}},
    {"3C:22:FB", {"Apple", "iPhone 12/13/14"}},
    {"AC:DE:48", {"Apple", "iPhone 11/12"}},
    {"F0:18:98", {"Apple", "iPhone/iPad"}},
    {"A4:83:E7", {"Apple", "iPhone/iPad"}},
    {"BC:92:6B", {"Apple", "iPhone/iPad"}},
    
    // Samsung
    {"00:00:F0", {"Samsung", "Phone/Tablet"}},
    {"00:12:47", {"Samsung", "Phone"}},
    {"00:12:FB", {"Samsung", "Galaxy"}},
    {"00:13:77", {"Samsung", "Phone/TV"}},
    {"00:15:B9", {"Samsung", "Galaxy"}},
    {"00:16:32", {"Samsung", "Phone"}},
    {"00:16:6B", {"Samsung", "Galaxy"}},
    {"00:16:6C", {"Samsung", "Phone/Tablet"}},
    {"00:17:C9", {"Samsung", "Galaxy"}},
    {"00:17:D5", {"Samsung", "Phone"}},
    {"00:18:AF", {"Samsung", "Galaxy"}},
    {"00:1A:8A", {"Samsung", "Phone/Tablet"}},
    {"00:1B:98", {"Samsung", "Galaxy"}},
    {"00:1C:43", {"Samsung", "Phone"}},
    {"00:1D:25", {"Samsung", "Galaxy"}},
    {"00:1E:7D", {"Samsung", "Phone/Tablet"}},
    {"00:1F:CD", {"Samsung", "Galaxy"}},
    {"00:21:19", {"Samsung", "Phone"}},
    {"00:21:4C", {"Samsung", "Galaxy"}},
    {"00:21:D1", {"Samsung", "Phone/Tablet"}},
    {"00:21:D2", {"Samsung", "Galaxy"}},
    {"00:23:39", {"Samsung", "Phone"}},
    {"00:23:99", {"Samsung", "Galaxy"}},
    {"00:23:D6", {"Samsung", "Phone/Tablet"}},
    {"00:23:D7", {"Samsung", "Galaxy"}},
    {"00:24:54", {"Samsung", "Phone"}},
    {"00:24:90", {"Samsung", "Galaxy"}},
    {"00:24:91", {"Samsung", "Phone/Tablet"}},
    {"00:25:38", {"Samsung", "Galaxy"}},
    {"00:25:66", {"Samsung", "Phone"}},
    {"00:26:37", {"Samsung", "Galaxy"}},
    {"00:26:5D", {"Samsung", "Phone/Tablet"}},
    {"28:F0:76", {"Samsung", "Galaxy Phone"}},
    {"E8:50:8B", {"Samsung", "Smart TV"}},
    {"34:02:86", {"Samsung", "Galaxy/Tablet"}},
    {"BC:20:BA", {"Samsung", "Galaxy S/Note"}},
    
    // Huawei
    {"00:1E:10", {"Huawei", "Phone"}},
    {"00:25:9E", {"Huawei", "Phone/Router"}},
    {"00:46:4B", {"Huawei", "Phone"}},
    {"00:66:4B", {"Huawei", "Phone/Tablet"}},
    {"00:9A:CD", {"Huawei", "Phone"}},
    {"00:E0:FC", {"Huawei", "Phone/Router"}},
    {"E0:51:D8", {"Huawei", "Phone/Tablet"}},
    {"0C:37:DC", {"Huawei", "Phone"}},
    {"18:99:D1", {"Huawei", "Phone/Tablet"}},
    {"AC:E2:D3", {"Huawei", "Phone"}},
    
    // Xiaomi
    {"34:CE:00", {"Xiaomi", "Phone/Tablet"}},
    {"64:09:80", {"Xiaomi", "Phone"}},
    {"78:02:F8", {"Xiaomi", "Phone/IoT"}},
    {"F8:A4:5F", {"Xiaomi", "Phone/Router"}},
    
    // Intel (Laptops)
    {"00:02:B3", {"Intel", "Laptop WiFi"}},
    {"00:03:47", {"Intel", "Laptop WiFi"}},
    {"00:04:23", {"Intel", "Laptop WiFi"}},
    {"3C:6A:A7", {"Intel", "Laptop WiFi Adapter"}},
    
    // Routers
    {"00:4C:E5", {"China Telecom", "TG2212 Router"}},
    {"00:90:FE", {"Sercomm", "Router"}},
    
    // HP
    {"00:01:E6", {"HP", "Laptop/Printer"}},
    {"00:10:83", {"HP", "Laptop"}},
    
    // Dell
    {"00:06:5B", {"Dell", "Laptop/PC"}},
    {"00:0B:DB", {"Dell", "Laptop"}},
    
    // Lenovo
    {"00:21:CC", {"Lenovo", "Laptop/Tablet"}},
    {"54:EE:75", {"Lenovo", "Laptop"}},
};

std::string GetManufacturer(const std::string& mac) {
    std::string oui = mac.substr(0, 8);
    
    auto it = ouiDatabase.find(oui);
    if (it != ouiDatabase.end()) {
        return it->second.name;
    }
    
    return "Unknown";
}

std::string GetDeviceType(const std::string& mac) {
    std::string oui = mac.substr(0, 8);
    
    auto it = ouiDatabase.find(oui);
    if (it != ouiDatabase.end()) {
        return it->second.commonDevices;
    }
    
    return "Network Device";
}

#endif
