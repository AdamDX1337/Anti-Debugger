#include "Header.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>
#include "json.hpp"
#include <windows.h>



std::string SteamHelp::ReadFile(const std::string& path) {
    std::ifstream file(path);
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}


std::string SteamHelp::GetInstallPath() {
    HKEY hKey;
    char value[512];
    DWORD BufferSize = sizeof(value);
    std::string steamPath = "";

    // Open the registry key
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Valve\\Steam", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "InstallPath", NULL, NULL, (LPBYTE)value, &BufferSize) == ERROR_SUCCESS) {
            steamPath = value;
        }
        RegCloseKey(hKey);
    }

    return steamPath;
}


int SteamHelp::CountGames(std::string & vdfContent) {
    int gameCount = 0;

    std::stringstream ss(vdfContent);
    std::string line;
    bool inAppsSection = false;

    while (std::getline(ss, line)) {
        if (line.find("\"apps\"") != std::string::npos) {
            inAppsSection = true;
        }
        else if (inAppsSection && line.find("}") != std::string::npos) {
            
            inAppsSection = false;
        }
        else if (inAppsSection) {
            
            gameCount++;
        }
    }
    return gameCount;
}