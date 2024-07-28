#include "Header.h"
#include <Windows.h>
#include <setupapi.h>
#include <Psapi.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <map>
#include <tlhelp32.h>
#include <filesystem>
//#include <ntifs.h>

bool Security::DebuggerCheck() {

    BOOL FOUND = false;

    BOOL DBGPresent = false;
    if (IsDebuggerPresent()) {
        DBGPresent = true;
        FOUND = true;
    }


    BOOL debuggerPresent = false;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    if (debuggerPresent) {
        debuggerPresent = true;
        FOUND = true;
    }



    BOOL PEB = false;
    _asm
    {
        xor eax, eax;			//clear the eax register
        mov eax, fs: [0x30] ;	//reference start of the process environment block
        mov eax, [eax + 0x02];	//beingdebugged is stored in peb + 2
        and eax, 0x000000FF;	//reference one byte
        mov PEB, eax;			//copy value to found
    }


    BOOL NtQuery = false;
    typedef NTSTATUS(NTAPI* NtQueryInformationProcessPtr)(
        HANDLE,
        UINT,
        PVOID,
        ULONG,
        PULONG
        );

    NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(
        GetModuleHandleA("ntdll.dll"),
        "NtQueryInformationProcess"
    );

    if (NtQueryInformationProcess) {
        DWORD debugPort = 0;
        NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 7 /* ProcessDebugPort */, &debugPort, sizeof(debugPort), nullptr);
        if (status == 0 && debugPort) {
            NtQuery = true;
            FOUND = true;
        }
    }

    DWORD thread_hide_from_debugger = 0x11;
    
    if (NtQueryInformationProcess == NULL) 
    {        
    }
    else {
           //(NtSetInformationThread)(GetCurrentThread(), thread_hide_from_debugger, 0, 0, 0);
    }        
    return FOUND;
}



bool Security::ProcessCheck() {

    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    std::string report;
    bool FOUND = false;

    
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        //std::cerr << "1 failed" << std::endl;

    }

    pe32.dwSize = sizeof(PROCESSENTRY32);


    if (!Process32First(hProcessSnap, &pe32)) {
        //std::cerr << "2 failed" << std::endl; 
        CloseHandle(hProcessSnap);    

    }

    std::map<DWORD, std::string> processNameMap;
    do {
        processNameMap[pe32.th32ProcessID] = pe32.szExeFile;
    } while (Process32Next(hProcessSnap, &pe32));

    Process32First(hProcessSnap, &pe32);
    std::vector<std::string> stringsToCheck = Security::getStrings();
    do {
        
        std::string processName = pe32.szExeFile;
        for (const auto& str : stringsToCheck) {
            //std::cout << "name0" << std::endl;
            //std::cout << processName << std::endl;
            if (processName.std::string::find(str) == 0) {
                DWORD parentPID = pe32.th32ParentProcessID;
                std::cout << str;
                std::string parentName = processNameMap[parentPID];
                FOUND = true;
            }
        }
  
    } while (Process32Next(hProcessSnap, &pe32));

    for (const auto& str : stringsToCheck) {
        std::string name = str;
        if (FindWindowA(name.c_str(), 0))
        {
            FOUND = true;
            //std::cout << "name1" << std::endl;
            //std::cout << name << std::endl;
        }
    }
    for (const auto& str : stringsToCheck) {
        std::string name = str;
        if (FindWindowA(NULL, name.c_str()))
        {
            FOUND = true;
            //std::cout << "name2" << std::endl;
            //std::cout << name << std::endl;
        }
    }

    CloseHandle(hProcessSnap);



    return FOUND;

}

bool Security::SteamCheck() {
    std::string steamPath = SteamHelp::GetInstallPath();
    if (steamPath.empty()) {
        //std::cerr << "steam installation path not found" << std::endl;
        return false;
    }

    std::filesystem::path configPath = std::filesystem::path(steamPath) / "steamapps" / "libraryfolders.vdf";
    if (!std::filesystem::exists(configPath)) {
        //std::cerr << "steam libraryfolders.vdf file not found at " << configPath << std::endl;

        std::filesystem::path configPath = std::filesystem::path(steamPath) / "config" / "libraryfolders.vdf";
        if (!std::filesystem::exists(configPath)) {
            return false;
        }
    }

    std::string vdfContent = SteamHelp::ReadFile(configPath.string());
    int gameCount = SteamHelp::CountGames(vdfContent);

    if (gameCount < 2)
        return true;

    //std::cout << "steam game count: " << gameCount << std::endl;
    return false;
}




bool Security::VMCheck() {
    bool FOUND = false;
    HANDLE handle = CreateFile(("\\\\.\\VBoxMiniRdrDN"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle != INVALID_HANDLE_VALUE) 
    { 
        CloseHandle(handle); 
        FOUND = true;
    }
        
    HKEY hKey = 0; 
    DWORD dwType = REG_SZ; 
    char buf[255] = { 0 }; 
    DWORD dwBufSize = sizeof(buf);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\VMware, Inc.\\VMware Tools"), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
    { 
        FOUND = true;
    }
        
    

    
    hKey = 0;
    dwType = REG_SZ;
    //buf[255] = { 0 };
    dwBufSize = sizeof(buf);
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\HardwareConfig\\Current\\"), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
        {
            LSTATUS result = RegGetValue(hKey, NULL, TEXT("SystemManufacturer"), RRF_RT_REG_SZ, NULL, buf, &dwBufSize);
            if (result == ERROR_SUCCESS)
            {
                if (strcmp(buf, "Microsoft Corporation") == 0)
                    FOUND = true;
            }
        }    
    
        hKey = 0;  
        dwType = REG_SZ; 
        //buf[255] = { 0 };  
        dwBufSize = sizeof(buf);

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\HardwareConfig\\Current\\"), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
        {
            LSTATUS result = RegGetValue(hKey, NULL, TEXT("BIOSVendor"), RRF_RT_REG_SZ, NULL, buf, &dwBufSize);
            if (result == ERROR_SUCCESS)
            {
                if (strcmp(buf, "Microsoft Corporation") == 0)
                    FOUND = true;
            }
        }    
    
        hKey = 0;
        dwType = REG_SZ;
        //buf[255] = { 0 };
        dwBufSize = sizeof(buf);

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\HardwareConfig\\Current\\"), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
        {
            LSTATUS result = RegGetValue(hKey, NULL, TEXT("SystemFamily"), RRF_RT_REG_SZ, NULL, buf, &dwBufSize);
            if (result == ERROR_SUCCESS)
            {
                if (strcmp(buf, "Virtual Machine") == 0)
                    FOUND = true;
            }
        }
   
        hKey = 0;
        dwType = REG_SZ;
        //buf[255] = { 0 };
        dwBufSize = sizeof(buf);

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\HardwareConfig\\Current\\"), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
        {
            LSTATUS result = RegGetValue(hKey, NULL, TEXT("SystemProductName"), RRF_RT_REG_SZ, NULL, buf, &dwBufSize);
            if (result == ERROR_SUCCESS)
            {
                if (strcmp(buf, "Virtual Machine") == 0)
                    FOUND = true;
            }
        }


    

    return FOUND;
}