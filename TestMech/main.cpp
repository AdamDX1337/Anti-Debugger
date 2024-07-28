
#include <iostream>
#include <Windows.h>
#include "Header.h"

void MainFunc() {
    //std::cout << "MainFunc1";
    bool testing = false;
    bool OneChecks = false;

    //AllocConsole();

    if (!testing) {
        bool securityVM = false;
        bool securityProc = false;
        bool securityDBG = false;
        bool securitySteam = false;
        bool broken = false;

        while (!securityProc && !securityVM && !securityDBG && !securitySteam) {

            securityProc = Security::ProcessCheck();
            securityDBG = Security::DebuggerCheck();

            if (!OneChecks) {
                securityVM = Security::VMCheck();
                securitySteam = Security::SteamCheck();
                OneChecks = true;
            }

            //std::cout << "check\n";
        }

        broken = true;

        if (broken) {
            Info::SystemInfo();
            Info::ProcessInfo();
            Info::DriverInfo();
            Info::SteamInfo();
            ExitProcess(1);
        }
    }
}
DWORD WINAPI MainThread(LPVOID lpReserved)
{
    //std::cout << "MainThread0";
    MainFunc();
    //std::cout << "MainThread";
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    {
       // std::cout << "Loaded";
        HANDLE hThread = CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
        //if (hThread == nullptr)
            //std::cerr << "Failed to create thread, error: " << GetLastError() << std::endl;
    }
        //CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
    //case DLL_THREAD_ATTACH:
    //case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


