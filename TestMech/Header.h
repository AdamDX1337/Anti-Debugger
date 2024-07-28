#pragma once
#include <iostream>
#include <string>
#include <vector>

class FileWriter {
public:	
	static void Send(const std::string& a1);
};

class Info {
public:
	static void ProcessInfo();
	static void DriverInfo();
	static void SystemInfo();
	static void SteamInfo();
	
};

class Security {
public:
    static std::vector<std::string> getStrings() {
		//Add named you do NOT want to be runnin!

        std::vector<std::string> values;
        values.push_back("OLLYDBG");
		values.push_back("ghirda");

        values.push_back("ida");
        values.push_back("The Interactive Disassembler");

        values.push_back("x64dbg");
        values.push_back("x64dbg.exe");

        values.push_back("x32dbg");
        values.push_back("x32dbg.exe");

		values.push_back("x96dbg");
		values.push_back("x96dbg.exe");

        return values;
    }
	static bool DebuggerCheck();
	static bool ProcessCheck();
	static bool VMCheck();
	static bool SteamCheck();

	//static void DriverCheck();
};

class SteamHelp {
public:
	static std::string ReadFile(const std::string& path);
	static std::string GetInstallPath();
	static int CountGames(std::string& vdfContent);
};