// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>

#include <windows.h>
#include <psapi.h>

constexpr uint16_t MASK = 0xffff;

class DLog
{
    FILE *file = nullptr;

    DLog(const char* filename) {
        if (!file)
        {
            fopen_s(&file, filename, "w+");
        }
    }

    ~DLog() {
        fclose(file);
        file = nullptr;
    }

public:

    static DLog& Get()
    {
        static DLog instance = DLog("DLSSFix.log");
        return instance;
    }

    void println(const char* fmt, ...)
    {
        if (file)
        {
            va_list args;
            va_start(args, fmt);
            vfprintf(file, fmt, args);
            fprintf(file, "\n");
            va_end(args);
            fflush(file);
        }
    }
};

HMODULE GetBaseModule()
{
    HMODULE hModule = 0;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (!hProcess)
    {
        return 0;
    }

    DWORD dwSizeModules;
    // get The number of bytes required to store all module handles in the lphModule array
    EnumProcessModules(hProcess, nullptr, 0, &dwSizeModules);
    if (!dwSizeModules)
    {
        return 0;
    }

    HMODULE* Modules = (HMODULE*)malloc(dwSizeModules);
    if (Modules)
    {
        if (EnumProcessModules(hProcess, Modules, dwSizeModules, &dwSizeModules))
        {
            hModule = Modules[0];
        }
        free(Modules);
    }

    return hModule;
}

std::string GetBaseName()
{
    char basename[100];
    GetModuleBaseNameA(GetCurrentProcess(), nullptr, (LPSTR)&basename, 100);
    return std::string(basename);
}


//inline uintptr_t SigScan(std::vector<uint16_t> pattern, bool logProcess = false, std::string msg = {}, bool failSilently = false)
std::vector<LPVOID> MemPatternScan(LPVOID lpBase, std::vector<uint16_t> pattern, bool bScanAllModules = false, size_t MaxMatches = 0)
{
    std::vector<LPVOID> OutMatches;
	LPBYTE lpRegionBase = (LPBYTE)lpBase;

    DLog& Log = DLog::Get();

    std::string patternString = "";
    for (auto bytes : pattern)
    {
        std::stringstream stream;
        std::string byte = "";
        if (bytes > 0xff)
        {
            byte = "??";
        }
        else
        {
            stream << std::hex << bytes;
            byte = stream.str();
        }
        patternString.append(byte + " ");
    }
    Log.println("Pattern: %s", patternString.c_str());

	LPBYTE currentAddress = 0;
	while (true)
	{
		MEMORY_BASIC_INFORMATION memoryInfo = { 0 };
		if (VirtualQuery((void*)lpRegionBase, &memoryInfo, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
		{
			DWORD error = GetLastError();
			if (error == ERROR_INVALID_PARAMETER)
			{
				Log.println("Reached end of scannable memory.");
			}
			else
			{
				Log.println("VirtualQuery failed, error code: %i.", error);
			}
			break;
		}
		lpRegionBase = (LPBYTE)memoryInfo.BaseAddress;

        bool bIsValidMem = memoryInfo.State == MEM_COMMIT &&
            (memoryInfo.Protect & (PAGE_EXECUTE_READWRITE | PAGE_READWRITE | PAGE_READONLY | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;

		bool bShouldScan = bScanAllModules || memoryInfo.AllocationBase == lpBase;

		CHAR moduleName[100];
		GetModuleFileNameA((HMODULE)memoryInfo.AllocationBase, moduleName, 100);

		if (bIsValidMem && bShouldScan)
		{
			Log.println("Checking region: %p %d %s", lpRegionBase, memoryInfo.RegionSize, moduleName);
			currentAddress = lpRegionBase;
			while (currentAddress < (lpRegionBase + memoryInfo.RegionSize) - pattern.size())
			{
				for (size_t i = 0; i < pattern.size(); i++)
				{
					uint8_t bitmask = ~uint8_t(pattern[i] >> 8);
					bool bByteMatches = ((*(uint8_t*)currentAddress) & bitmask) == (uint8_t(pattern[i] & 0xff) & bitmask);
					++currentAddress;
					if (!bByteMatches)
					{
						break;
					}
					if (i == pattern.size() - 1)
					{
						LPVOID lpMatch = currentAddress - pattern.size();
						Log.println("Found signature at %p", lpMatch);
                        OutMatches.push_back(lpMatch);
                        break;
					}
				}
			}
		}
		else
		{
			//Log.println("Skipped region: %p %s", lpRegionBase, moduleName);
		}

        if (MaxMatches > 0 && OutMatches.size() >= MaxMatches)
        {
            break;
        }

		lpRegionBase += memoryInfo.RegionSize;
	}

	return OutMatches;
}

/*
RDR2.exe+26D5E7C - E8 EF907A00           - call RDR2.NVSDK_NGX_Parameter_SetI
RDR2.exe+26D5E81 - 44 8B 43 14           - mov r8d,[rbx+14]                     ; R8 = 2B -> R8 = B
RDR2.exe+26D5E85 - 48 8D 15 14A0F300     - lea rdx,[RDR2.exe+360FEA0]
RDR2.exe+26D5E8C - 48 8B CF              - mov rcx,rdi
*/

void Main()
{
    DLog& log = DLog::Get();

    log.println("%p %s", GetBaseModule(), GetBaseName().c_str());

    std::vector<uint16_t> Pattern = {0xE8, MASK, MASK, MASK, MASK, 0x44, 0x8B, 0x43, 0x14, 0x48, 0x8D, 0x15, MASK, MASK, MASK, MASK, 0x48, 0x8B, 0xCF};
    std::vector<LPVOID> Matches = MemPatternScan(GetBaseModule(), Pattern);

    // replace memory on 2nd and 3rd matches, there should be 3 in total;
    Matches = std::vector<LPVOID>{ Matches[1], Matches[2] };
    for (LPVOID p : Matches)
    {
        p = (LPBYTE)p + 5;
        log.println("Replacing memory at %p", p);

        DWORD oldProtec, dwDummy;
        VirtualProtect(p, 4, PAGE_EXECUTE_READWRITE, &oldProtec);
        memcpy(p, "\x41\xB0\x0B\x90", 4);
        VirtualProtect(p, 4, oldProtec, &dwDummy);
    }
}

DWORD WINAPI MainThread(LPVOID lpParam)
{
    Main();
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //scriptRegister(hModule, Main);
        CreateThread(0, 0, &MainThread, 0, 0, 0);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

