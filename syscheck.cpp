#include "syscheck.h"
#include "helper.h"
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <tchar.h>
#include <vector>
#include <sysinfoapi.h>
#include <shlwapi.h>

#pragma comment(lib, "IPHLPAPI")
#pragma comment(lib, "Shlwapi")

#define _WINSOCKAPI_
#define wstring std::wstring
#define vector std::vector
constexpr int INFO_BUFFER_SIZE = 15000;

bool systemChecks() {
	// try loading comsnap.dll to verify that program can detect blacklisted dlls
	/* if (LoadLibrary(L"comsnap.dll") != NULL) {
		std::cout << "Loaded comsnap.dll successfully";
	}
	else {
		"Failed to load comsnap.dll";
	} */

	hasVMNetworkAdapter();
	std::cout << "\nCore count: " << getNumProcessors();
	hasVMDllsLoaded();
	hasKnownFileName();
	return (hasVMUsername() && hasVMDrive() && hasVMProcess() && hasVMMac());
}

bool hasVMProcess() {
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		std::cerr << "\nFailed to get handle to process snapshot.";
		return false;
	}

	PROCESSENTRY32 pe32{};
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		std::cerr << "\nFailed to get first process in process snapshot.";
		return false;
	}

	const vector<wstring> wCommonVMProcesses = {
		L"vboxservice.exe",
		L"vboxtray.exe",
		L"vmtoolsd.exe",
		L"vmwaretray.exe",
		L"vmwareuser.exe",
		L"VGAuthService.exe",
		L"vmacthlp.exe"
	};

	do {
		WCHAR* wExeFile = pe32.szExeFile;
		if (containsString(wCommonVMProcesses, (wstring)wExeFile)) {
			CloseHandle(hProcessSnap);
			std::wcout << "\nFound a possible vm/sandbox process running. Process: " << wExeFile;
			return true;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return false;
}

bool hasVMDrive() {
	wstring command = L"powershell.exe -Command \"[System.IO.DriveInfo]::GetDrives() | Select-Object -ExpandProperty DriveFormat -ErrorAction 'silentlycontinue'\"";
	wstring output = runPowerShellCommand(command);

	if (!output.empty() && (output.find(L"VBox") != string::npos)) {
		std::cout << "\nFound a drive that is most likely a VM shared folder for Virtual Box.";
		return true;
	}

	return false;
}

bool hasVMUsername() {
	TCHAR tUsername[INFO_BUFFER_SIZE] = { '\0' };
	DWORD dBuffCharCount = INFO_BUFFER_SIZE;
	const vector<wstring> wCommonSandboxUsernames = {
		L"emily",
		L"hapubws",
		L"hong lee",
		L"johnson",			//Lastline Sandbox
		L"miller",			//Lastline Sandbox
		L"john doe",		//VirusTotal Cuckoofork Sandbox
		L"timmy",
		L"milozs",
		L"peter wilson",
		L"sandbox",
		L"sand box",
		L"virus",
		L"malware",
		L"maltest",
		L"vmware",
		L"test",
		L"testuser",
		L"test user",
		L"user",
		L"currentuser",
		L"it-admin",
	};

	if (!GetUserName(tUsername, &dBuffCharCount)) {
		std::cerr << "\nCouldn't get username of person logged in.";
		return false;
	}

	if (containsString(wCommonSandboxUsernames, (wstring)tUsername)) {
		std::wcout << "\nFound a username that is commonly used in vms/sandboxes. Username: " << (wstring)tUsername;
		return true;
	}

	return false;
}

bool hasVMHostname() {
	TCHAR tHostname[INFO_BUFFER_SIZE] = { '\0' };
	DWORD dBuffCharCount = INFO_BUFFER_SIZE;
	const vector<wstring> wCommonSandboxHostnames = {
		L"sandbox",
		L"7silvia",
		L"hanspeter-pc",
		L"john-pc",
		L"mueller-pc",
		L"win7-traps",
		L"fortinet",
		L"tequilaboomboom", // VirusTotal Cuckoofork Sandbox
	};

	if (GetComputerName(tHostname, &dBuffCharCount)) {
		std::cerr << "Couldn't get computer name.";
		return false;
	}
	
	if (containsString(wCommonSandboxHostnames, (wstring)tHostname)) {
		std::wcout << "\nFound a hostname that is commonly used in vms/sandboxes. Hostname: " << (wstring)tHostname;
		return true;
	}

	return false;
}

bool hasVMMac() {
	char macAddr[30];
	ULONG family = AF_UNSPEC;
	ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
	ULONG uOutBuffLen = sizeof(IP_ADAPTER_ADDRESSES);

	PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)HeapAlloc(GetProcessHeap(), 0, uOutBuffLen);
	if (GetAdaptersAddresses(family, flags, NULL, pAddresses, &uOutBuffLen) == ERROR_BUFFER_OVERFLOW) {
		HeapFree(GetProcessHeap(), 0, pAddresses);
		pAddresses = (IP_ADAPTER_ADDRESSES*)HeapAlloc(GetProcessHeap(), 0, uOutBuffLen);
	}

	if (pAddresses == NULL) {
		std::cerr << "\nMemory allocation failed for IP_ADAPTER_ADDRESSES struct\n";
		return false;
	}

	PIP_ADAPTER_ADDRESSES pCurrAddresses{};
	const vector<string> knownVMMacAddresses = {
		"08-00-27",   // Virtual Box
		"00-0C-29",   // Standalone ESXi hosts, VMware Horizon, VMware Workstation
		"00:50:56",   // VMware Workstation, VMware vSphere, VMware ESXi server
		"00:05:69",   // VMware ESXi, VMware GSX
		"00:1C:14",   // VMWare
		"00:16:E3",   // Xen
		"00:1C:42",   // Parallels
	};

	if (GetAdaptersAddresses(family, flags, NULL, pAddresses, &uOutBuffLen) == NO_ERROR) {
		pCurrAddresses = pAddresses;
		while (pCurrAddresses) {
			if (pCurrAddresses->PhysicalAddressLength != 0) {
				sprintf_s(macAddr, "%.2X-%.2X-%.2X", (int)pCurrAddresses->PhysicalAddress[0], (int)pCurrAddresses->PhysicalAddress[1], (int)pCurrAddresses->PhysicalAddress[2]);
				if (containsString(knownVMMacAddresses, (string)macAddr)) {
					std::cout << "\nFound a known VM Mac Address.";
					HeapFree(GetProcessHeap(), 0, pAddresses);
					return true;
				}
			}

			pCurrAddresses = pCurrAddresses->Next;
		}

		HeapFree(GetProcessHeap(), 0, pAddresses);
	}
	else {
		std::cerr << "\nThere was an error while trying to get adapter addresses of the system.";
	}

	return false;
}

bool hasVMNetworkAdapter() {
	ULONG uOutBuffLen = sizeof(IP_INTERFACE_INFO);
	PIP_INTERFACE_INFO pInterfaceInfo = (IP_INTERFACE_INFO*)HeapAlloc(GetProcessHeap(), 0, uOutBuffLen);
	const vector<wstring> wKnownVMNetAdapters = {
		L"vmware",
	};

	if (GetInterfaceInfo(pInterfaceInfo, &uOutBuffLen) == ERROR_INSUFFICIENT_BUFFER) {
		HeapFree(GetProcessHeap(), 0, pInterfaceInfo);
		pInterfaceInfo = (IP_INTERFACE_INFO*)HeapAlloc(GetProcessHeap(), 0, uOutBuffLen);
	}

	if (GetInterfaceInfo(pInterfaceInfo, &uOutBuffLen) == NO_ERROR) {
		for (long i = 0; i < pInterfaceInfo->NumAdapters; i++) {
			if (containsString(wKnownVMNetAdapters, (wstring)pInterfaceInfo->Adapter[i].Name)) {
				std::wcout << "\nGot network interface name. Interface: " << (wstring)pInterfaceInfo->Adapter[i].Name;
				HeapFree(GetProcessHeap(), 0, pInterfaceInfo);
				return true;
			} 
		}

		HeapFree(GetProcessHeap(), 0, pInterfaceInfo);
	}
	else {
		std::cerr << "\nThere was an error while trying to get information regarding interfaces of the system.";
	}

	return false;
}

int getNumProcessors() {
	SYSTEM_INFO siSystemInfo{};
	
	GetSystemInfo(&siSystemInfo);

	return siSystemInfo.dwNumberOfProcessors;
}

bool hasVMDllsLoaded() {
	HMODULE hDll = nullptr;
	const vector<wstring> wKnownVMDlls = {
		L"avghookx.dll",	// AVG
		L"avghooka.dll",	// AVG
		L"snxhk.dll",		// Avast
		L"sbiedll.dll",		// Sandboxie
		L"dbghelp.dll",		// WindBG
		L"api_log.dll",		// iDefense Lab
		L"dir_watch.dll",	// iDefense Lab
		L"pstorec.dll",		// SunBelt Sandbox
		L"vmcheck.dll",		// Virtual PC
		L"wpespy.dll",		// WPE Pro
		L"cmdvrt64.dll",    // Comodo Container
		L"cmdvrt32.dll",	// Comodo Container
		//L"comsnap.dll",							// testing purposes
	};

	for (wstring knownDll : wKnownVMDlls) {
		hDll = GetModuleHandle(knownDll.c_str());

		if (hDll != NULL) {
			std::wcout << "\nFound a known VM dll loaded with current program's modules: " << knownDll;
			return true;
		}
	}

	return false;
}

bool hasKnownFileName() {
	TCHAR tFilePath[MAX_PATH] = { '\0' };
	DWORD dFileNamesize = MAX_PATH;
	const vector<wstring> wKnownFileNames = {
		L"sample.exe",
		L"bot.exe",
		L"sandbox.exe",
		L"malware.exe",
		L"test.exe",
		L"klavme.exe",
		L"myapp.exe",
		L"testapp.exe",
	};

	if (GetModuleFileName(NULL, tFilePath, dFileNamesize)) {
		TCHAR* tExeName = PathFindFileName(tFilePath);

		if (containsString(wKnownFileNames, (wstring)tExeName)) {
			std::wcout << "\nName of executable is commonly used in sandboxes. Name: " << (wstring)tExeName;
			return true;
		}
	}
	else {
		std::cerr << "\nFailed to path to executable.";
	}

	return false;
}
