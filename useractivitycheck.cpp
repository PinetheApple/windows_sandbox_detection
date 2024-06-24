#include "useractivitycheck.h"
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>

#pragma comment(lib, "user32")

constexpr int INFO_BUFFER_SIZE = 15000;

bool userChecks() {
	TCHAR tUsername[INFO_BUFFER_SIZE] = { '\0' };
	DWORD dBuffCharCount = INFO_BUFFER_SIZE;

	if (GetUserName(tUsername, &dBuffCharCount)) {
		const wstring home_dir = L"C:\\Users\\" + (wstring)tUsername;
		const wstring desktop_dir = home_dir + L"\\Desktop\\*";
		const wstring documents_dir = home_dir + L"\\Documents\\*";
		const wstring downloads_dir = home_dir + L"\\Downloads\\*";
		std::cout << "\nFile count [Desktop]: " << getFileCount(desktop_dir);
		std::cout << "\nFile count [Documents]: " << getFileCount(documents_dir);
		std:: cout << "\nFile count [Downloads]: " << getFileCount(downloads_dir);
	}
	else {
		std::cerr << "\nCouldn't get username";
	}

	std::cout << "\nProcess count: " << getRunningProcessCount();
	return false;
}

int getFileCount(wstring tDirName) {
	WIN32_FIND_DATA w32FindData;
	HANDLE hFind = FindFirstFile(tDirName.c_str(), &w32FindData);
	int fileCount = 0;

	if (hFind == INVALID_HANDLE_VALUE) {
		std::cerr << "\nFailed to get handle to find files.";
		return -1;
	}

	do {
		fileCount++;
	} while (FindNextFile(hFind, &w32FindData) != 0);

	return fileCount < 4 ? 0 : fileCount - 3;
}

int getRunningProcessCount() {
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		std::cerr << "\nFailed to get handle to process snapshot.";
		return -1;
	}

	PROCESSENTRY32 pe32{};
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		std::cerr << "\nFailed to get first process in process snapshot.";
		return -1;
	}

	int procCount = 0;
	do {
		procCount++;
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return procCount;
}

bool hasUnusedBrowser() {

	return false;
}
