#include "helper.h"
#include <windows.h>
#include <iostream>

bool containsString(vector<wstring> wStringVector, wstring wSearchString) {
	for (wstring wEle : wStringVector) {
		if (lstrcmpi(wEle.c_str(), wSearchString.c_str()) == 0) {
			std::wcout << "\nFound match: " << wSearchString;
			return true;
		}
	}

	return false;
}

bool containsString(vector<string> stringVector, string searchString) {
	for (string ele : stringVector) {
		if (_strcmpi(ele.c_str(), searchString.c_str()) == 0) {
			std::cout << "\nFound match: " << searchString;
			return true;
		}
	}

	return false;
}

wstring runPowerShellCommand(wstring& command) {
	wstring result;
	wchar_t buffer[4096];

	FILE* pipe = _wpopen(command.c_str(), L"r");
	while (fgetws(buffer, sizeof(buffer) / sizeof(wchar_t), pipe)) {
		result += buffer;
	}

	_pclose(pipe);
	return result;
}
