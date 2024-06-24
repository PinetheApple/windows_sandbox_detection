#pragma once
#include <string>
#include <vector>

#define wstring std::wstring
#define string std::string
#define vector std::vector

bool containsString(vector<wstring> wStringVector, wstring wSearchString);
bool containsString(vector<string> stringVector, string searchString);
wstring runPowerShellCommand(wstring& command);
