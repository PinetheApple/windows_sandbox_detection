#pragma once
#include <string>

#define wstring std::wstring

bool userChecks();
int getFileCount(wstring tDirName);
int getRunningProcessCount();
bool hasUnusedBrowser();
