#include "timecheck.h"
#include <iostream>
#include <windows.h>
#include <sysinfoapi.h>

bool timeChecks() {
    DWORD dCurrTime = GetTickCount64();

    std::cout << "\nSystem started " << (dCurrTime/60000) << " minutes ago.";
    return false;
}
