#include "timecheck.h"
#include <iostream>
#include <windows.h>
#include <sysinfoapi.h>

bool timeChecks() {
    DWORD dCurrTime = GetTickCount64();

    std::cout << "\nSystem started " << (dCurrTime/60000) << " minutes ago.";
    return ((dCurrTime/60000) < 10); //return true if the system started less than 10 minutes ago
}
