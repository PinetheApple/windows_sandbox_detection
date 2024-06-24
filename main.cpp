#include <stdio.h>
#include "syscheck.h"
#include "useractivitycheck.h"
#include "timecheck.h"

bool isSandboxed();

int main(void) {
    if (isSandboxed()) {
        printf("\nThis program is running in a virtual machine/sandbox.");
    } else {
        printf("\nThis program is not running in a virtual machine/sandbox");
    }

    return 0;
}

bool isSandboxed() {
    timeChecks();
    userChecks();
    return (systemChecks());
}
