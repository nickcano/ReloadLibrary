#include "ReloadLibrary.h"
#pragma comment(lib, "ReloadLibrary.lib")

#include <Windows.h>

int main()
{
	if (ReloadLibrary("kernel32.dll"))
		Sleep(10000); // if we step into this, we should see it in our clone dll

    return 0;
}

