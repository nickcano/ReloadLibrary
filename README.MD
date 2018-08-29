# ReloadLibrary

ReloadLibrary is a quick-and-dirty anti-hook library. Given the name of a `.dll`, it will make a temporary copy of the `.dll` on disk, load the copy, and overwrite the import address table with corresponding function addresses in the cloned library. Examples:
```cpp
// reload kernel32.dll and replace imports in the main module
ReloadLibrary("kernel32.dll");

// reload ntdll and replace imports in kernel32.dll
ReloadLibrary("ntdll.dll", GetModuleHandleA("kernel32.dll"));
```

A call to `ReloadLibrary()` will return 0 on failure, otherwise returning the number of function pointers replaced in the import address table.

# Development

The code is C++ with project files for Visual Studio 2017. This is a quick and dirty PoC and I do not intend to maintain or improve it. It is simple to use, you can import the library or simply copy the code from `ReloadLibrary.cpp` into your project.

I have done basically no testing beyond making sure the concept works, and there are likely various edge-cases which can be handled.

A known issue is that clone libraries will be left in temp, since they cannot be deleted until the process dies. There are various ways to fix this; I would recommend using the `RunOnce` registry key to set up a call to `del` the file upon the next login.