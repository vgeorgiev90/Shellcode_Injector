This is a simple shellcode injector utility that i have created in order to start learning Csharp and prepare for the RTO2 exam.
The flow is as follows
1. Fetch the shellcode from a remote server, or a local file
2. Create a sacrifical process for injection, or inject existing one
3. Allocate memory for the shellcode
4. Execute the shellcode

In order to reduce the number of PInvoke calls only 2 functions are loaded: LoadLibraryA and GetProcAddress.
They are referenced with their ordinal numbers instead of a function name. The hardcoded numbers (697,969) are taken from a Windows 10 standard edition.
For different flavors change accordingly and recompile. Additionally all of the function calls are hidden trough dynamic importations and type redefinitions.
The following APIs are used from kernel32.dll and ntdll.dll

Memory management:
VirtualAllocEX, VirtualProtectEx, WriteProcessMemory, NtCreateSection, NtMapViewOfSection

Code execution:
CreateRemoteThread, QueueUserAPC, NtCreateThreadEx, NtQueueApcThread

Additional:
OpenProcess, ResumeThread, WaitForSingleObject, InitializeProcThreadAttributeList, UpdateProcThreadAttribute, DeleteProcThreadAttributeList

It is possible to mix the memory alloc and code execution techniques to achieve different injections, 
its also possible to spoof the parent process ID of the sacrifical process spawned trough UpdateProcThreadAttribute
and/or to block the loading of non microsoft signed DLLs, this can be useful to prevent EDR DLLs from being loaded in the sacrifical process.
For additional explanations and examples the help menu can be used.

TODO:
1. Enumerate threads of an existing process and queue the APC on one of them, after this is done force it into alerted state.
2. Possibly make use of encrypted shellcode 
3. Better error handling
4. Add self injection capability 
