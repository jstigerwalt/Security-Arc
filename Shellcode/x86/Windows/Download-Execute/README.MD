Download & Execute Windows x86 Shellcode uses PEB style of DLL loading and API Function calls. 

Other shellcode will be uploaded to show the uses of hard coded addressing that can be useful in certain enviroments of known OS/Service
packs. This will allow for smaller shellcode and direct access to already pre-loaded DLL's. LoadAddress and GetProcAddress will have to be
used in all Windwos shellcode. There is no way to be certain that "urlmon.dll" will be loaded with any PEB executable. There is a 5% chance 
you will ever find a program using this DLL in a enterprise executable. 

This is my personal opinion and beliefs, others may have been lucky and may not have to find the API functions using various methods.

