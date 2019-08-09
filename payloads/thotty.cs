using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Input;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace thotpatrol
{
    class Program
    {
        [DllImport("user32.dll")] public static extern int GetAsyncKeyState(Int32 i);

        static void Main(string[] args)
        {
            while (true)
            {
                Thread.Sleep(200);
                for (int i = 0; i < 255; i++)
                {

                    int keystate = GetAsyncKeyState(i);


                    if (keystate != 0)
                    {
                        MessageBoxButtons buttons = MessageBoxButtons.YesNo;
                        MessageBox.Show("BEGONE THOTTY NONCE", "THOT", buttons);
                        
                    }
                }

            }

        }
    }
}
