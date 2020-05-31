using System;

public class Class1
{
	public Class1()
	{
	}
}


//启动Task程序
ApplicationLoader.PROCESS_INFORMATION procInfo;
ApplicationLoader.StartProcessAndBypassUAC(applicationName, out procInfo);


using System;
using System.Collections.Generic;
using System.Text;
using System.Security;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace WS_Monitor_Task_CSharp
{


    /// <summary>
    /// Class that allows running applications with full admin rights. In
    /// addition the application launched will bypass the Vista UAC prompt.
    /// </summary>
    public class ApplicationLoader
    {


        #region Structrures

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int Length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
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


        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        #endregion


        #region Enumberation
        enum TOKEN_TYPE : int
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }

        enum SECURITY_IMPERSONATION_LEVEL : int
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }

        #endregion




        #region Constants

        public const int TOKEN_DUPLICATE = 0x0002;
        public const uint MAXIMUM_ALLOWED = 0x2000000;
        public const int CREATE_NEW_CONSOLE = 0x00000010;

        public const int IDLE_PRIORITY_CLASS = 0x40;
        public const int NORMAL_PRIORITY_CLASS = 0x20;
        public const int HIGH_PRIORITY_CLASS = 0x80;
        public const int REALTIME_PRIORITY_CLASS = 0x100;

        #endregion



        #region Win32 API Imports

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);

        [DllImport("kernel32.dll")]
        static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
           ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,
          String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        static extern bool ProcessIdToSessionId(uint dwProcessId, ref uint pSessionId);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpThreadAttributes, int TokenType,
             int ImpersonationLevel, ref IntPtr DuplicateTokenHandle);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("advapi32", SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, ref IntPtr TokenHandle);

        #endregion




        /// <summary>
        /// Launches the given application with full admin rights, and in addition bypasses the Vista UAC prompt
        /// </summary>
        /// <param name="applicationName">The name of the application to launch</param>
        /// <param name="procInfo">Process information regarding the launched application that gets returned to the caller</param>
        /// <returns></returns>
        public static bool StartProcessAndBypassUAC(String applicationName, out PROCESS_INFORMATION procInfo)
        {
            uint winlogonPid = 0;
            IntPtr hUserTokenDup = IntPtr.Zero,
                hPToken = IntPtr.Zero,
                hProcess = IntPtr.Zero;
            procInfo = new PROCESS_INFORMATION();

            // obtain the currently active session id; every logged on user in the system has a unique session id
            TSControl.WTS_SESSION_INFO[] pSessionInfo = TSControl.SessionEnumeration();
            uint dwSessionId = 100;
            for (int i = 0; i < pSessionInfo.Length; i++)
            {
                if (pSessionInfo[i].SessionID != 0)
                {
                    try
                    {
                        int count = 0;
                        IntPtr buffer = IntPtr.Zero;
                        StringBuilder sb = new StringBuilder();

                        bool bsuccess = TSControl.WTSQuerySessionInformation(
                           IntPtr.Zero, pSessionInfo[i].SessionID,
                           TSControl.WTSInfoClass.WTSUserName, out sb, out count);

                        if (bsuccess)
                        {
                            if (sb.ToString().Trim() == "dmpadmin")
                            {
                                dwSessionId = (uint)pSessionInfo[i].SessionID;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        LoaderService.WriteLog(ex.Message.ToString(), "Monitor");
                    }
                }
            }


            // obtain the process id of the winlogon process that is running within the currently active session
            Process[] processes = Process.GetProcessesByName("explorer");
            foreach (Process p in processes)
            {
                if ((uint)p.SessionId == dwSessionId)
                {
                    winlogonPid = (uint)p.Id;
                }
            }

            LoaderService.WriteLog(winlogonPid.ToString(), "Monitor");

            // obtain a handle to the winlogon process
            hProcess = OpenProcess(MAXIMUM_ALLOWED, false, winlogonPid);

            // obtain a handle to the access token of the winlogon process
            if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, ref hPToken))
            {
                CloseHandle(hProcess);
                return false;
            }

            // Security attibute structure used in DuplicateTokenEx and CreateProcessAsUser
            // I would prefer to not have to use a security attribute variable and to just 
            // simply pass null and inherit (by default) the security attributes
            // of the existing token. However, in C# structures are value types and therefore
            // cannot be assigned the null value.
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            sa.Length = Marshal.SizeOf(sa);

            // copy the access token of the winlogon process; the newly created token will be a primary token
            if (!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, ref sa, (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, (int)TOKEN_TYPE.TokenPrimary, ref hUserTokenDup))
            {
                CloseHandle(hProcess);
                CloseHandle(hPToken);
                return false;
            }

            // By default CreateProcessAsUser creates a process on a non-interactive window station, meaning
            // the window station has a desktop that is invisible and the process is incapable of receiving
            // user input. To remedy this we set the lpDesktop parameter to indicate we want to enable user 
            // interaction with the new process.
            STARTUPINFO si = new STARTUPINFO();
            si.cb = (int)Marshal.SizeOf(si);
            si.lpDesktop = @"winsta0\default"; // interactive window station parameter; basically this indicates that the process created can display a GUI on the desktop

            // flags that specify the priority and creation method of the process
            int dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;

            // create a new process in the current user's logon session
            bool result = CreateProcessAsUser(hUserTokenDup,        // client's access token
                                            null,                   // file to execute
                                            applicationName,        // command line
                                             ref sa,                 // pointer to process SECURITY_ATTRIBUTES
                                             ref sa,                 // pointer to thread SECURITY_ATTRIBUTES
                                             false,                  // handles are not inheritable
                                             dwCreationFlags,        // creation flags
                                             IntPtr.Zero,            // pointer to new environment block 
                                             null,                   // name of current directory 
                                             ref si,                 // pointer to STARTUPINFO structure
                                             out procInfo            // receives information about new process
                                             );

            // invalidate the handles
            CloseHandle(hProcess);
            CloseHandle(hPToken);
            CloseHandle(hUserTokenDup);
            LoaderService.WriteLog("launch Task", "Monitor");

            return result; // return the result
        }

    }
}



using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace WS_Monitor_Task_CSharp
{
    public class TSControl
    {
        /**/
        /// <summary> 
        /// Terminal Services API Functions,The WTSEnumerateSessions function retrieves a list of sessions on a specified terminal server, 
        /// </summary> 
        /// <param name="hServer">[in] Handle to a terminal server. Specify a handle opened by the WTSOpenServer function, or specify WTS_CURRENT_SERVER_HANDLE to indicate the terminal server on which your application is running</param> 
        /// <param name="Reserved">Reserved; must be zero</param> 
        /// <param name="Version">[in] Specifies the version of the enumeration request. Must be 1. </param> 
        /// <param name="ppSessionInfo">[out] Pointer to a variable that receives a pointer to an array of WTS_SESSION_INFO structures. Each structure in the array contains information about a session on the specified terminal server. To free the returned buffer, call the WTSFreeMemory function. 
        /// To be able to enumerate a session, you need to have the Query Information permission.</param> 
        /// <param name="pCount">[out] Pointer to the variable that receives the number of WTS_SESSION_INFO structures returned in the ppSessionInfo buffer. </param> 
        /// <returns>If the function succeeds, the return value is a nonzero value. If the function fails, the return value is zero</returns> 
        [DllImport("wtsapi32", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool WTSEnumerateSessions(int hServer, int Reserved, int Version, ref long ppSessionInfo, ref int pCount);

        /**/
        /// <summary> 
        /// Terminal Services API Functions,The WTSFreeMemory function frees memory allocated by a Terminal Services function. 
        /// </summary> 
        /// <param name="pMemory">[in] Pointer to the memory to free</param> 
        [DllImport("wtsapi32.dll")]
        public static extern void WTSFreeMemory(System.IntPtr pMemory);

        /**/
        /// <summary> 
        /// Terminal Services API Functions,The WTSLogoffSession function logs off a specified Terminal Services session. 
        /// </summary> 
        /// <param name="hServer">[in] Handle to a terminal server. Specify a handle opened by the WTSOpenServer function, or specify WTS_CURRENT_SERVER_HANDLE to indicate the terminal server on which your application is running. </param> 
        /// <param name="SessionId">[in] A Terminal Services session identifier. To indicate the current session, specify WTS_CURRENT_SESSION. You can use the WTSEnumerateSessions function to retrieve the identifiers of all sessions on a specified terminal server. 
        /// To be able to log off another user's session, you need to have the Reset permission </param> 
        /// <param name="bWait">[in] Indicates whether the operation is synchronous. 
        /// If bWait is TRUE, the function returns when the session is logged off. 
        /// If bWait is FALSE, the function returns immediately.</param> 
        /// <returns>If the function succeeds, the return value is a nonzero value. 
        /// If the function fails, the return value is zero.</returns> 
        [DllImport("wtsapi32.dll")]
        public static extern bool WTSLogoffSession(int hServer, long SessionId, bool bWait);


        [DllImport("Wtsapi32.dll")]
        public static extern bool WTSQuerySessionInformation(
            System.IntPtr hServer,
            int sessionId,
            WTSInfoClass wtsInfoClass,
            out StringBuilder ppBuffer,
            out int pBytesReturned
            );

        public enum WTSInfoClass
        {
            WTSInitialProgram,
            WTSApplicationName,
            WTSWorkingDirectory,
            WTSOEMId,
            WTSSessionId,
            WTSUserName,
            WTSWinStationName,
            WTSDomainName,
            WTSConnectState,
            WTSClientBuildNumber,
            WTSClientName,
            WTSClientDirectory,
            WTSClientProductId,
            WTSClientHardwareId,
            WTSClientAddress,
            WTSClientDisplay,
            WTSClientProtocolType
        }

        /**/
        /// <summary> 
        /// The WTS_CONNECTSTATE_CLASS enumeration type contains INT values that indicate the connection state of a Terminal Services session. 
        /// </summary> 
        public enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit,
        }


        /**/
        /// <summary> 
        /// The WTS_SESSION_INFO structure contains information about a client session on a terminal server. 
        /// if the WTS_SESSION_INFO.SessionID==0, it means that the SESSION is the local logon user's session. 
        /// </summary> 
        public struct WTS_SESSION_INFO
        {
            public int SessionID;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pWinStationName;
            public WTS_CONNECTSTATE_CLASS state;
        }

        /**/
        /// <summary> 
        /// The SessionEnumeration function retrieves a list of 
        ///WTS_SESSION_INFO on a current terminal server. 
        /// </summary> 
        /// <returns>a list of WTS_SESSION_INFO on a current terminal server</returns> 
        public static WTS_SESSION_INFO[] SessionEnumeration()
        {
            //Set handle of terminal server as the current terminal server 
            int hServer = 0;
            bool RetVal;
            long lpBuffer = 0;
            int Count = 0;
            long p;
            WTS_SESSION_INFO Session_Info = new WTS_SESSION_INFO();
            WTS_SESSION_INFO[] arrSessionInfo;
            RetVal = WTSEnumerateSessions(hServer, 0, 1, ref lpBuffer, ref Count);
            arrSessionInfo = new WTS_SESSION_INFO[0];
            if (RetVal)
            {
                arrSessionInfo = new WTS_SESSION_INFO[Count];
                int i;
                p = lpBuffer;
                for (i = 0; i < Count; i++)
                {
                    arrSessionInfo[i] =
                        (WTS_SESSION_INFO)Marshal.PtrToStructure(new IntPtr(p),
                        Session_Info.GetType());
                    p += Marshal.SizeOf(Session_Info.GetType());
                }
                WTSFreeMemory(new IntPtr(lpBuffer));
            }
            else
            {
                //Insert Error Reaction Here 
            }
            return arrSessionInfo;
        }

        public TSControl()
        {
            // 
            // TODO: 在此处添加构造函数逻辑 
            // 

        }


    }
}
