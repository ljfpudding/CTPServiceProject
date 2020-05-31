// CTPWinService.cpp : 定义控制台应用程序的入口点。
//
//sc create "My Sample Service" binPath= C:\SampleService.exe
//sc delete "My Sample Service"
//=====================================================

#include "stdafx.h"
#include "WtsApi32.h"
#include "UserEnv.h"

#include <string>
#include <vector>
#include<iostream>
#include "conio.h"
#include "tlhelp32.h"


using namespace std;

#pragma comment(lib, "Wtsapi32.Lib")
#pragma comment(lib, "Userenv.Lib")


SERVICE_STATUS        g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

PROCESS_INFORMATION   g_processInfo;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler(DWORD);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

#define SERVICE_NAME  _T("CTP Control Service")



VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
	DWORD Status = E_FAIL;

	OutputDebugString(_T("CTP Control Service: ServiceMain: Entry"));

	g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);

	if (g_StatusHandle == NULL)
	{
		OutputDebugString(_T("CTP Control Service: ServiceMain: RegisterServiceCtrlHandler returned error"));
		goto EXIT;
	}

	// Tell the service controller we are starting
	ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
	g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	g_ServiceStatus.dwControlsAccepted = 0;
	g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	g_ServiceStatus.dwWin32ExitCode = 0;
	g_ServiceStatus.dwServiceSpecificExitCode = 0;
	g_ServiceStatus.dwCheckPoint = 0;

	if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
	{
		OutputDebugString(_T("CTP Control Service: ServiceMain: SetServiceStatus returned error"));
	}

	/*
	* Perform tasks neccesary to start the service here
	*/
	OutputDebugString(_T("CTP Control Service: ServiceMain: Performing Service Start Operations"));

	// Create stop event to wait on later.
	g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (g_ServiceStopEvent == NULL)
	{
		OutputDebugString(_T("CTP Control Service: ServiceMain: CreateEvent(g_ServiceStopEvent) returned error"));

		g_ServiceStatus.dwControlsAccepted = 0;
		g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		g_ServiceStatus.dwWin32ExitCode = GetLastError();
		g_ServiceStatus.dwCheckPoint = 1;

		if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
		{
			OutputDebugString(_T("CTP Control Service: ServiceMain: SetServiceStatus returned error"));
		}
		goto EXIT;
	}

	// Tell the service controller we are started
	g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	g_ServiceStatus.dwWin32ExitCode = 0;
	g_ServiceStatus.dwCheckPoint = 0;

	if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
	{
		OutputDebugString(_T("CTP Control Service: ServiceMain: SetServiceStatus returned error"));
	}

	// Start the thread that will perform the main task of the service
	HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);

	OutputDebugString(_T("CTP Control Service: ServiceMain: Waiting for Worker Thread to complete"));

	// Wait until our worker thread exits effectively signaling that the service needs to stop
	Sleep(60 * 60 * 1000);
	WaitForSingleObject(hThread, INFINITE);

	OutputDebugString(_T("CTP Control Service: ServiceMain: Worker Thread Stop Event signaled"));


	/*
	* Perform any cleanup tasks
	*/
	OutputDebugString(_T("CTP Control Service: ServiceMain: Performing Cleanup Operations"));

	CloseHandle(g_ServiceStopEvent);

	g_ServiceStatus.dwControlsAccepted = 0;
	g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	g_ServiceStatus.dwWin32ExitCode = 0;
	g_ServiceStatus.dwCheckPoint = 3;

	if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
	{
		OutputDebugString(_T("CTP Control Service: ServiceMain: SetServiceStatus returned error"));
	}

EXIT:
	OutputDebugString(_T("CTP Control Service: ServiceMain: Exit"));

	return;
}

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode)
{
	OutputDebugString(_T("CTP Control Service: ServiceCtrlHandler: Entry"));

	switch (CtrlCode)
	{
	case SERVICE_CONTROL_STOP:

		OutputDebugString(_T("CTP Control Service: ServiceCtrlHandler: SERVICE_CONTROL_STOP Request"));

		if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
			break;

		/*
		* Perform tasks neccesary to stop the service here
		*/

		g_ServiceStatus.dwControlsAccepted = 0;
		g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		g_ServiceStatus.dwWin32ExitCode = 0;
		g_ServiceStatus.dwCheckPoint = 4;

		if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
		{
			OutputDebugString(_T("CTP Control Service: ServiceCtrlHandler: SetServiceStatus returned error"));
		}

		// This will signal the worker thread to start shutting down
		SetEvent(g_ServiceStopEvent);

		break;

	default:
		break;
	}

	OutputDebugString(_T("CTP Control Service: ServiceCtrlHandler: Exit"));
}

HANDLE GetCurrentUserToken()
{
	PWTS_SESSION_INFO pSessionInfo = 0;
	DWORD dwCount = 0;
	::WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &dwCount);
	int session_id = 0;
	for (DWORD i = 0; i < dwCount; ++i)
	{
		WTS_SESSION_INFO si = pSessionInfo[i];
		if (WTSActive == si.State)
		{
			session_id = si.SessionId;
			break;
		}
	}
	::WTSFreeMemory(pSessionInfo);
	HANDLE current_token = 0;
	BOOL bRet = ::WTSQueryUserToken(session_id, &current_token);
	int errorcode = GetLastError();
	if (bRet == false)
	{
		return 0;
	}
	HANDLE primaryToken = 0;
	bRet = ::DuplicateTokenEx(current_token, TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS, 0, SecurityImpersonation, TokenPrimary, &primaryToken);
	errorcode = GetLastError();
	if (bRet == false)
	{
		return 0;
	}
	return primaryToken;
}

BOOL StartCTPController(std::wstring processPath_)
{
	HANDLE primaryToken = GetCurrentUserToken();
	if (primaryToken == 0)
	{
		return FALSE;
	}
	STARTUPINFO StartupInfo = { 0 };

	StartupInfo.cb = sizeof(STARTUPINFO);

	SECURITY_ATTRIBUTES Security1;
	SECURITY_ATTRIBUTES Security2;

	std::wstring command = L"\"" + processPath_ + L"\"";
	//if (arguments_.length() != 0)
	//{
	//	command += L" " + arguments_;
	//}
	void* lpEnvironment = NULL;
	BOOL resultEnv = ::CreateEnvironmentBlock(&lpEnvironment, primaryToken, FALSE);
	if (resultEnv == 0)
	{
		long nError = GetLastError();
	}
	BOOL result = ::CreateProcessAsUser(primaryToken, 0, (LPWSTR)(command.c_str()), NULL, NULL, FALSE, CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT, NULL, 0, &StartupInfo, &g_processInfo);
	
	
	::DestroyEnvironmentBlock(lpEnvironment);
	::CloseHandle(primaryToken);
	return result;
}

 void SessionEnumeration(vector<WTS_SESSION_INFO> &vc)
{
	HANDLE hServer = NULL;
	PWTS_SESSION_INFO pSessionInfo = 0;
	DWORD dwCount = 0;
	WTS_SESSION_INFO Session_Info;
	//vector<WTS_SESSION_INFO> arrSessionInfo;
	BOOL RetVal = ::WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &dwCount);
	if (RetVal)
	{
		for (int i = 0; i < (int)dwCount; i++)
		{
			vc.push_back(pSessionInfo[i]);
		}
	}
	else
	{
		//Insert Error Reaction Here 
	}

}

//=============================================================================================================

#define SafeDeleteArraySize(pData) { if(pData){delete []pData;pData=NULL;} }

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)

#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)

typedef LONG KPRIORITY;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

//进程结构
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

//系统信息类
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,						//系统的基本信息
	SystemProcessorInformation,             // obsolete...delete
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,						//系统进程信息
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,					//系统模块信息
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

wchar_t* GetProcessIdName(HANDLE ProcessId)
{
	//定义变量
	NTSTATUS status;
	ULONG NeededSize;
	PVOID pBuffer = NULL;
	wchar_t* pProcessName = NULL;
	PSYSTEM_PROCESS_INFORMATION pInfo;
	typedef NTSTATUS(__stdcall  *fnZwQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	static fnZwQuerySystemInformation pZwQuerySystemInformation = (fnZwQuerySystemInformation)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "ZwQuerySystemInformation");

	do
	{
		status = pZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &NeededSize);
		if (status != STATUS_INFO_LENGTH_MISMATCH || NeededSize <= 0)break;

		NeededSize *= 2;
		pBuffer = new BYTE[NeededSize];
		if (pBuffer == NULL)break;

		RtlZeroMemory(pBuffer, NeededSize);
		status = pZwQuerySystemInformation(SystemProcessInformation, pBuffer, NeededSize, NULL);
		if (!NT_SUCCESS(status))break;
		pInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;

		do
		{
			if (pInfo == NULL)break;
			if (pInfo->NextEntryOffset == 0)break;
			pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo) + pInfo->NextEntryOffset);


			if (ProcessId == pInfo->UniqueProcessId)
			{
				pProcessName = (wchar_t*)new BYTE[pInfo->ImageName.Length + sizeof(wchar_t)];
				ZeroMemory(pProcessName, pInfo->ImageName.Length + sizeof(wchar_t));
				CopyMemory(pProcessName, pInfo->ImageName.Buffer, pInfo->ImageName.Length);
				break;
			}


		} while (TRUE);



	} while (FALSE);

	SafeDeleteArraySize(pBuffer);
	return pProcessName;
}

void GetSpecifyProcess(std::wstring strProcessName, vector<SYSTEM_PROCESS_INFORMATION> &vc)
{
	//定义变量

	
	NTSTATUS status;
	ULONG NeededSize;
	PVOID pBuffer = NULL;
	wchar_t* pProcessName = NULL;
	PSYSTEM_PROCESS_INFORMATION pInfo;
	typedef NTSTATUS(__stdcall  *fnZwQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	static fnZwQuerySystemInformation pZwQuerySystemInformation = (fnZwQuerySystemInformation)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "ZwQuerySystemInformation");

	do
	{
		status = pZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &NeededSize);
		if (status != STATUS_INFO_LENGTH_MISMATCH || NeededSize <= 0)break;

		NeededSize *= 2;
		pBuffer = new BYTE[NeededSize];
		if (pBuffer == NULL)break;

		RtlZeroMemory(pBuffer, NeededSize);
		status = pZwQuerySystemInformation(SystemProcessInformation, pBuffer, NeededSize, NULL);
		if (!NT_SUCCESS(status))break;
		pInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;

		do
		{
			if (pInfo == NULL)break;
			if (pInfo->NextEntryOffset == 0)break;
			pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo) + pInfo->NextEntryOffset);


			//if (ProcessId == pInfo->UniqueProcessId)
			//{
			pProcessName = (wchar_t*)new BYTE[pInfo->ImageName.Length + sizeof(wchar_t)];
			ZeroMemory(pProcessName, pInfo->ImageName.Length + sizeof(wchar_t));
			CopyMemory(pProcessName, pInfo->ImageName.Buffer, pInfo->ImageName.Length);

			wstring str = wstring(pProcessName);
			if (str == strProcessName)
			{
				vc.push_back(*pInfo);
			}

		} while (TRUE);

	} while (FALSE);

	SafeDeleteArraySize(pBuffer);
}

BOOL StartProcessAndBypassUAC(wstring processPath_, PROCESS_INFORMATION &procInfo)
{

	DWORD winlogonPid = 0;
	//IntPtr hUserTokenDup = IntPtr.Zero,
		//hPToken = IntPtr.Zero,
		//hProcess = IntPtr.Zero;
	//procInfo = new PROCESS_INFORMATION();
	//TSControl.WTS_SESSION_INFO[] pSessionInfo = TSControl.SessionEnumeration();

	vector<WTS_SESSION_INFO> pSessionInfo;
	SessionEnumeration(pSessionInfo);


	DWORD dwSessionId = 100;
	for (int i = 0; i < pSessionInfo.size(); i++)
	{
		if (pSessionInfo[i].SessionId != 0)
		{
			try
			{
				//int count = 0;
				//IntPtr buffer = IntPtr.Zero;
				//StringBuilder sb = new StringBuilder();
				
				PVOID pstr = NULL;
				DWORD dwLen = 0;
				BOOL bsuccess = ::WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, pSessionInfo[i].SessionId, WTS_INFO_CLASS::WTSUserName, (LPWSTR*)&pstr, &dwLen);
				wstring sb = (PWCHAR)pstr;

				//= TSControl.WTSQuerySessionInformation(
					//IntPtr.Zero, pSessionInfo[i].SessionID,
					//TSControl.WTSInfoClass.WTSUserName, out sb, out count);

				{
					DWORD dwSessionId = ::WTSGetActiveConsoleSessionId();
					PVOID pstr = NULL;
					DWORD dwLen = 0;
					::WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, dwSessionId, WTS_INFO_CLASS::WTSUserName, (LPWSTR*)&pstr, &dwLen);
					wstring strUserName = (PWCHAR)pstr;
				}



				std::wcout << sb.c_str() << std::endl;
				_getch();

				if (bsuccess)
				{
					if (sb == L"aaa")
					{
						dwSessionId = pSessionInfo[i].SessionId;
						std::cout << "sb == L username" << std::endl;
						_getch();
					}
				}
			}
			catch (...)
			{
				//LoaderService.WriteLog(ex.Message.ToString(), "Monitor");
			}
		}
	}

	//Process[] processes = Process.GetProcessesByName("explorer");

	vector<SYSTEM_PROCESS_INFORMATION> vcProcess;
	GetSpecifyProcess(wstring(L"notepad.exe"), vcProcess);
//=========================================================================
	{

		//////////////////////////////////////////
		// Find the winlogon process
		////////////////////////////////////////

		PROCESSENTRY32 procEntry;  //用来存放快照进程信息的一个结构体
								   //函数为指定的进程、进程使用的堆[HEAP]、模块[MODULE]、线程[THREAD]）建立一个快照[snapshot]
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap == INVALID_HANDLE_VALUE)
		{
			return 1;
		}

		procEntry.dwSize = sizeof(PROCESSENTRY32);

		if (!Process32First(hSnap, &procEntry)) //获得第一个进程的句柄.
		{
			return 1;
		}

		do
		{
			if (_wcsicmp(procEntry.szExeFile, _T("explorer.exe")) == 0)  //查找winlogon.exe
			{
				// We found a winlogon process...make sure it's running in the console session
				DWORD winlogonSessId = 0;
				if (ProcessIdToSessionId(procEntry.th32ProcessID, &winlogonSessId) && winlogonSessId == dwSessionId)//得到与进程ID对应的终端服务会话ID
				{
					winlogonPid = procEntry.th32ProcessID;
					break;
				}
				//winlogonPid = procEntry.th32ParentProcessID;
			}

		} while (Process32Next(hSnap, &procEntry)); //获得下一个进程的句柄


	}





//===============================================================	
	HANDLE hwinlogon = NULL;

	//for (int i = 0; i < vcProcess.size(); i++)
	//{
	//	if (dwSessionId == vcProcess[i].SessionId)
	//	{
	//		hwinlogon = vcProcess[i].UniqueProcessId;
			//winlogonPid = ::GetProcessId(hwinlogon);
			//break;
	//	}
	//}

	HANDLE hPToken = NULL;

	HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, false, winlogonPid);

	BOOL fOk = FALSE;
	if (::OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hPToken))
	{

		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		::LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);

		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		::AdjustTokenPrivileges(hPToken, FALSE, &tp, sizeof(tp), NULL, NULL);

		fOk = (GetLastError() == ERROR_SUCCESS);
		//CloseHandle(hPToken);

	}



	if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hPToken))
	{
		CloseHandle(hwinlogon);
		return false;
	}


	SECURITY_ATTRIBUTES sa;
	HANDLE primaryToken = 0;
	if (!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, &sa, SecurityIdentification, TokenPrimary, &primaryToken))
	{
		CloseHandle(hwinlogon);
		CloseHandle(hPToken);
		return false;
	}

	STARTUPINFO si;
	si.cb = sizeof(STARTUPINFO);
	si.lpDesktop = LPWSTR("winsta0\default");  // interactive window station parameter; basically this indicates that the process created can display a GUI on the desktop

	int dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;

	//::CreateProcessAsUser(primaryToken, 
	//0, 
	//(LPWSTR)(command.c_str()), 
	//NULL, 
	//NULL, 
	//FALSE, 
	//CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT, NULL, 0, &StartupInfo, &g_processInfo);

	wstring command = L"\"" + processPath_ + L"\"";

	//PROCESS_INFORMATION procInfo;


	BOOL result = CreateProcessAsUser(primaryToken,        // client's access token
		0,                   // file to execute
		(LPWSTR)(command.c_str()),        // command line
		&sa,                 // pointer to process SECURITY_ATTRIBUTES
		&sa,                 // pointer to thread SECURITY_ATTRIBUTES
		FALSE,                  // handles are not inheritable
		dwCreationFlags,        // creation flags
		NULL,            // pointer to new environment block 
		0,                   // name of current directory 
		&si,                 // pointer to STARTUPINFO structure
		&procInfo            // receives information about new process
	);

	// invalidate the handles
	CloseHandle(hwinlogon);
	CloseHandle(hPToken);
	CloseHandle(primaryToken);

}
//===========================================================================================================

// 突破SESSION 0隔离创建用户进程
BOOL CreateUserProcess(wstring strPath)
{
	BOOL bRet = TRUE;
	DWORD dwSessionID = 0;
	HANDLE hToken = NULL;
	HANDLE hDuplicatedToken = NULL;
	LPVOID lpEnvironment = NULL;
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);
	do
	{
		// 获得当前Session ID
		dwSessionID = ::WTSGetActiveConsoleSessionId();
		// 获得当前Session的用户令牌
		if (FALSE == ::WTSQueryUserToken(dwSessionID, &hToken))
		{
			//ShowMessage("WTSQueryUserToken", "ERROR");
			bRet = FALSE;
			break;
		}
		// 复制令牌
		if (FALSE == ::DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
			SecurityIdentification, TokenPrimary, &hDuplicatedToken))
		{
			//ShowMessage("DuplicateTokenEx", "ERROR");
			bRet = FALSE;
			break;
		}
		// 创建用户Session环境
		if (FALSE == ::CreateEnvironmentBlock(&lpEnvironment,
			hDuplicatedToken, FALSE))
		{
			//ShowMessage("CreateEnvironmentBlock", "ERROR");
			bRet = FALSE;
			break;
		}
		// 在复制的用户Session下执行应用程序，创建进程
		if (FALSE == ::CreateProcessAsUser(hDuplicatedToken,
			(LPCTSTR)strPath.c_str(), NULL, NULL, NULL, FALSE,
			NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
			lpEnvironment, NULL, &si, &pi))
		{
			//ShowMessage("CreateProcessAsUser", "ERROR");
			bRet = FALSE;
			break;
		}
	} while (FALSE);
	// 关闭句柄, 释放资源
	if (lpEnvironment)
	{
		::DestroyEnvironmentBlock(lpEnvironment);
	}
	if (hDuplicatedToken)
	{
		::CloseHandle(hDuplicatedToken);
	}
	if (hToken)
	{
		::CloseHandle(hToken);
	}
	return bRet;
}

//===========================================================================================================

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam)
{
	OutputDebugString(_T("CTP Control Service: ServiceWorkerThread: Entry"));

	memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));

	//  Periodically check if the service has been requested to stop
	while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0)
	{
		/*
		* Perform main service function here
		*/

		// Simulate some work by sleeping


		time_t nowtime;
		nowtime = time(NULL); //获取日历时间  		
		struct tm local;
		localtime_s(&local,&nowtime);  //获取当前系统时间  

		switch (local.tm_hour)
		{
		case 8:

			break;

		case 15:
			if (local.tm_min == 10)
			{
				if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
				{
					std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
					StartCTPController(strApp);
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			

			if (local.tm_min == 21)
			{
				if (g_processInfo.hThread != NULL && g_processInfo.hProcess != NULL)
				{
					DWORD dwEC = 0;
					TerminateProcess(g_processInfo.hProcess, dwEC);					
					// Close process and thread handles. 
					CloseHandle(g_processInfo.hProcess);
					CloseHandle(g_processInfo.hThread);
					memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟			
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			if (local.tm_min == 32)
			{
				if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
				{
					std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
					StartCTPController(strApp);
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			if (local.tm_min == 43)
			{
				if (g_processInfo.hThread != NULL && g_processInfo.hProcess != NULL)
				{
					DWORD dwEC = 0;
					TerminateProcess(g_processInfo.hProcess, dwEC);
					// Close process and thread handles. 
					CloseHandle(g_processInfo.hProcess);
					CloseHandle(g_processInfo.hThread);
					memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟			
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			break;

		case 11:

			if (local.tm_min == 45)
			{
				if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
				{
					std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
					StartCTPController(strApp);
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			if (local.tm_min == 56)
			{
				if (g_processInfo.hThread != NULL && g_processInfo.hProcess != NULL)
				{
					DWORD dwEC = 0;
					TerminateProcess(g_processInfo.hProcess, dwEC);
					// Close process and thread handles. 
					CloseHandle(g_processInfo.hProcess);
					CloseHandle(g_processInfo.hThread);
					memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟			
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			break;
	

		case 2:
			break;
		case 16:

			if (local.tm_min == 5)
			{
				if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
				{
					std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
					StartCTPController(strApp);
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			if (local.tm_min == 30)
			{
				if (g_processInfo.hThread != NULL && g_processInfo.hProcess != NULL)
				{
					DWORD dwEC = 0;
					TerminateProcess(g_processInfo.hProcess, dwEC);
					// Close process and thread handles. 
					CloseHandle(g_processInfo.hProcess);
					CloseHandle(g_processInfo.hThread);
					memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟			
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			break;
		case 20:

			if (local.tm_min == 50)
			{
				if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
				{
					std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
					StartCTPController(strApp);
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 3;//3分钟
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			if (local.tm_min == 56)
			{
				if (g_processInfo.hThread != NULL && g_processInfo.hProcess != NULL)
				{
					DWORD dwEC = 0;
					TerminateProcess(g_processInfo.hProcess, dwEC);
					// Close process and thread handles. 
					CloseHandle(g_processInfo.hProcess);
					CloseHandle(g_processInfo.hThread);
					memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟			
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			break;

		default:
			break;
		}



		/*if((local.tm_hour == 8 && local.tm_min == 56)  )
		{

			if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
			{
				std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
				StartCTPController(strApp);
				unsigned long ulInterval = 1000; //1秒
				ulInterval = ulInterval * 60 * 60;//1小时
				//ulInterval = ulInterval * 6; //6小时
				//ulInterval = ulInterval + 1000 * 60 * 10;//6小时+10分钟;
				WaitForSingleObject(g_ServiceStopEvent, ulInterval);
			}

		}
		else if ((local.tm_hour == 20 && local.tm_min == 56))
		{
			if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
			{
				std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
				StartCTPController(strApp);
				unsigned long ulInterval = 1000; //1秒
				ulInterval = ulInterval * 60 * 60;//1小时
				//ulInterval = ulInterval * 5; //5小时
				//ulInterval = ulInterval + 1000 * 60 * 40;//5小时+30 +10分钟;
				WaitForSingleObject(g_ServiceStopEvent, ulInterval);
			}
		}
		else if ((local.tm_hour == 13 && local.tm_min == 26))
		{
			std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
			StartCTPController(strApp);
			unsigned long ulInterval = 1000; //1秒
			ulInterval = ulInterval * 60 * 60;//1小时
			WaitForSingleObject(g_ServiceStopEvent, ulInterval);
		}
		else
		{
			if ((local.tm_hour == 15 && local.tm_min == 28)) //15:28关闭， 等到晚上20:56分开启 
			{

				if (g_processInfo.hThread != NULL && g_processInfo.hProcess != NULL)
				{
					DWORD dwEC = 0;
					BOOL b = GetExitCodeProcess(
						g_processInfo.hProcess,     // handle to the process
						&dwEC              // termination status
					);

					//if (b)
					{
						TerminateProcess(g_processInfo.hProcess, dwEC);
					}
					// Close process and thread handles. 
					CloseHandle(g_processInfo.hProcess);
					CloseHandle(g_processInfo.hThread);
					memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));

					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 60;//1小时
					ulInterval = ulInterval * 5; //5小时
												 //ulInterval = ulInterval - 1000 * 60 * 15;//5小时+15分钟;				
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}				
			 }
			else if((local.tm_hour == 2 && local.tm_min == 55))
			{
				if (g_processInfo.hThread != NULL && g_processInfo.hProcess != NULL)
				{
					DWORD dwEC = 0;
					BOOL b = GetExitCodeProcess(
						g_processInfo.hProcess,     // handle to the process
						&dwEC              // termination status
					);

					//if (b)
					{
						TerminateProcess(g_processInfo.hProcess, dwEC);
					}
					// Close process and thread handles. 
					CloseHandle(g_processInfo.hProcess);
					CloseHandle(g_processInfo.hThread);
					memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));

					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 60;//1小时
					ulInterval = ulInterval * 5; //5小时
												 //ulInterval = ulInterval + 1000 * 60 * 45;//5小时+30+15分钟;				
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}
		}

		*/

		//test several times

		/*if ((local.tm_hour == 21 && (local.tm_min == 5 || local.tm_min == 10 || local.tm_min == 15)))
		{

			if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
			{
				std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
				StartCTPController(strApp);
				unsigned long ulInterval = 1000; //1秒
				ulInterval = ulInterval * 60 * 2;
				WaitForSingleObject(g_ServiceStopEvent, ulInterval);
			}
		}
		else if ((local.tm_hour == 21 && (local.tm_min == 8 || local.tm_min == 13 || local.tm_min == 18)))
		{

			DWORD dwEC = 0;
			BOOL b = GetExitCodeProcess(
				g_processInfo.hProcess,     // handle to the process
				&dwEC              // termination status
			);

			//if (b)
			{
				TerminateProcess(g_processInfo.hProcess, dwEC);
			}
			// Close process and thread handles. 
			CloseHandle(g_processInfo.hProcess);
			CloseHandle(g_processInfo.hThread);
			memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));

			unsigned long ulInterval = 1000; //1秒
			ulInterval = ulInterval * 60 * 2;
			WaitForSingleObject(g_ServiceStopEvent, ulInterval);

		}*/

	}
	OutputDebugString(_T("CTP Control Service: ServiceWorkerThread: Exit"));

	return ERROR_SUCCESS;
}


/*
DWORD INTER_GetExplorerToken(PHANDLE phExplorerToken)
{
	DWORD       dwStatus = ERROR_FILE_NOT_FOUND;
	BOOL        bRet = FALSE;
	HANDLE      hProcess = NULL;
	HANDLE      hProcessSnap = NULL;
	char        szExplorerPath[MAX_PATH] = { 0 };
	char        FileName[MAX_PATH] = { 0 };
	PROCESSENTRY32 pe32 = { 0 };

	try
	{
		hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE)
		{
			dwStatus = GetLastError();
		}
		else
		{
			pe32.dwSize = sizeof(PROCESSENTRY32);
			int bMore = ::Process32First(hProcessSnap, &pe32);
			while (bMore)
			{
				if (::wcscmp(pe32.szExeFile, _T("explorer.exe")) == 0)
				{
					hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
					if (OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, phExplorerToken))
					{
						dwStatus = 0;
					}
					else
					{
						dwStatus = GetLastError();
					}
					break;
				}
				bMore = ::Process32Next(hProcessSnap, &pe32);
			}
		}
	}
	catch (...)
	{
	}

	if (hProcess)
	{
		CloseHandle(hProcess);
	}
	if (hProcessSnap)
	{
		CloseHandle(hProcessSnap);
	}

	return dwStatus;
}
*/

void ChangeSessionAndShowUI()
{
	HANDLE	hTokenThis = NULL;
	HANDLE	hTokenDup = NULL;
	HANDLE	hThisProcess = GetCurrentProcess();
	

	if (!OpenProcessToken(hThisProcess, TOKEN_ALL_ACCESS, &hTokenThis))
	{
		CloseHandle(hThisProcess);
		return ;
	}




	if (!DuplicateTokenEx(hTokenThis, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hTokenDup))
	{
		return;
	}





	DWORD	dwSessionId = WTSGetActiveConsoleSessionId();
	SetTokenInformation(hTokenDup, TokenSessionId, &dwSessionId, sizeof(DWORD));
	STARTUPINFO	si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);
	si.lpDesktop =(LPWSTR) "WinSta0//Default";
	LPVOID	pEnv = NULL;
	DWORD	dwCreationFlag = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
	CreateEnvironmentBlock(&pEnv, hTokenDup, FALSE);
	CreateProcessAsUser(
		hTokenDup,
		NULL,
		(LPWSTR)"notepad",
		NULL,
		NULL,
		FALSE,
		dwCreationFlag,
		pEnv,
		NULL,
		&si,
		&pi);

}

int _tmain(int argc, TCHAR *argv[])
{
	//OutputDebugString(_T("CTP Control Service: Main: Entry"));

	//SERVICE_TABLE_ENTRY ServiceTable[] =
	//{
	//	{ SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
	//	{ NULL, NULL }
	//};
	//

	//if (StartServiceCtrlDispatcher(ServiceTable) == FALSE)
	//{
	//	OutputDebugString(_T("CTP Control Service: Main: StartServiceCtrlDispatcher returned error"));
	//	return GetLastError();
	//}

	//OutputDebugString(_T("CTP Control Service: Main: Exit"));

	printf("_tmain start \n");

	memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));

	//  Periodically check if the service has been requested to stop
	while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0)
	{
		/*
		* Perform main service function here
		*/

		// Simulate some work by sleeping


		time_t nowtime;
		nowtime = time(NULL); //获取日历时间  		
		struct tm local;
		localtime_s(&local, &nowtime);  //获取当前系统时间  

		switch (local.tm_hour)
		{
		case 8:

			break;

		case 15:
			if (local.tm_min == 10)
			{
				if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
				{
					std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
					StartCTPController(strApp);
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}



			if (local.tm_min == 21)
			{
				if (g_processInfo.hThread != NULL && g_processInfo.hProcess != NULL)
				{
					DWORD dwEC = 0;
					TerminateProcess(g_processInfo.hProcess, dwEC);
					// Close process and thread handles. 
					CloseHandle(g_processInfo.hProcess);
					CloseHandle(g_processInfo.hThread);
					memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟			
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			if (local.tm_min == 32)
			{
				if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
				{
					std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
					StartCTPController(strApp);
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			if (local.tm_min == 43)
			{
				if (g_processInfo.hThread != NULL && g_processInfo.hProcess != NULL)
				{
					DWORD dwEC = 0;
					TerminateProcess(g_processInfo.hProcess, dwEC);
					// Close process and thread handles. 
					CloseHandle(g_processInfo.hProcess);
					CloseHandle(g_processInfo.hThread);
					memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟			
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			break;

		case 11:

			if (local.tm_min == 45)
			{
				if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
				{
					std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
					StartCTPController(strApp);
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			if (local.tm_min == 56)
			{
				if (g_processInfo.hThread != NULL && g_processInfo.hProcess != NULL)
				{
					DWORD dwEC = 0;
					TerminateProcess(g_processInfo.hProcess, dwEC);
					// Close process and thread handles. 
					CloseHandle(g_processInfo.hProcess);
					CloseHandle(g_processInfo.hThread);
					memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟			
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			break;


		case 2:
			break;
		case 16:

			if (local.tm_min == 5)
			{
				if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
				{
					std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
					StartCTPController(strApp);
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			if (local.tm_min == 30)
			{
				if (g_processInfo.hThread != NULL && g_processInfo.hProcess != NULL)
				{
					DWORD dwEC = 0;
					TerminateProcess(g_processInfo.hProcess, dwEC);
					// Close process and thread handles. 
					CloseHandle(g_processInfo.hProcess);
					CloseHandle(g_processInfo.hThread);
					memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 10;//10分钟			
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			break;
		case 21:

			if (local.tm_min == 45)
			{
				if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
				{
					std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
					StartCTPController(strApp);
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 3;//3分钟

					printf("local.tm_min == 45 StartCTPController \n");

					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			if (local.tm_min == 50)
			{
				if (g_processInfo.hThread != NULL && g_processInfo.hProcess != NULL)
				{
					DWORD dwEC = 0;
					TerminateProcess(g_processInfo.hProcess, dwEC);
					// Close process and thread handles. 
					CloseHandle(g_processInfo.hProcess);
					CloseHandle(g_processInfo.hThread);
					memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 3;//10分钟		

					printf("local.tm_min == 50 TerminateProcess \n");
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			if (local.tm_min == 55)
			{
				if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
				{
					std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
					StartCTPController(strApp);
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 3;//3分钟

					printf("local.tm_min == 55 StartCTPController \n");
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}

			if (local.tm_min == 59)
			{
				if (g_processInfo.hThread != NULL && g_processInfo.hProcess != NULL)
				{
					DWORD dwEC = 0;
					TerminateProcess(g_processInfo.hProcess, dwEC);
					// Close process and thread handles. 
					CloseHandle(g_processInfo.hProcess);
					CloseHandle(g_processInfo.hThread);
					memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));
					unsigned long ulInterval = 1000; //1秒
					ulInterval = ulInterval * 60 * 3;//10分钟	

					printf("local.tm_min == 59 TerminateProcess \n");
					WaitForSingleObject(g_ServiceStopEvent, ulInterval);
				}
			}


			break;

		default:
			break;
		}



		/*if((local.tm_hour == 8 && local.tm_min == 56)  )
		{

		if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
		{
		std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
		StartCTPController(strApp);
		unsigned long ulInterval = 1000; //1秒
		ulInterval = ulInterval * 60 * 60;//1小时
		//ulInterval = ulInterval * 6; //6小时
		//ulInterval = ulInterval + 1000 * 60 * 10;//6小时+10分钟;
		WaitForSingleObject(g_ServiceStopEvent, ulInterval);
		}

		}
		else if ((local.tm_hour == 20 && local.tm_min == 56))
		{
		if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
		{
		std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
		StartCTPController(strApp);
		unsigned long ulInterval = 1000; //1秒
		ulInterval = ulInterval * 60 * 60;//1小时
		//ulInterval = ulInterval * 5; //5小时
		//ulInterval = ulInterval + 1000 * 60 * 40;//5小时+30 +10分钟;
		WaitForSingleObject(g_ServiceStopEvent, ulInterval);
		}
		}
		else if ((local.tm_hour == 13 && local.tm_min == 26))
		{
		std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
		StartCTPController(strApp);
		unsigned long ulInterval = 1000; //1秒
		ulInterval = ulInterval * 60 * 60;//1小时
		WaitForSingleObject(g_ServiceStopEvent, ulInterval);
		}
		else
		{
		if ((local.tm_hour == 15 && local.tm_min == 28)) //15:28关闭， 等到晚上20:56分开启
		{

		if (g_processInfo.hThread != NULL && g_processInfo.hProcess != NULL)
		{
		DWORD dwEC = 0;
		BOOL b = GetExitCodeProcess(
		g_processInfo.hProcess,     // handle to the process
		&dwEC              // termination status
		);

		//if (b)
		{
		TerminateProcess(g_processInfo.hProcess, dwEC);
		}
		// Close process and thread handles.
		CloseHandle(g_processInfo.hProcess);
		CloseHandle(g_processInfo.hThread);
		memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));

		unsigned long ulInterval = 1000; //1秒
		ulInterval = ulInterval * 60 * 60;//1小时
		ulInterval = ulInterval * 5; //5小时
		//ulInterval = ulInterval - 1000 * 60 * 15;//5小时+15分钟;
		WaitForSingleObject(g_ServiceStopEvent, ulInterval);
		}
		}
		else if((local.tm_hour == 2 && local.tm_min == 55))
		{
		if (g_processInfo.hThread != NULL && g_processInfo.hProcess != NULL)
		{
		DWORD dwEC = 0;
		BOOL b = GetExitCodeProcess(
		g_processInfo.hProcess,     // handle to the process
		&dwEC              // termination status
		);

		//if (b)
		{
		TerminateProcess(g_processInfo.hProcess, dwEC);
		}
		// Close process and thread handles.
		CloseHandle(g_processInfo.hProcess);
		CloseHandle(g_processInfo.hThread);
		memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));

		unsigned long ulInterval = 1000; //1秒
		ulInterval = ulInterval * 60 * 60;//1小时
		ulInterval = ulInterval * 5; //5小时
		//ulInterval = ulInterval + 1000 * 60 * 45;//5小时+30+15分钟;
		WaitForSingleObject(g_ServiceStopEvent, ulInterval);
		}
		}
		}

		*/

		//test several times

		/*if ((local.tm_hour == 21 && (local.tm_min == 5 || local.tm_min == 10 || local.tm_min == 15)))
		{

		if (g_processInfo.hThread == NULL && g_processInfo.hProcess == NULL)
		{
		std::wstring strApp = L"C:\\WindRunnerHitPlayer\\风行期货进击系统.exe";
		StartCTPController(strApp);
		unsigned long ulInterval = 1000; //1秒
		ulInterval = ulInterval * 60 * 2;
		WaitForSingleObject(g_ServiceStopEvent, ulInterval);
		}
		}
		else if ((local.tm_hour == 21 && (local.tm_min == 8 || local.tm_min == 13 || local.tm_min == 18)))
		{

		DWORD dwEC = 0;
		BOOL b = GetExitCodeProcess(
		g_processInfo.hProcess,     // handle to the process
		&dwEC              // termination status
		);

		//if (b)
		{
		TerminateProcess(g_processInfo.hProcess, dwEC);
		}
		// Close process and thread handles.
		CloseHandle(g_processInfo.hProcess);
		CloseHandle(g_processInfo.hThread);
		memset(&g_processInfo, 0, sizeof(PROCESS_INFORMATION));

		unsigned long ulInterval = 1000; //1秒
		ulInterval = ulInterval * 60 * 2;
		WaitForSingleObject(g_ServiceStopEvent, ulInterval);

		}*/

	}


	return 0;
}