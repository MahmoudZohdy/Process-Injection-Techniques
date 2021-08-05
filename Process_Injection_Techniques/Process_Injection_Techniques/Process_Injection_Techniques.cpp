// Process_Injection_Techniques.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "Injection.h"
#include "Utiliti.h"

using namespace std;

int wmain(int argc,WCHAR* argv[])
{
    DWORD Result = 0;
    int InjectionType;
    /*PROCESS_INFO info;
    StartExecutableAsSuspended(argv[1], &info, CREATE_SUSPENDED);
    Result = InjectDllUsingCreateRemoteThread(info.PID, argv[2]);
    if (Result == -1) {
        printf("Injection Failed\n");
    }
    else {
        printf("Injection Succeeded\n");
    }
    ResumeThread(info.MainThreadHandle);
    return 0;*/

	if (argc < 3) {
		PrintUsage();
		return 0;
	}
	ParseCommandLineArgument(argc, argv);
    InjectionType = _wtoi(argv[1]);
    switch (InjectionType) {
    case 1:
        Result = InjectDllUsingCreateRemoteThread(ProcessID, DLLPath);
        if (Result == -1) {
            printf("Injection Failed\n");
        }
        else {
            printf("Injection Succeeded\n");
        }
        break;

    case 2:
        Result = InjectDllUsingSetWindowHook(DLLPath, ExportFunctionName);
        if (Result == -1) {
            printf("Injection Failed\n");
        }
        else {
            printf("Injection Succeeded\n");
        }
        break;

    case 3:
        Result = InjectShellCodeInProcess(ProcessID, ShellCodePath);
        if (Result == -1) {
            printf("Injection Failed\n");
        }
        else {
            printf("Injection Succeeded\n");
        }
        break;

    case 4:
        Result = InjectUsingAPC(ProcessID, ShellCodePath);
        if (Result == -1) {
            printf("Injection Failed\n");
        }
        else {
            printf("Injection Succeeded\n");
        }
        break;

    case 5:
        Result = InjectUsingEarlyBirdAPC(ProcessName, ShellCodePath);
        if (Result == -1) {
            printf("Injection Failed\n");
        }
        else {
            printf("Injection Succeeded\n");
        }
        break;

    case 6:
        Result = InjectUsingTLSCallBack(ProcessID, ShellCodePath, ProcessName);
        if (Result == -1) {
            printf("Injection Failed\n");
        }
        else {
            printf("Injection Succeeded\n");
        }
        break;
    
    case 7:
        Result = InjectUsingThreadExecutionHijacking(ProcessID, ShellCodePath);
        if (Result == -1) {
            printf("Injection Failed\n");
        }
        else {
            printf("Injection Succeeded\n");
        }
        break;

    case 8:
        Result = InjectUsingProcessHollowing(ProcessName, SourceProcessName);
        if (Result == -1) {
            printf("Injection Failed\n");
        }
        else {
            printf("Injection Succeeded\n");
        }
        break;
    default:
        PrintUsage();
        break;
    }
	return 0;
}
