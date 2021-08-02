// Process_Injection_Techniques.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "Injection.h"
#include "Utiliti.h"

using namespace std;

int wmain(int argc,WCHAR* argv[])
{
    
	if (argc < 2) {
		PrintUsage();
		return 0;
	}
	ParseCommandLineArgument(argc, argv);
	
    int InjectionType = _wtoi(argv[1]);
    switch (InjectionType) {
    case 1:
        InjectDllUsingCreateRemoteThread(ProcessID, DLLPath);
        break;

    case 2:
        InjectDllUsingSetWindowHook(DLLPath, ExportFunctionName);
        break;

    case 3:
        InjectShellCodeInProcess(ProcessID, ShellCodePath);
        break;

    case 4:
        InjectUsingAPC(ProcessID, ShellCodePath);
        break;

    case 5:
        InjectUsingEarlyBirdAPC(ProcessName, ShellCodePath);
        break;

    case 6:
        InjectUsingTLSCallBack(ProcessID, ShellCodePath, ProcessName);
        break;

    default:
        PrintUsage();
        break;
    }
	return 0;
}
