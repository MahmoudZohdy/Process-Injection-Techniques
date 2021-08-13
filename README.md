# Process-Injection-Techniques

This is the C implementation of Diffrent Process Injection Technique.

```
Usage: Process_Injection_Techniques.exe

This wil print the injection techniques that is implemented and how to use them
```



***Techniques that i will cover here:***

[x] Inject Dll in remtote process using **CreateRemoteThread** API.

[x] Inject Dll in remtote process using **SetWindowsHookExW** API.

[x] Inject ShellCode in remtote process using **CreateRemoteThread** API.

[x] Inject ShellCode in remote process using **QueueUserAPC** API.

[x] Inject ShellCode in remote process using **Early Bird** Technique.

[x] Inject ShellCode in remote process using **TLS CallBack** Technique.

[x] Inject using **Thread execution hijacking**.

[x] Inject Dll in remtote process using **Reflective DLL injection**.

[x] inject using **Process Hollowing**.

[ ] inject using **Process Doppelganging**.

[ ] inject using **Atom Bombing**.

[x] inject using **Process Ghosting**.

[x] inject and persist using **Image File Execution Options**.

[x] inject using using **AppInit_DLLs** Registry.

[x] inject using using **AppCertDlls** Registry.


```
NOTE:
- In Process Hollowing Injection technique, it Crashes With Some 64bit process like System32\svchost.exe,... 
- In Process Ghosting injecting 32bit in 32bit work only on 32bit version of windows.
- In Reflective DLL injection The Dll To inject should Depend only on Kernel32.dll and ntdll.dll for stability, as they are loaded at the same base address for all processes on the system, See Refrence[6] in the README for more info

if you Know the Solution please for the Process Hollowing and Process Ghosting let me know on abdelaziz.zohdy@gmail.com.
```

# Refrence:
[1]https://skanthak.homepage.t-online.de/appcert.html

[2]https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack

[3]https://github.com/hasherezade/process_ghosting

[4]https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/

[5]https://github.com/stephenfewer/ReflectiveDLLInjection

[6]http://www.nynaeve.net/?p=198

[7]https://www.ired.team/