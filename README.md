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

[ ] Inject Dll in remtote process using **Reflective DLL injection**.

[x] inject using **Process Hollowing**.

[ ] inject using **Process Doppelganging**.

[ ] inject using **Atom Bombing**.

[x] inject using **Process Ghosting**.

[x] inject and persist using **Image File Execution Options**.

[x] inject using using **AppInit_DLLs** Registry.

[x] inject using using **AppCertDlls** Registry.

[ ] inject using **SHIMS**.

```
NOTE:
- In Process Hollowing Injection technique, it Crashes With Some 64bit process like System32\svchost.exe,... 
- In Process Ghosting injecting 32bit in 32bit work only on 32bit version of windows.

if you Know the Solution please let me know on abdelaziz.zohdy@gmail.com.
```

# Refrence:
[1]https://skanthak.homepage.t-online.de/appcert.html

[2]https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack

[3]https://github.com/hasherezade/process_ghosting
