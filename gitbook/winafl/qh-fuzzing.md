# Fuzzing Quick Heal using WinAFL

Fuzzing closed source application is not as easy as fuzzing application whose source code is available.

Quick Heal is a closed source AV scanner made in India. This AV has lots of services and drivers installed in the system. Each can pose security risk. However, in this workshop we are interested in fuzzing the file parsers in this particular AV.

Quick Heal installs **Core Scanning Server (SAPISSVC.EXE)** as a **SYSTEM** service. The Quick Heal GUI uses **IPC** to communicate with **SAPISSVC.EXE** service.

## How do we fuzz it now?

**SAPISSVC.EXE** runs as SYSTEM. We can't attach debugger to it easily. After some reversing of the main **SCANNER.EXE** (GUI application), I figured out that if the service is not not responding or dead, then the **SCANNER.EXE** with load the scanning engine and then continue scanning the file.

## Fuzzing SCANNER.EXE

Now we know that it's easy to fuzz **SCANNER.EXE**. But is it efficient enough to fuzz it using AFL/WinAFL?

Short answer not really. Then, how to fuzz it?


## Write custom Quick Heal client

Writing a custom client for an application whose source code nor debugging symbols are available, it's really hard and requires extensive reverse engineering.

I reached out to QuickHeal to see if they can provide me **qhscan** binary. **qhscan** is the command line scanner for Linux. But they asked to give my address, phone number and email so that their sales team can contact me and then provide me **quick heal for linux**. I declined this offer.

Quick Heal provides a scanning SDK (**SCANSDK.DLL**) which is utilized by the **SCANNER.EXE** and other command line scanners they provide. As this is a SDK, the important functions are exported.

```bash
ashfaq@hacksys:~$ cat dump-exports.py 
import os
import sys
import pefile

if __name__ == "__main__":
    filename = sys.argv[1]
    pe = pefile.PE(filename, fast_load=True)
    pe.parse_data_directories(directories=pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"])

    print "Dumping exports for: {0}".format(os.path.basename(filename))
    print ""

    exports = [e.name for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]

    for export in exports:
        print export
```

```bash
ashfaq@hacksys:~/Shared$ python dump-exports.py SCANSDK.DLL 
Dumping exports for: SCANSDK.DLL

GetAWStatus
GetQHOptions
GetSSStatus
QHAppCtlCloseFile
QHAppCtlDeinit
QHAppCtlGetFileType
QHAppCtlGetOptions
QHAppCtlGetVersionInfo
QHAppCtlInit
QHAppCtlOpenFile
QHAppCtlScanFile
QHAppCtlScanFileEx
QHAppCtlScanFileExForRS
QHAppCtlSetOptions
QHAppCtlSetOptionsForRS
QHAppcApplySignatures
QHAppcLoadSignatures
QHAppcReloadSignatures
QhCleanBoot
QhCleanFile
QhCleanFileEx
QhCleanFileExForMobile
QhCleanFileForMobile
QhCleanFileGen
QhCloseFile
QhCloseFileForMobile
QhCreateMimeObject
QhDeinitScan
QhDeinitScanForSAS
QhDeleteMimeObject
QhGetAPIVersion
QhGetAPIVersionEx
QhGetAVStamp
QhGetAVStampEx
QhGetActionForCommandLineW
QhGetFileType
QhGetFileTypeForMobile
QhGetFileTypeForSAS
QhGetOptions
QhGetOptionsForSAS
QhGetQuarantineUploadDecisionW
QhGetUpdateState
QhInitScan
QhInitScanForSAS
QhIsAccessDeniedAppExcludedW
QhIsCriticalAppInfectedW
QhIsHiddenProcessExcludedW
QhIsKindOfWorm
QhLoadBootScanner
QhOpenFile
QhOpenFileForMobile
QhOpenFileForSAS
QhReloadSignatures
QhResetFPTFlags
QhScanBoot
QhScanBuffer
QhScanBufferEx
QhScanBufferForSAS
QhScanFile
QhScanFileEx
QhScanFileExForMobile
QhScanFileForMobile
QhScanMBR
QhScanMessage
QhScanSSMemDS
QhScanSectorBuffer
QhScanURL
QhSetCallBack
QhSetCallBackForMobile
QhSetCallbackForSAS
QhSetMessageString
QhSetMessageStringForSAS
QhSetOptions
QhSetOptionsForSAS
QhSetProcessInfoForSAS
QhUnloadBootScanner
QhUpdatesArrived
```

Using old school debugging techniques, I figured out the API call sequence that is required to load the scanning engine and scan a file.

```
scansdk!QhInitScanForSAS
scansdk!QhSetCallbackForSAS
scansdk!QhOpenFileForSAS
scansdk!QhGetFileTypeForSAS
scansdk!QhScanFileEx
scansdk!QhCloseFile
scansdk!QhDeinitScanForSAS
```

Another big challenge in reversing an application is to figure out the data structures. As I have been doing RE stuff from a long time, it did not take much time to figure out the data structures. Few snipped data structures are listed below.

```c
typedef struct _INITSCAN_1 {
    SHORT Size;
    ...
    CHAR QuickHealDir[0x100];
    CHAR TempDir[0x100];
    ...
} INITSCAN_1, *PINITSCAN_1;

typedef struct _INITSCAN_2 {
    ...
    DWORD CurrentPid;
    ...
} INITSCAN_2, *PINITSCAN_2;

typedef struct _CALLBACK_PARAM_1 {
    ...
    CHAR DetectionDescription[50];
    ...
} CALLBACK_PARAM_1, *PCALLBACK_PARAM_1;
```

```
C:\Users\hacksys\Desktop\qhscan>qhscan.exe C:\61f67cf6f474351517e3b48cdd247f8255
892f48680ba52f6d6b8bf6c5d4b1d0.pdf

   8   8                   8""""8            ""8""
   8   8 eeeee eeee e   e  8      e    e eeeee 8   eeee eeeee eeeeeee
   8eee8 8   8 8  8 8   8  8eeeee 8    8 8   " 8e  8    8   8 8  8  8
   88  8 8eee8 8e   8eee8e     88 8eeee8 8eeee 88  8eee 8eee8 8e 8  8
   88  8 88  8 88   88   8 e   88   88      88 88  88   88  8 88 8  8
   88  8 88  8 88e8 88   8 8eee88   88   8ee88 88  88ee 88  8 88 8  8

                         Quick Heal Scanner Client
                       CloudFuzz Technolabs Pvt. Ltd.

[+] Loading ScanSDK
        [+] DLL: C:\Program Files\Quick Heal\Quick Heal AntiVirus Pro\SCANSDK.DL
L
        [+] Handle: 0x71070000
[+] Resolving ScanSDK APIs
[+] Scanning: C:\61f67cf6f474351517e3b48cdd247f8255892f48680ba52f6d6b8bf6c5d4b1d
0.pdf
        [+] QhScanFileEx
                [+] Infected: JS/Pdfcm.AQ
                [+] [Unrepairable]

C:\Users\hacksys\Desktop\qhscan>
```

## Fuzzing using WinAFL

As the custom client is ready to scan the files for us. It's a matter of few commands to start WinAFL and start fuzzing.

### Minset

```
winafl-cmin.py -v -D C:\Users\hacksys\Desktop\DynamoRIO\bin32 -t 100000 -i C:\Users\hacksys\Desktop\av -o C:\Users\hacksys\Desktop\minset -covtype edge -coverage_module SCANSDK.DLL -coverage_module platform.qvd -coverage_module filesdk.qvd -coverage_module ggstub.dll -coverage_module onlnmf.dll -coverage_module diskapi.dll -coverage_module bdsitf.dll -coverage_module infori.dll -coverage_module FileWrap.dll -coverage_module registry.dll -coverage_module opsitf.dll -coverage_module catitf.dll -coverage_module disasm.qvd -coverage_module dataproc.qvd -coverage_module qhpicln.dll -coverage_module engncore.qvd -coverage_module pescan.qvd -coverage_module pepoly.qvd -coverage_module arcvsdk.qvd -coverage_module lzesdk.qvd -coverage_module heurscan.qvd -coverage_module npesdk.qvd -coverage_module boot.qvd -coverage_module miscscan.qvd -coverage_module webcat.dll -coverage_module qhkill.qvd -target_module qhscan.exe -target_method ScanFile -nargs 1 -w 4 -- C:\Users\hacksys\Desktop\qhscan\qhscan.exe @@
```

### Fuzzing

```
afl-fuzz.exe -M master0 -i F:\minset -o F:\fuzz -D C:\Users\hacksys\Desktop\DynamoRIO\bin32 -t 20000 -- -covtype edge -coverage_module SCANSDK.DLL -coverage_module platform.qvd -coverage_module filesdk.qvd -coverage_module ggstub.dll -coverage_module onlnmf.dll -coverage_module diskapi.dll -coverage_module bdsitf.dll -coverage_module infori.dll -coverage_module FileWrap.dll -coverage_module registry.dll -coverage_module opsitf.dll -coverage_module catitf.dll -coverage_module disasm.qvd -coverage_module dataproc.qvd -coverage_module qhpicln.dll -coverage_module engncore.qvd -coverage_module pescan.qvd -coverage_module pepoly.qvd -coverage_module arcvsdk.qvd -coverage_module lzesdk.qvd -coverage_module heurscan.qvd -coverage_module npesdk.qvd -coverage_module boot.qvd -coverage_module miscscan.qvd -coverage_module webcat.dll -coverage_module qhkill.qvd -target_module qhscan.exe -target_method ScanFile -nargs 1 -- F:\qhscan.exe @@

afl-fuzz.exe -S slave0 -i - -o F:\fuzz -D C:\Users\hacksys\Desktop\DynamoRIO\bin32 -t 20000 -- -covtype edge -coverage_module SCANSDK.DLL -coverage_module platform.qvd -coverage_module filesdk.qvd -coverage_module ggstub.dll -coverage_module onlnmf.dll -coverage_module diskapi.dll -coverage_module bdsitf.dll -coverage_module infori.dll -coverage_module FileWrap.dll -coverage_module registry.dll -coverage_module opsitf.dll -coverage_module catitf.dll -coverage_module disasm.qvd -coverage_module dataproc.qvd -coverage_module qhpicln.dll -coverage_module engncore.qvd -coverage_module pescan.qvd -coverage_module pepoly.qvd -coverage_module arcvsdk.qvd -coverage_module lzesdk.qvd -coverage_module heurscan.qvd -coverage_module npesdk.qvd -coverage_module boot.qvd -coverage_module miscscan.qvd -coverage_module webcat.dll -coverage_module qhkill.qvd -target_module qhscan.exe -target_method ScanFile -nargs 1 -- F:\qhscan.exe @@
```
