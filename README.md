# Dsebler
Dsebler is a reimplementation of the __Driver Signature Enforcement (DSE) bypass technique__ showed by [floesen](https://github.com/floesen/KExecDD). The code was restructured and reorganized with the possibility of easily adding gadget offsets based on the OS version. I also preferred the injection of a code block with replaceable function pointers over dll injection. For a more stable version which relies on parser functions rather than hardcoded offsets, I recommend taking a look at [KBlast](https://github.com/lem0nSec/KBlast).

## DSE?
Driver Signature Enforcement is a Microsoft security feature which ensures that only trusted and verified drivers can be loaded onto the Windows operating system. This is to prevent untrusted and potentially malicious software to cause harm to the OS. Since the value which regulates the behaviour of DSE resides in the Windows kernel memory itself (CI.dll), it cannot be disabled from userland unless a vulnerability allowing for arbitrary writing on the Windows kernel is found on a signed driver.

## Static Analysis on IDA
The Microsoft Kernel Mode Security Support Provider Interface (KsecDD) is a kernel module which provides cryptographic services on the Windows operating system. Even dpapi.dll relies on KsecDD.sys to conduct its main tasks. Interestingly, [floesen](https://github.com/floesen) found out that KsecDD allows the process lsass.exe to execute arbitrary memory addresses with the possibility to also set parameters through the IOCTL 0x39006f. When this control code is issued, the KsecFastIoDeviceControl dispatchar calls the function KsecIoctlHandleFunctionReturn as shown below.

![](pictures/3.png)


The case statement first checks whether the buffer length which was sent from userland is 16. If so it passes execution to KsecIoctlHandleFunctionReturn.
The parameter that is passed to KsecIoctlHandleFunctionReturn is a 16-byte-large data structure which I named IPC_SET_FUNCTION_RETURN_PARAMETER. The struct holds three values. The first is a pointer to a second 16-byte data structure which in turn holds a pointer which will be the custom address to be executed (rip), and another 8-byte large element which will be the first parameter that is passed at execution time (rcx). Going back to the main struct, the second value is a 4-byte-large element which will go into rdx at execution time. The third 4-byte value is not needed.

![](pictures/8.png)


 KsecIoctlHandleFunctionReturn performs some checks on whether the passed struct is large 16 bytes and whether the address is a userland address. The most important part is the call to the function CallInProgressCompleted, which is where the actual execution logic resides.

 ![](pictures/4.png)


 As shown below, the decompiled version of the CallInProgressCompleted executes the first value of pInternalStruct (IPC_SET_FUNCTION_RETURN_DEEP_PARAMETER struct), whose pointer is in turn the first value of the IPC_SET_FUNCTION_RETURN_PARAMETER struct which is passed to KsecIoctlHandleFunctionReturn from userland by lsass.exe. The second value of pInternalStruct is passed as first parameter in rcx, and the second value of the original IPC_SET_FUNCTION_RETURN_PARAMETER struct is passed as second parameter (rdx).


![](pictures/5.png)


## Brief POC on Windbg
The Windows OS used to run this code is a Windows 10 build 19045.

![](pictures/9.png)

After attacching Windbg to the kernel of the virtual machine, a breakpoint is placed on KsecIoctlHandleFunctionReturn. After running Dsebler.exe the breakpoint is hit, and the call stack also shows that the function is called from KsecFastIoDeviceControl.

![](pictures/1.png)


Moving on it can be seen that the CallInProgressCompleted function finally calls the ntoskrnl.exe gadget "mov \[rcx\], rdx" which is the first value of pInternalStruct (IPC_SET_FUNCTION_RETURN_DEEP_PARAMETER). By the same token rcx is a pointer to g_cioptions, which is the second value of pInternalStruct and rdx is the second value of pParameterStruct (IPC_SET_FUNCTION_RETURN_PARAMETER). Rdx is 0 in order to write 0 to g_cioptions.

![](pictures/2.png)


By stepping into the next instruction g_cioptions gets successfully overwritten with 0 and DSE disabled.

![](pictures/6.png)

Attempting to load the unsigned driver of [KBlast](https://github.com/lem0nSec/KBlast) now works. Shout out to [floesen](https://github.com/floesen) for the amazing finding!!

![](pictures/7.png)


## Warning :warning:
This code was developed and tested on a Windows 10.0 build 19045.4412 virtual machine. It will cause system crash if it is used on a different OS due to other OS' offsets not being implemented at the moment. If you are aware of other OS' offsets for g_cioptions and the ntoskrnl gadget used, do open a pull request!


## Reference
https://github.com/floesen/KExecDD
