# Dsebler
Dsebler is a reimplementation of the __Driver Signature Enforcement (DSE) bypass technique__ showed by [floesen](https://github.com/floesen/KExecDD). This repo is a technical analysis of the technique. The code here is temporary, and the repo will be archived when the technique will be added to [KBlast](https://github.com/lem0nSec/KBlast).

## DSE?
Driver Signature Enforcement is a Microsoft security feature which ensures that only trusted and verified drivers can be loaded onto the Windows operating system. This is among other things to prevent untrusted and potentially malicious software to cause harm to the OS. Since the value which regulates the behaviour of DSE is inside the Windows kernel itself, it cannot be technically disabled from userland unless a vulnerability is found on a trusted driver which allows for arbitrary writing on the Windows kernel.

## KsecDD
The Microsoft Kernel Mode Security Support Provider Interface (KsecDD) is a system driver which provides cryptographic services since Windows Vista. Even dpapi.dll relies on KsecDD.sys to conduct its main tasks. Interestinly, ![floesen](https://github.com/floesen) found out that KsecDD allows lsass.exe to run custom kernel addresses with the possibility to also set parameters through the IOCTL 0x39009f.

## Reference
https://github.com/floesen/KExecDD
