#include "dse.h"

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