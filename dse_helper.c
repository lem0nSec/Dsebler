#include "dse.h"

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
		else
			goto error;
	}

	return RemoteHandler;

error:
	return 0;

}