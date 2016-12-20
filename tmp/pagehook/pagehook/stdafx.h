#pragma once
#include <ntddk.h>
#include <stdio.h>
#include <stdarg.h>
#include <wchar.h>
#include <ntddscsi.h>
#include <srb.h>
#include <ntimage.h>
#include <windef.h>

typedef struct _KAPC_STATE {
	LIST_ENTRY  ApcListHead[2];
	PKPROCESS   Process;
	BOOLEAN     KernelApcInProgress;
	BOOLEAN     KernelApcPending;
	BOOLEAN     UserApcPending;
} KAPC_STATE, *PKAPC_STATE;

NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS Process);
NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE Id, PEPROCESS *Process);
NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(HANDLE Id, PETHREAD *Thread);
NTKERNELAPI PEPROCESS IoThreadToProcess(IN PETHREAD Thread);
NTKERNELAPI PVOID ObGetObjectType(IN PVOID Object);
NTKERNELAPI VOID NTAPI KeAttachProcess(PEPROCESS Process);
NTKERNELAPI VOID NTAPI KeDetachProcess();
NTKERNELAPI VOID NTAPI KeStackAttachProcess(PEPROCESS Process, PKAPC_STATE ApcState);
NTKERNELAPI VOID NTAPI KeUnstackDetachProcess(PKAPC_STATE ApcState);