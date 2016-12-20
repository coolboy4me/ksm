#include "BaseUseFun.h"



PEPROCESS g_debugProcess = NULL;





BOOLEAN bIsProcessDebuger(PEPROCESS process)
{
	if (strstr(PsGetProcessImageFileName(process), "CTP_OD"))
		return TRUE;
	if (strstr(PsGetProcessImageFileName(process), "ctp_od"))
		return TRUE;
	if (strstr(PsGetProcessImageFileName(process), "CTP_CE"))
		return TRUE;
	if (strstr(PsGetProcessImageFileName(process), "ctp_ce"))
		return TRUE;
	if (strstr(PsGetProcessImageFileName(process), "ctp"))
		return TRUE;
	if (strstr(PsGetProcessImageFileName(process), "CTP"))
		return TRUE;
	if (strstr(PsGetProcessImageFileName(process), "OLLYDBG"))
		return TRUE;
	return FALSE;
}

PEPROCESS HandleToProcess(HANDLE hProcess, BOOL bThread)
{
	PEPROCESS Process = NULL;
	PETHREAD Thread;
	NTSTATUS ns;
	if (hProcess == (HANDLE)-1)
	{
		if (bThread)
			Process = ((PETHREAD)PsGetCurrentThread())->Tcb.ApcState.Process;
		else
			Process = PsGetCurrentProcess();
	}
	else
	{
		if (bThread)
		{
			ns = ObReferenceObjectByHandle(
				hProcess,
				THREAD_GET_CONTEXT,
				*PsThreadType,
				KernelMode,
				&Thread,
				NULL);
			if (NT_SUCCESS(ns))
			{
				ObDereferenceObject(Thread);
				Process = IoThreadToProcess(Thread);
			}
		}
		else
		{
			ns = ObReferenceObjectByHandle(
				hProcess,
				0x0800,
				*PsProcessType,
				KernelMode,
				&Process,
				NULL);
			if (NT_SUCCESS(ns))
				ObDereferenceObject(Process);
			else
				Process = NULL;
		}
	}

	return Process;
}

