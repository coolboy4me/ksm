#include "BaseUseFun.h"



PEPROCESS g_debugProcess = NULL;



ULONG32 SetIA32EFER()
{
	//table 4-10 
	//IA32_EFER.NXE = 1; wrmsr
	/*


	Table 35-2. IA-32 Architectural MSRs (Contd.)
	//11λ  д1
	Execute Disable Bit Enable:
	IA32_EFER.NXE (R/W)
	*/
	ULONG32 tmp32 = 0;
	__asm {
		pushad
			mov ecx, 0xc0000080
			rdmsr
			mov tmp32, eax
			popad
	}
	tmp32 |= (1 << 11);

	__asm{
		pushad
			mov edx, 0
			mov eax, tmp32
			mov ecx, 0xc0000080
			wrmsr
			popad
	}

	tmp32 = 0;
	__asm {
		pushad
			mov ecx, 0xc0000080
			rdmsr
			mov tmp32, eax
			popad
	}

	return tmp32;
}

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

