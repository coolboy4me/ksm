#include "ContextThread.h"
#include "BaseUseFun.h"
#include "pagehack.h"

HOOK_INFO g_PsGetContextThread;
HOOK_INFO g_PsSetContextThread;

typedef NTSTATUS (__stdcall *RelodContextThread)(
	__in PETHREAD Thread,
	__in PCONTEXT ThreadContext,
	__in KPROCESSOR_MODE Mode
	);

NTSTATUS __stdcall MyPsSetContextThread(
	__in PETHREAD Thread,
	__in PCONTEXT ThreadContext,
	__in KPROCESSOR_MODE Mode
	)
{
	NTSTATUS status;
	PEPROCESS eProcess;

	eProcess = IoThreadToProcess(Thread);
	status = STATUS_SUCCESS;
	if (NT_SUCCESS(status))
	{
		DbgPrint("vmx£ºMyPsSetContextThread£º[%s][%s][%p]\n",
			PsGetProcessImageFileName(PsGetCurrentProcess()),
			PsGetProcessImageFileName(eProcess),
			ThreadContext->Eip);
	}
	status = CALL_NORNAL_API(RelodContextThread,g_PsSetContextThread)(
		Thread,
		ThreadContext,
		Mode); 
	//if (NT_SUCCESS(status))
	//{
	//	DbgPrint("vmx£ºMyPsSetContextThread£º[%s][%s][%p]\n", 
	//		PsGetProcessImageFileName(PsGetCurrentProcess()), 
	//		PsGetProcessImageFileName(eProcess),
	//		ThreadContext->Eip);
	//}
	return status;
}


NTSTATUS __stdcall MyPsGetContextThread(
	__in PETHREAD Thread,
	__in PCONTEXT ThreadContext,
	__in KPROCESSOR_MODE Mode
	)
{
	NTSTATUS status;
	PEPROCESS eProcess;

	eProcess = IoThreadToProcess(Thread);
	status = CALL_NORNAL_API(RelodContextThread,g_PsGetContextThread)(
		Thread,
		ThreadContext,
		Mode); 
	if (NT_SUCCESS(status))
	{
		DbgPrint("vmx£ºMyPsGetContextThread£º[%s][%s][%p]\n", 
			PsGetProcessImageFileName(PsGetCurrentProcess()),
			PsGetProcessImageFileName(eProcess),
			ThreadContext->Eip);
	}
	return status;
}



void HookContextThread()
{
	ULONG StartAddress;
	UNICODE_STRING usPsSetContextThread;
	UNICODE_STRING usPsGetContextThread;

	RtlInitUnicodeString(&usPsSetContextThread, L"PsSetContextThread");
	StartAddress = (DWORD)MmGetSystemRoutineAddress(&usPsSetContextThread);
	if (StartAddress == 0xFFFF)
		return;
	FORMAT_PATCH_FUNC_ST(g_PsSetContextThread, StartAddress, MyPsSetContextThread);
	inlineHook(&g_PsSetContextThread);
	DbgPrint("vmx:HOOK PsSetContextThread is Success:[%p]\n", StartAddress);

	RtlInitUnicodeString(&usPsGetContextThread, L"PsGetContextThread");
	StartAddress = (DWORD)MmGetSystemRoutineAddress(&usPsGetContextThread);
	if (StartAddress == 0xFFFF)
		return;
	FORMAT_PATCH_FUNC_ST(g_PsGetContextThread, StartAddress, MyPsGetContextThread);
	inlineHook(&g_PsGetContextThread);
	DbgPrint("vmx:HOOK PsGetContextThread is Success:[%p]\n", StartAddress);
}

void UnhookContextThread()
{
	unInlineHook(&g_PsSetContextThread);
	DbgPrint(("UnHOOK PsSetContextThread is Success\n"));

	unInlineHook(&g_PsGetContextThread);
	DbgPrint(("UnHOOK PsGetContextThread is Success\n"));
}
