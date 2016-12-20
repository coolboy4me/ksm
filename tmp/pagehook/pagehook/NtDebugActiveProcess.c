#include "NtDebugActiveProcess.h"
#include "BaseUseFun.h"

HOOK_INFO g_NtDebugActiveProcessInfo;
typedef NTSTATUS (__stdcall	*OrgNtDebugActiveProcess)(//·´»ã±àOK
	HANDLE ProcessHandle,
	HANDLE DebugObjectHandle
	);
NTSTATUS __stdcall	MyNtDebugActiveProcess(//·´»ã±àOK
	HANDLE ProcessHandle,
	HANDLE DebugObjectHandle
	)
{
	PEPROCESS process;
	NTSTATUS status;

	status = CALL_NORNAL_API(OrgNtDebugActiveProcess, g_NtDebugActiveProcessInfo)(
		ProcessHandle,
		DebugObjectHandle);

	if (NT_SUCCESS(status))
	{
		if (bIsProcessDebuger(PsGetCurrentProcess()))
		{
			process = HandleToProcess(ProcessHandle, FALSE);
			if (process)
			{
				g_debugProcess = process;
				DbgPrint("vmx:OD¸½¼Ó[%s]",PsGetProcessImageFileName(process));
			}
		}
	}

	return status;
}


VOID HookNtDebugActiveProcess()
{
	ULONG32 ulAddress;

	ulAddress = KeServiceDescriptorTable->ServiceTableBase[57];
	DbgPrint("vmx:NtDebugActiveProcess:%p\n", ulAddress);
	FORMAT_PATCH_FUNC_ST(g_NtDebugActiveProcessInfo, ulAddress, MyNtDebugActiveProcess);
	inlineHook(&g_NtDebugActiveProcessInfo);
}


VOID UnHookNtDebugActiveProcess()
{
	unInlineHook(&g_NtDebugActiveProcessInfo);
}
