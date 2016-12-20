#include "KiDispatchException.h"
#include "BaseUseFun.h"

HOOK_INFO g_KiDispatchExceptionInfo;
typedef NTSTATUS(__stdcall	*OrgKiDispatchException)(//·´»ã±àOK
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PKTRAP_FRAME TrapFrame,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN FirstChance
	);

VOID __stdcall MyKiDispatchException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PKTRAP_FRAME TrapFrame,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN FirstChance
)
{
	PEPROCESS process;
	if (PreviousMode == UserMode && PsGetCurrentProcess() == g_debugProcess)
	{
		if (MmIsAddressValid(TrapFrame) && MmIsAddressValid(ExceptionRecord) &&
			MmIsAddressValid(&TrapFrame->Eip) && MmIsAddressValid(&ExceptionRecord->ExceptionAddress) &&
			MmIsAddressValid(&ExceptionRecord->ExceptionCode))
		{
			DbgPrint("vmx:KiDispatch[%s][%p][%p][%p]\n",
				PsGetProcessImageFileName(PsGetCurrentProcess()),
				TrapFrame->Eip,
				ExceptionRecord->ExceptionAddress,
				ExceptionRecord->ExceptionCode);
		}
	}
	CALL_NORNAL_API(OrgKiDispatchException, g_KiDispatchExceptionInfo)(
		ExceptionRecord,
		ExceptionFrame,
		TrapFrame, 
		PreviousMode, 
		FirstChance);
}


VOID HookKiDispatchException()
{
	ULONG32 ulAddress;

	ulAddress = 0x804ff466  ;
	DbgPrint("vmx:NtDebugActiveProcess:%p\n", ulAddress);
	FORMAT_PATCH_FUNC_ST(g_KiDispatchExceptionInfo, ulAddress, MyKiDispatchException);
	inlineHook(&g_KiDispatchExceptionInfo);
}


VOID UnHookKiDispatchException()
{
	unInlineHook(&g_KiDispatchExceptionInfo);
}
