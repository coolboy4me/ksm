#include "NtWriteVirtualMemory.h"
#include "BaseStructDKK.h"
#include "ntimage.h"
#include "BaseUseFun.h"
#include "pagehack.h"

HOOK_INFO g_NtWriteVirtualMemoryInfo;
typedef NTSTATUS (__stdcall *OrgNtWriteVirtualMemory)(
	IN	HANDLE				ProcessHandle,
	OUT	PVOID				BaseAddress,
	IN	PVOID				Buffer,
	IN	ULONG				BufferSize,
	OUT	PULONG				NumberOfBytesWritten);
NTSTATUS __stdcall MyNtWriteVirtualMemory(
	IN	HANDLE				ProcessHandle,
	OUT	PVOID				BaseAddress,
	IN	PVOID				Buffer,
	IN	ULONG				BufferSize,
	OUT	PULONG				NumberOfBytesWritten
	)
{
	PEPROCESS process;

	if (bIsProcessDebuger(PsGetCurrentProcess()))
	{
		process = HandleToProcess(ProcessHandle, FALSE);
		if (process)
		{
			if (g_debugProcess == process)
			{
				if (BufferSize == 1 )
				{
					if (*(BYTE*)Buffer == 0xCC)
					{
						if (AddBP(process, (ULONG32)BaseAddress, 3))
						{
							DbgPrint("vmx:Ìí¼Ó¶Ïµã:[%s][%p]\n", PsGetProcessImageFileName(process), BaseAddress);
							if (NumberOfBytesWritten)
								*NumberOfBytesWritten = 1;
							return STATUS_SUCCESS;
						}
					} 
					else
					{
						if (DelBP(process, (ULONG32)BaseAddress, 3))
						{
							DbgPrint("vmx:É¾³ý¶Ïµã:[%s][%p]\n", PsGetProcessImageFileName(process), BaseAddress);
							if (NumberOfBytesWritten)
								*NumberOfBytesWritten = 1;
							return STATUS_SUCCESS;
						}
					}
				}
			}
		}
	}
	return CALL_NORNAL_API(OrgNtWriteVirtualMemory, g_NtWriteVirtualMemoryInfo)(
		ProcessHandle,
		BaseAddress,
		Buffer,
		BufferSize,
		NumberOfBytesWritten);
}


VOID HookNtWriteVirtualMemory()
{
	ULONG32 ulAddress;

	ulAddress = KeServiceDescriptorTable->ServiceTableBase[277];
	DbgPrint("vmx:NtWriteVirtualMemory:%p\n", ulAddress);
	FORMAT_PATCH_FUNC_ST(g_NtWriteVirtualMemoryInfo, ulAddress, MyNtWriteVirtualMemory);
	inlineHook(&g_NtWriteVirtualMemoryInfo);
}


VOID UnHookNtWriteVirtualMemory()
{
	unInlineHook(&g_NtWriteVirtualMemoryInfo);
}




