#include "stdafx.h"
#include "idthook.h"



typedef NTSTATUS (NTAPI *_KeSetAffinityThread)(
	IN PKTHREAD Thread,
	IN KAFFINITY Affinity
	);

NTSTATUS NTAPI HookIDT(UINT nIdtNum,PVOID NewFunction,PVOID *pSaveFunction,ULONG NewDPL)
{
	KAFFINITY processors;
	PKTHREAD thread;
	LONG	i;
	ULONG_PTR OldTrap=0;
	IDTINFO		    idt_info;
	IDTENTRY*	    idt_entries;
	ULONG_PTR NewTrap = 0;
	UNICODE_STRING ustrKeSetAffinityThread;
	_KeSetAffinityThread KeSetAffinityThread;
	processors = KeQueryActiveProcessors();
	thread     = KeGetCurrentThread();
	NewTrap = (ULONG_PTR)NewFunction;
	RtlInitUnicodeString(&ustrKeSetAffinityThread, L"KeSetAffinityThread");
	KeSetAffinityThread = (_KeSetAffinityThread)MmGetSystemRoutineAddress(&ustrKeSetAffinityThread);
	for(i = 0; i < 32; i++)
	{
		KAFFINITY curProc = processors & (1 << i);
		if(curProc != 0)
		{
			DbgPrint("Switch To Cpu[%d]\n",i);
			KeSetAffinityThread(thread, curProc);
			__asm sidt idt_info
			idt_entries = (IDTENTRY*) MAKELONG(idt_info.LowIDTbase,idt_info.HiIDTbase);
			//////////////////////////////////////////////////////////////////////////
			OldTrap = MAKELONG(idt_entries[nIdtNum].LowOffset,idt_entries[nIdtNum].HiOffset);
			if(NewDPL==-1)
				NewDPL = (ULONG)idt_entries[nIdtNum].DPL;
			__asm nop;
			__asm nop;
			__asm nop;
			__asm cli;
			idt_entries[nIdtNum].LowOffset = (USHORT)NewTrap;
			idt_entries[nIdtNum].HiOffset = (USHORT)((ULONG)NewTrap >> 16);
			idt_entries[nIdtNum].DPL = (UCHAR)NewDPL;
			__asm sti;
			//////////////////////////////////////////////////////////////////////////
		}
	}
	KeSetAffinityThread(thread, processors);
	if (pSaveFunction)
	{
		*pSaveFunction = (PVOID)OldTrap;
	}
	return STATUS_SUCCESS;
}
NTSTATUS NTAPI UnHookIDT(UINT nIdtNum,PVOID SaveFunction)
{
	KAFFINITY processors;
	PKTHREAD thread;
	LONG	i;
	IDTINFO		    idt_info;
	IDTENTRY*	    idt_entries;
	ULONG_PTR NewTrap = 0;
	UNICODE_STRING ustrKeSetAffinityThread;
	_KeSetAffinityThread KeSetAffinityThread;
	processors = KeQueryActiveProcessors();
	thread     = KeGetCurrentThread();
	NewTrap = (ULONG_PTR)SaveFunction;
	RtlInitUnicodeString(&ustrKeSetAffinityThread, L"KeSetAffinityThread");
	KeSetAffinityThread = (_KeSetAffinityThread)MmGetSystemRoutineAddress(&ustrKeSetAffinityThread);
	for(i = 0; i < 32; i++)
	{
		KAFFINITY curProc = processors & (1 << i);
		if(curProc != 0)
		{
			KeSetAffinityThread(thread, curProc);
			__asm sidt idt_info
			idt_entries = (IDTENTRY*) MAKELONG(idt_info.LowIDTbase,idt_info.HiIDTbase);
			//////////////////////////////////////////////////////////////////////////
			__asm nop;
			__asm nop;
			__asm nop;
			__asm cli;
			idt_entries[nIdtNum].LowOffset = (USHORT)NewTrap;
			idt_entries[nIdtNum].HiOffset = (USHORT)((ULONG)NewTrap >> 16);
			__asm sti;
			//////////////////////////////////////////////////////////////////////////
		}
	}
	KeSetAffinityThread(thread, processors);
	return STATUS_SUCCESS;
}