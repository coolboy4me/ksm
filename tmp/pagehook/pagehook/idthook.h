#pragma once
#include <ntddk.h>
#include <windef.h>

#pragma pack(1)
// entry in the IDT, this is sometimes called
// an "interrupt gate"
typedef struct
{
	unsigned short LowOffset;
	unsigned short selector;
	unsigned char unused_lo;
	unsigned char segment_type : 4;	//0x0E is an interrupt gate
	unsigned char system_segment_flag : 1;
	unsigned char DPL : 2;	// descriptor privilege level 
	unsigned char P : 1; /* present */
	unsigned short HiOffset;
}IDTENTRY;

/* sidt returns idt in this format */
typedef struct
{
	unsigned short IDTLimit;
	unsigned short LowIDTbase;
	unsigned short HiIDTbase;
} IDTINFO;
#pragma pack()


NTSTATUS NTAPI HookIDT(UINT nIdtNum, PVOID NewFunction, PVOID *pSaveFunction, ULONG NewDPL);
NTSTATUS NTAPI UnHookIDT(UINT nIdtNum, PVOID SaveFunction);



