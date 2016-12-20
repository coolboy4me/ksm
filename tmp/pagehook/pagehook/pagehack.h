#pragma once
typedef struct _HARDWARE_PTE_X86PAE {
	union {
		struct {
			ULONGLONG Valid : 1;
			ULONGLONG Write : 1;
			ULONGLONG Owner : 1;
			ULONGLONG WriteThrough : 1;
			ULONGLONG CacheDisable : 1;
			ULONGLONG Accessed : 1;
			ULONGLONG Dirty : 1;
			ULONGLONG LargePage : 1;
			ULONGLONG Global : 1;
			ULONGLONG CopyOnWrite : 1;         // software field
			ULONGLONG Prototype : 1;           // software field
			ULONGLONG reserved0 : 1;          // software field
			ULONGLONG PageFrameNumber : 26;
			//ULONGLONG reserved1 : 26;          // software field
			ULONGLONG reserved1 : 25;          // software field
			ULONGLONG ExecuteDisable : 1;        // 这个
		};
		struct {
			ULONG LowPart;
			ULONG HighPart;
		};
	};
} HARDWARE_PTE_X86PAE, *PHARDWARE_PTE_X86PAE;
//typedef struct _MMPTE_SOFTWARE {
//	ULONG Valid : 1;
//	ULONG PageFileLow : 4;
//	ULONG Protection : 5;
//	ULONG Prototype : 1;
//	ULONG Transition : 1;
//	ULONG PageFileHigh : 20;
//} MMPTE_SOFTWARE;
//
//typedef struct _MMPTE_TRANSITION {
//	ULONG Valid : 1;
//	ULONG Write : 1;
//	ULONG Owner : 1;
//	ULONG WriteThrough : 1;
//	ULONG CacheDisable : 1;
//	ULONG Protection : 5;
//	ULONG Prototype : 1;
//	ULONG Transition : 1;
//	ULONG PageFrameNumber : 20;
//} MMPTE_TRANSITION;
//
//typedef struct _MMPTE_PROTOTYPE {
//	ULONG Valid : 1;
//	ULONG ProtoAddressLow : 7;
//	ULONG ReadOnly : 1;  // if set allow read only access.
//	ULONG WhichPool : 1;
//	ULONG Prototype : 1;
//	ULONG ProtoAddressHigh : 21;
//} MMPTE_PROTOTYPE;
//
//typedef struct _MMPTE_HARDWARE {
//	ULONG Valid : 1;
//	ULONG Write : 1;       // UP version
//	ULONG Owner : 1;
//	ULONG WriteThrough : 1;
//	ULONG CacheDisable : 1;
//	ULONG Accessed : 1;
//	ULONG Dirty : 1;
//	ULONG LargePage : 1;
//	ULONG Global : 1;
//	ULONG CopyOnWrite : 1; // software field
//	ULONG Prototype : 1;   // software field
//	ULONG reserved : 1;    // software field
//	ULONG PageFrameNumber : 20;
//} MMPTE_HARDWARE, *PMMPTE_HARDWARE;
//
//typedef struct _MMPTE {
//	union  {
//		ULONG Long;
//		MMPTE_HARDWARE Hard;
//		MMPTE_PROTOTYPE Proto;
//		MMPTE_SOFTWARE Soft;
//		MMPTE_TRANSITION Trans;
//	} u;
//} MMPTE, *PMMPTE;

typedef struct _MMPTE_SOFTWARE_PAE {
	ULONGLONG Valid : 1;
	ULONGLONG PageFileLow : 4;
	ULONGLONG Protection : 5;
	ULONGLONG Prototype : 1;
	ULONGLONG Transition : 1;
	ULONGLONG Unused : 20;
	ULONGLONG PageFileHigh : 32;
} MMPTE_SOFTWARE_PAE;

typedef struct _MMPTE_TRANSITION_PAE {
	ULONGLONG Valid : 1;
	ULONGLONG Write : 1;
	ULONGLONG Owner : 1;
	ULONGLONG WriteThrough : 1;
	ULONGLONG CacheDisable : 1;
	ULONGLONG Protection : 5;
	ULONGLONG Prototype : 1;
	ULONGLONG Transition : 1;
	ULONGLONG PageFrameNumber : 24;
	ULONGLONG Unused : 28;
} MMPTE_TRANSITION_PAE;

typedef struct _MMPTE_PROTOTYPE_PAE {
	ULONGLONG Valid : 1;
	ULONGLONG Unused0: 7;
	ULONGLONG ReadOnly : 1;  // if set allow read only access.  LWFIX: remove
	ULONGLONG Unused1: 1;
	ULONGLONG Prototype : 1;
	ULONGLONG Protection : 5;
	ULONGLONG Unused: 16;
	ULONGLONG ProtoAddress: 32;
} MMPTE_PROTOTYPE_PAE;

typedef struct _MMPTE_HARDWARE_PAE {
	ULONGLONG Valid : 1;
	ULONGLONG Write : 1;        // UP version
	ULONGLONG Owner : 1;
	ULONGLONG WriteThrough : 1;
	ULONGLONG CacheDisable : 1;
	ULONGLONG Accessed : 1;
	ULONGLONG Dirty : 1;
	ULONGLONG LargePage : 1;
	ULONGLONG Global : 1;
	ULONGLONG CopyOnWrite : 1; // software field
	ULONGLONG Prototype : 1;   // software field
	ULONGLONG reserved0 : 1;  // software field
	ULONGLONG PageFrameNumber : 24;
	ULONGLONG reserved1 : 28;  // software field
} MMPTE_HARDWARE_PAE, *PMMPTE_HARDWARE_PAE;

typedef struct _MMPTE_PAE {
	union  {
		LARGE_INTEGER Long;
		MMPTE_HARDWARE_PAE Hard;
		MMPTE_PROTOTYPE_PAE Proto;
		MMPTE_SOFTWARE_PAE Soft;
		MMPTE_TRANSITION_PAE Trans;
	} u;
} MMPTE_PAE;

typedef MMPTE_PAE *PMMPTE_PAE;


#define PTE_BASE    0xC0000000
#define PDE_BASE    0xC0300000
#define PDE_BASE_PAE 0xc0600000

//#define MiGetPdeAddress(va)  ((MMPTE*)(((((ULONG)(va)) >> 22) << 2) + PDE_BASE))
//#define MiGetPteAddress(va) ((MMPTE*)(((((ULONG)(va)) >> 12) << 2) + PTE_BASE))

#define MiGetPdeAddressPae(va)   ((PMMPTE_PAE)(PDE_BASE_PAE + ((((ULONG)(va)) >> 21) << 3)))
#define MiGetPteAddressPae(va)   ((PMMPTE_PAE)(PTE_BASE + ((((ULONG)(va)) >> 12) << 3)))


#define PF_MEM_TAG 'pfmm'
typedef struct _PF_ITEM_
{
	PEPROCESS Process;
	PHARDWARE_PTE_X86PAE Pte;
	BOOL bSingle;
	ULONG32 StepEip;
}PFITEM,*PPFITEM;

//typedef struct PFLIST_ROOT_NODE {
//	LIST_ENTRY RootEntry;
//	ERESOURCE Lock;
//	BOOLEAN Initialized;
//	ULONG volatile LockCount;
//} PFLIST_ROOT_NODE;
//
//typedef struct PF_INFO_NODE {
//	LIST_ENTRY ListEntry;
//	PFITEM PfInfo;
//	ULONG RefCount;			// 引用计数 
//} PF_INFO_NODE;

typedef struct _PF_CONTEXT_{
	ULONG   regCr2;
	ULONG   regFs;
	ULONG   regEs;
	ULONG   regDs;
	ULONG   regEflag;
	ULONG   regEdi;
	ULONG   regEsi;
	ULONG   regEbp;
	ULONG   regEsp;
	ULONG   regEbx;
	ULONG   regEdx;
	ULONG   regEcx;
	ULONG   regEax;
	ULONG   regErrorCode;
	ULONG   regEip;
	ULONG   regCs;
	ULONG   regEflags;
	ULONG   regEspR3;
	ULONG   regSs;
}PF_CONTEXT, *PPF_CONTEXT;  

typedef struct _DBTRAP_CONTEXT
{
	ULONG   regFs;
	ULONG   regEs;
	ULONG   regDs;
	ULONG   regEflag;
	ULONG   regEdi;
	ULONG   regEsi;
	ULONG   regEbp;
	ULONG   regEsp;
	ULONG   regEbx;
	ULONG   regEdx;
	ULONG   regEcx;
	ULONG   regEax;
	ULONG   regEip;
	ULONG   regCs;
	ULONG   regEflags;
	ULONG   regEspR3;
	ULONG   regSs;
}DBTRAP_CONTEXT,*PDBTRAP_CONTEXT;

typedef NTSTATUS  (__stdcall *MMACCESSFAULT)(
	ULONG   ErrorMask,
	PVOID   VirtualAddress,
	ULONG   ProcessorMode,
	PVOID   KTrapInformation);       


#define PF_PASS_INT0E 0
#define PF_INTO_INT1 1
#define PF_NEED_CHECK 2
#define PF_INTO_INT3 3
#define PF_CONTINUE_EXECUTION 4

#define DB_PASS_INT01 0
#define DB_CONTINUE_EXECUTION 1
#define DB_PASS_TRAP03 2


#define BP_MEM_TAG 'spbp'
typedef struct _BP_ITEM_
{
	PEPROCESS Process;
	ULONG32 Address;
	ULONG32 ExceptionType;
	ULONG32 VistCount;
}BPITEM,*PBPITEM;

ULONG32 GetBP(PEPROCESS Process,ULONG32 Address,BOOL bFormVt);
BOOL AddBP(PEPROCESS Process,ULONG32 Address,ULONG32 ExceptionType);
BOOL DelBP(PEPROCESS Process,ULONG32 Address,ULONG32 ExceptionType);

BOOL InitPageHack();
ULONG32 GetDBHanlderAddress();
ULONG32 GetPFHanlderAddress();
BOOL __stdcall IsPageHooked(PEPROCESS Process,PHARDWARE_PTE_X86PAE Page,BOOL bInVT,BOOL* dwSingle,DWORD *dwStepEip);
