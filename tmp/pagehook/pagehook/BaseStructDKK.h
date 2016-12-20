/***************************************************************************************
* AUTHOR : CTP
* DATE   : 2015-2-7
* MODULE : struct.h
* 
* Command: 
*   驱动的头文件
*
* Description:
*   定义一些常量,避免重复劳动; 您可以在此添加需要的函数/结构体
*
****************************************************************************************

Copyright (C) 2010 CTP.
****************************************************************************************/

#pragma once

#include <ntddk.h> 
#include <WinDef.h>
#include "ntimage.h"
//----------------------------------------------------

#define ObjectNameInformation 1

#pragma pack(1)
typedef struct _ServiceDescriptorTable 
{
	PULONG_PTR ServiceTableBase; //System Service Dispatch Table 的基地址  
	PULONG_PTR ServiceCounterTable;//包含着 SSDT 中每个服务被调用次数的计数器。这个计数器一般由sysenter 更新。 
	ULONG_PTR  NumberOfServices;//由 ServiceTableBase 描述的服务的数目。  
	PTUCHAR    ParamTableBase; //包含每个系统服务参数字节数表的基地址-系统服务参数表 
}ServiceDescriptorTable,*PServiceDescriptorTable;  
#pragma pack()

extern PServiceDescriptorTable KeServiceDescriptorTable;

NTSYSAPI BOOLEAN NTAPI KeAddSystemServiceTable ( 
	PVOID* ServiceTable, 
	ULONG_PTR Reserved, 
	ULONG_PTR Limit, 
	BYTE* Arguments, 
	ULONG_PTR NumOfDesc);

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation = 0,
	ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS {  
	SystemBasicInformation,  
	SystemProcessorInformation,  
	SystemPerformanceInformation,  
	SystemTimeOfDayInformation,  
	SystemPathInformation,  
	SystemProcessInformation, //5  
	SystemCallCountInformation,  
	SystemDeviceInformation,  
	SystemProcessorPerformanceInformation,  
	SystemFlagsInformation,  
	SystemCallTimeInformation,  
	SystemModuleInformation,  
	SystemLocksInformation,  
	SystemStackTraceInformation,  
	SystemPagedPoolInformation,  
	SystemNonPagedPoolInformation,  
	SystemHandleInformation,  
	SystemObjectInformation,  
	SystemPageFileInformation,  
	SystemVdmInstemulInformation,  
	SystemVdmBopInformation,  
	SystemFileCacheInformation,  
	SystemPoolTagInformation,  
	SystemInterruptInformation,  
	SystemDpcBehaviorInformation,  
	SystemFullMemoryInformation,  
	SystemLoadGdiDriverInformation,  
	SystemUnloadGdiDriverInformation,  
	SystemTimeAdjustmentInformation,  
	SystemSummaryMemoryInformation,  
	SystemNextEventIdInformation,  
	SystemEventIdsInformation,  
	SystemCrashDumpInformation,  
	SystemExceptionInformation,  
	SystemCrashDumpStateInformation,  
	SystemKernelDebuggerInformation,  
	SystemContextSwitchInformation,  
	SystemRegistryQuotaInformation,  
	SystemExtendServiceTableInformation,  
	SystemPrioritySeperation,  
	SystemPlugPlayBusInformation,  
	SystemDockInformation,  
	SystemPowerInformation2,  
	SystemProcessorSpeedInformation,  
	SystemCurrentTimeZoneInformation,  
	SystemLookasideInformation  
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;  


//  PEB
   
#pragma pack(4)
typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
#pragma pack() 

typedef struct _PEB_ORIG {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[229];
    PVOID Reserved3[59];
    ULONG SessionId;
} PEB_ORIG, *PPEB_ORIG;

typedef void (*PPEBLOCKROUTINE)(PVOID PebLock);

struct _PEB_FREE_BLOCK {
	struct _PEB_FREE_BLOCK *Next;
	ULONG Size;
};
typedef struct _PEB_FREE_BLOCK PEB_FREE_BLOCK;
typedef struct _PEB_FREE_BLOCK *PPEB_FREE_BLOCK;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StdInputHandle;
	HANDLE StdOutputHandle;
	HANDLE StdErrorHandle;
	UNICODE_STRING CurrentDirectoryPath;
	HANDLE CurrentDirectoryHandle;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingPositionLeft;
	ULONG StartingPositionTop;
	ULONG Width;
	ULONG Height;
	ULONG CharWidth;
	ULONG CharHeight;
	ULONG ConsoleTextAttributes;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopName;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN Spare;
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PPEBLOCKROUTINE FastPebLockRoutine;
	PPEBLOCKROUTINE FastPebUnlockRoutine;
	ULONG EnvironmentUpdateCount;
	PVOID *KernelCallbackTable;
	PVOID EventLogSection;
	PVOID EventLog;
	PPEB_FREE_BLOCK FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[0x2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID ReadOnlySharedMemoryHeap;
	PVOID *ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	BYTE Spare2[0x4];
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID **ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	PVOID GdiDCAttributeList;
	PVOID LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	ULONG OSBuildNumber;
	ULONG OSPlatformId;
	ULONG ImageSubSystem;
	ULONG ImageSubSystemMajorVersion;
	ULONG ImageSubSystemMinorVersion;
	ULONG GdiHandleBuffer[0x22];
	ULONG PostProcessInitRoutine;
	ULONG TlsExpansionBitmap;
	BYTE TlsExpansionBitmapBits[0x80];
	ULONG SessionId;
} PEB, *PPEB;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SpareUl2;
    ULONG SpareUl3;
    ULONG PeakVirtualSize;
    ULONG VirtualSize;
    ULONG PageFaultCount;
    ULONG PeakWorkingSetSize;
    ULONG WorkingSetSize;
    ULONG QuotaPeakPagedPoolUsage;
    ULONG QuotaPagedPoolUsage;
    ULONG QuotaPeakNonPagedPoolUsage;
    ULONG QuotaNonPagedPoolUsage;
    ULONG PagefileUsage;
    ULONG PeakPagefileUsage;
    ULONG PrivatePageCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef  struct _SYSTEM_THREADS
{
	LARGE_INTEGER		KernelTime;
	LARGE_INTEGER		UserTime;
	LARGE_INTEGER		CreateTime;
	ULONG				WaitTime;
	PVOID				StartAddress;
	CLIENT_ID			ClientIs;
	KPRIORITY			Priority;
	KPRIORITY			BasePriority;
	ULONG				ContextSwitchCount;
	ULONG				ThreadState;
	KWAIT_REASON		WaitReason;
}SYSTEM_THREADS,*PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES
{
	ULONG				NextEntryDelta;
	ULONG				ThreadCount;
	ULONG				Reserved[6];
	LARGE_INTEGER		CreateTime;
	LARGE_INTEGER		UserTime;
	LARGE_INTEGER		KernelTime;
	UNICODE_STRING		ProcessName;
	KPRIORITY			BasePriority;
	ULONG				ProcessId;
	ULONG				InheritedFromProcessId;
	ULONG				HandleCount;
	ULONG				Reserved2[2];
	VM_COUNTERS			VmCounters;
	IO_COUNTERS			IoCounters; //windows 2000 only
	struct _SYSTEM_THREADS	Threads[1];
}SYSTEM_PROCESSE,*PSYSTEM_PROCESSES;

typedef struct _HANDLE_TABLE_ENTRY_INFO
{
    ULONG AuditMask;
} HANDLE_TABLE_ENTRY_INFO, *PHANDLE_TABLE_ENTRY_INFO;

typedef struct _HANDLE_TABLE_ENTRY
{
    union
    {
        PVOID Object;
        ULONG_PTR ObAttributes;
        PHANDLE_TABLE_ENTRY_INFO InfoTable;
        ULONG_PTR Value;
    };
    union
    {
        ULONG GrantedAccess;
        struct
        {
            USHORT GrantedAccessIndex;
            USHORT CreatorBackTraceIndex;
        };
        LONG NextFreeTableEntry;
    };
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TABLE
{
    ULONG TableCode;
    PEPROCESS QuotaProcess;
    PVOID UniqueProcessId;
    ULONG HandleTableLock[4];
    LIST_ENTRY HandleTableList;
    ULONG HandleContentionEvent;
    PVOID DebugInfo;
    LONG ExtraInfoPages;
    ULONG FirstFree;
    ULONG LastFree;
    ULONG NextHandleNeedingPool;
    LONG HandleCount;
    union
    {
        ULONG Flags;
        UCHAR StrictFIFO:1;
    };
} HANDLE_TABLE, *PHANDLE_TABLE;

typedef struct _OBJECT_TYPE_INITIALIZER {
	USHORT Length;
	BOOLEAN UseDefaultObject;
	BOOLEAN CaseInsensitive;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	BOOLEAN MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
	PVOID DumpProcedure;
	PVOID OpenProcedure;
	PVOID CloseProcedure;
	PVOID DeleteProcedure;
	PVOID ParseProcedure;
	PVOID SecurityProcedure;
	PVOID QueryNameProcedure;
	PVOID OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;


typedef struct _OBJECT_TYPE {
	ERESOURCE Mutex;
	LIST_ENTRY TypeList;
	UNICODE_STRING Name;            // Copy from object header for convenience
	PVOID DefaultObject;
	ULONG Index;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	OBJECT_TYPE_INITIALIZER TypeInfo;
	ULONG Key;
	ERESOURCE ObjectLocks[4];
} OBJECT_TYPE, *POBJECT_TYPE;

typedef struct _OBJECT_DIRECTORY_ENTRY {
	//指向下一个OBJECT_DIRECTORY_ENTRY
	struct _OBJECT_DIRECTORY_ENTRY *ChainLink;
	//指向一个对象的对象头
	PVOID Object;
	//此对象，对象名的hash值
	//	ULONG HashValue; xp下没有这个成员，2003及之后的版本才有
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY {
    struct _OBJECT_DIRECTORY_ENTRY *HashBuckets[ 37 ];
    ULONG Lock;
    PVOID DeviceMap;
    ULONG SessionId;
	USHORT Reserved;
	USHORT SymbolicLinkUsageCount;
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

/*
typedef enum _KAPC_ENVIRONMENT {
  OriginalApcEnvironment,
  AttachedApcEnvironment,
  CurrentApcEnvironment,
  InsertApcEnvironment
} KAPC_ENVIRONMENT;
*/

typedef enum
{
    OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment
} KAPC_ENVIRONMENT;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _OBJECT_CREATE_INFORMATION {
	ULONG Attributes;
	HANDLE RootDirectory;
	PVOID ParseContext;
	KPROCESSOR_MODE ProbeMode;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG SecurityDescriptorCharge;
	PSECURITY_DESCRIPTOR SecurityDescriptor;
	PSECURITY_QUALITY_OF_SERVICE SecurityQos;
	SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_CREATE_INFORMATION, *POBJECT_CREATE_INFORMATION;

typedef struct _OBJECT_HEADER {
	union {
		struct {
			LONG PointerCount;
			LONG HandleCount;
		};
		LIST_ENTRY Entry;
	};
	POBJECT_TYPE Type;
	UCHAR NameInfoOffset;
	UCHAR HandleInfoOffset;
	UCHAR QuotaInfoOffset;
	UCHAR Flags;

	union {
		POBJECT_CREATE_INFORMATION ObjectCreateInfo;
		PVOID QuotaBlockCharged;
	};

	PSECURITY_DESCRIPTOR SecurityDescriptor;

	QUAD Body;
} OBJECT_HEADER, *POBJECT_HEADER;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY 
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT PathLength;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION_LIST, *PSYSTEM_MODULE_INFORMATION_LIST;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG       ProcessId;
	UCHAR       ObjectTypeNumber;
	UCHAR       Flags;
	USHORT      Handle;
	PVOID       Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_INFORMATION Information[];
}SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _DEBUG_OBJECT {
	KEVENT EventsPresent;
	FAST_MUTEX Mutex;
	LIST_ENTRY EventList;
	ULONG Flags;
} DEBUG_OBJECT, *PDEBUG_OBJECT;

#define PS_CROSS_THREAD_FLAGS_TERMINATED           0x00000001UL

#define DISPATCHER_OBJECT_TYPE_MASK 0x7

typedef enum _KOBJECTS {
	EventNotificationObject = 0,
	EventSynchronizationObject = 1,
	MutantObject = 2,
	ProcessObject = 3,
	QueueObject = 4,
	SemaphoreObject = 5,
	ThreadObject = 6,
	GateObject = 7,
	TimerNotificationObject = 8,
	TimerSynchronizationObject = 9,
	Spare2Object = 10,
	Spare3Object = 11,
	Spare4Object = 12,
	Spare5Object = 13,
	Spare6Object = 14,
	Spare7Object = 15,
	Spare8Object = 16,
	Spare9Object = 17,
	ApcObject,
	DpcObject,
	DeviceQueueObject,
	EventPairObject,
	InterruptObject,
	ProfileObject,
	ThreadedDpcObject,
	MaximumKernelObject
} KOBJECTS;

#define KOBJECT_LOCK_BIT 0x80
#define KOBJECT_LOCK_BIT_NUMBER 7
#define KOBJECT_TYPE_MASK 0x7f
#define ASSERT_THREAD(object) ASSERT((object)->Header.Type == ThreadObject)


#define PcTeb 0x18
#define PcKprcb 0x20

#define EXCEPTION_BREAKPOINT                STATUS_BREAKPOINT //断点
#define EXCEPTION_SINGLE_STEP               STATUS_SINGLE_STEP //单步执行
#define EXCEPTION_ACCESS_VIOLATION          STATUS_ACCESS_VIOLATION //访问违规

//调试事件
#define DEBUG_EVENT_READ            (0x01)
#define DEBUG_EVENT_NOWAIT          (0x02)
#define DEBUG_EVENT_INACTIVE        (0x04)
#define DEBUG_EVENT_RELEASE         (0x08)
#define DEBUG_EVENT_PROTECT_FAILED  (0x10)
#define DEBUG_EVENT_SUSPEND         (0x20)

//调试对象属性
#define DEBUG_OBJECT_DELETE_PENDING (0x1)
#define DEBUG_OBJECT_KILL_ON_CLOSE  (0x2)

#define PS_PROCESS_FLAGS_PROCESS_DELETE         0x00000008UL
#define PS_PROCESS_FLAGS_CREATE_REPORTED        0x00000001UL
#define PS_PROCESS_FLAGS_NO_DEBUG_INHERIT       0x00000002UL
#define PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE      0x00400000UL

#define DEBUG_KILL_ON_CLOSE  (0x1)
#define DEBUG_READ_EVENT        (0x0001)
#define DEBUG_PROCESS_ASSIGN    (0x0002)
#define DEBUG_SET_INFORMATION   (0x0004)

#define PROCESS_VM_READ           (0x0010)
#define PROCESS_VM_WRITE          (0x0020)
#define PROCESS_SET_PORT          (0x0800)
#define PROCESS_TERMINATE         (0x0001)
#define PROCESS_VM_OPERATION      (0x0008)
#define PROCESS_CREATE_THREAD     (0x0002)
#define PROCESS_SET_INFORMATION   (0x0200)
#define PROCESS_QUERY_INFORMATION (0x0400)

#define THREAD_GET_CONTEXT             (0x0008)
#define THREAD_SET_CONTEXT             (0x0010)
#define THREAD_SUSPEND_RESUME          (0x0002)
#define THREAD_QUERY_INFORMATION       (0x0040)

#define LPC_EXCEPTION           7
#define LPC_DEBUG_EVENT         8
#define LPC_MAX_CONNECTION_INFO_SIZE (16 * sizeof(ULONG_PTR))

#define POOL_QUOTA_FAIL_INSTEAD_OF_RAISE 8

#define PS_CROSS_THREAD_FLAGS_DEADTHREAD           0x00000002UL
#define PS_CROSS_THREAD_FLAGS_HIDEFROMDBG          0x00000004UL
#define PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG    0x00000080UL
#define PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG 0x00000100UL

#define PORT_MAXIMUM_MESSAGE_LENGTH 256

#define PORT_TOTAL_MAXIMUM_MESSAGE_LENGTH ((PORT_MAXIMUM_MESSAGE_LENGTH + sizeof (PORT_MESSAGE) + LPC_MAX_CONNECTION_INFO_SIZE + 15) & ~15)

#define PS_TEST_SET_BITS(Flags, Flag) \
	RtlInterlockedSetBits(Flags, Flag)

#define DBGKM_MSG_OVERHEAD \
	(FIELD_OFFSET(DBGKM_APIMSG, u.Exception) - sizeof(PORT_MESSAGE))

#define DBGKM_API_MSG_LENGTH(TypeSize) \
	((sizeof(DBGKM_APIMSG) << 16) | (DBGKM_MSG_OVERHEAD + (TypeSize)))

#define DBGKM_FORMAT_API_MSG(m,Number,TypeSize)             \
	(m).h.u1.Length = DBGKM_API_MSG_LENGTH((TypeSize));     \
	(m).h.u2.ZeroInit = LPC_DEBUG_EVENT;                    \
	(m).ApiNumber = (Number)

#define DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(hdrs,field) \
	((hdrs)->OptionalHeader.##field)

#define PS_SET_BITS(Flags, Flag) \
	RtlInterlockedSetBitsDiscardReturn(Flags, Flag)

#define PS_CROSS_THREAD_FLAGS_SYSTEM               0x00000010UL

#define IS_SYSTEM_THREAD(Thread)  (((Thread)->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SYSTEM) != 0)

#define ProbeForWriteHandle(Address) {                                   \
	if ((Address) >= (HANDLE * const)MM_USER_PROBE_ADDRESS) {                \
	*(volatile HANDLE * const)MM_USER_PROBE_ADDRESS = 0;                     \
	}                                                                        \
	\
	*(volatile HANDLE *)(Address) = *(volatile HANDLE *)(Address);           \
	}

#define ProbeForWriteUlong(Address) {                                     \
	if ((Address) >= (ULONG * const)MM_USER_PROBE_ADDRESS) {	          \
	*(volatile ULONG * const)MM_USER_PROBE_ADDRESS = 0;               \
	}                                                                     \
	\
	*(volatile ULONG *)(Address) = *(volatile ULONG *)(Address);          \
	}

#define ProbeForReadSmallStructure(Address, Size, Alignment) {           \
	ASSERT(((Alignment) == 1) || ((Alignment) == 2) || \
	((Alignment) == 4) || ((Alignment) == 8) || \
	((Alignment) == 16));                                                \
	if ((Size == 0) || (Size > 0x10000)) {\
	ASSERT(0);                                                           \
	ProbeForRead(Address, Size, Alignment);                              \
	}else {	\
	if (((ULONG_PTR)(Address)& ((Alignment)-1)) != 0) {		\
	ExRaiseDatatypeMisalignment();                                       \
	}                                                                    \
	if ((ULONG_PTR)(Address) >= (ULONG_PTR)MM_USER_PROBE_ADDRESS) {		\
	*(volatile UCHAR * const)MM_USER_PROBE_ADDRESS = 0;                  \
	}                                                                    \
	}                                                                        \
	}

typedef struct _KGDTENTRY {
	USHORT  LimitLow;
	USHORT  BaseLow;
	union {
		struct {
			UCHAR   BaseMid;
			UCHAR   Flags1;
			UCHAR   Flags2;
			UCHAR   BaseHi;
		} Bytes;
		struct {
			ULONG   BaseMid : 8;
			ULONG   Type : 5;
			ULONG   Dpl : 2;
			ULONG   Pres : 1;
			ULONG   LimitHi : 4;
			ULONG   Sys : 1;
			ULONG   Reserved_0 : 1;
			ULONG   Default_Big : 1;
			ULONG   Granularity : 1;
			ULONG   BaseHi : 8;
		} Bits;
	} HighWord;
} KGDTENTRY, *PKGDTENTRY;

typedef struct _KIDTENTRY {
	USHORT Offset;
	USHORT Selector;
	USHORT Access;
	USHORT ExtendedOffset;
} KIDTENTRY, *PKIDTENTRY;

typedef struct _KEXECUTE_OPTIONS {
	UCHAR ExecuteDisable : 1;
	UCHAR ExecuteEnable : 1;
	UCHAR DisableThunkEmulation : 1;
	UCHAR Permanent : 1;
	UCHAR ExecuteDispatchEnable : 1;
	UCHAR ImageDispatchEnable : 1;
	UCHAR Spare : 2;
} KEXECUTE_OPTIONS, *PKEXECUTE_OPTIONS;

typedef struct _KPROCESS {
	DISPATCHER_HEADER Header;
	LIST_ENTRY ProfileListHead;
	ULONG DirectoryTableBase[2];
	KGDTENTRY LdtDescriptor;
	KIDTENTRY Int21Descriptor;
	USHORT IopmOffset;
	UCHAR Iopl;
	UCHAR Unused;
	ULONG ActiveProcessors;
	ULONG KernelTime;
	ULONG UserTime;
	LIST_ENTRY ReadyListHead;
	SINGLE_LIST_ENTRY SwapListEntry;
	PVOID VdmTrapcHandler;
	LIST_ENTRY ThreadListHead;
	ULONG ProcessLock;
	ULONG Affinity;
	USHORT StackCount;
	char BasePriority;
	char ThreadQuantum;
	UCHAR AutoAlignment;
	UCHAR State;
	UCHAR ThreadSeed;
	UCHAR DisableBoost;
	UCHAR PowerState;
	UCHAR DisableQuantum;
	UCHAR IdealNode;
	union {
		KEXECUTE_OPTIONS Flags;
		UCHAR ExecuteOptions;
	};
} KPROCESS, *PKPROCESS, *PRKPROCESS;

typedef struct _EX_PUSH_LOCK {
#define EX_PUSH_LOCK_LOCK_V          ((ULONG_PTR)0x0)
#define EX_PUSH_LOCK_LOCK            ((ULONG_PTR)0x1)
#define EX_PUSH_LOCK_WAITING         ((ULONG_PTR)0x2)
#define EX_PUSH_LOCK_WAKING          ((ULONG_PTR)0x4)
#define EX_PUSH_LOCK_MULTIPLE_SHARED ((ULONG_PTR)0x8)
#define EX_PUSH_LOCK_SHARE_INC       ((ULONG_PTR)0x10)
#define EX_PUSH_LOCK_PTR_BITS        ((ULONG_PTR)0xf)
	union {
		struct {
			ULONG_PTR Waiting : 1;
			ULONG_PTR Exclusive : 1;
			ULONG_PTR Shared : 30;
		};
		ULONG_PTR Value;
		PVOID Ptr;
	};
} EX_PUSH_LOCK, *PEX_PUSH_LOCK;

#define HANDLE_TRACE_DB_MAX_STACKS 65536
#define HANDLE_TRACE_DB_MIN_STACKS 128
#define HANDLE_TRACE_DB_DEFAULT_STACKS 4096
#define HANDLE_TRACE_DB_STACK_SIZE 16

typedef struct _HANDLE_TRACE_DB_ENTRY {
	CLIENT_ID ClientId;
	HANDLE Handle;
#define HANDLE_TRACE_DB_OPEN    1
#define HANDLE_TRACE_DB_CLOSE   2
#define HANDLE_TRACE_DB_BADREF  3
	ULONG Type;
	PVOID StackTrace[HANDLE_TRACE_DB_STACK_SIZE];
} HANDLE_TRACE_DB_ENTRY, *PHANDLE_TRACE_DB_ENTRY;

typedef struct _HANDLE_TRACE_DEBUG_INFO {
#define HANDLE_TRACE_DEBUG_INFO_CLEAN_DEBUG_INFO        0x1
#define HANDLE_TRACE_DEBUG_INFO_COMPACT_CLOSE_HANDLE    0x2
#define HANDLE_TRACE_DEBUG_INFO_BREAK_ON_WRAP_AROUND    0x4
#define HANDLE_TRACE_DEBUG_INFO_WAS_WRAPPED_AROUND      0x40000000
#define HANDLE_TRACE_DEBUG_INFO_WAS_SOMETIME_CLEANED    0x80000000
	ULONG CurrentStackIndex;
	HANDLE_TRACE_DB_ENTRY TraceDb[1];
} HANDLE_TRACE_DEBUG_INFO, *PHANDLE_TRACE_DEBUG_INFO;

typedef struct _EX_FAST_REF {
	union {
		PVOID Object;
		ULONG_PTR RefCnt : 3;
		ULONG_PTR Value;
	};
} EX_FAST_REF, *PEX_FAST_REF;

typedef struct _SID_AND_ATTRIBUTES {
	PVOID Sid;
	ULONG Attributes;
} SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;

typedef struct _PS_JOB_TOKEN_FILTER {
	ULONG CapturedSidCount;
	PSID_AND_ATTRIBUTES CapturedSids;
	ULONG CapturedSidsLength;
	ULONG CapturedGroupCount;
	PSID_AND_ATTRIBUTES CapturedGroups;
	ULONG CapturedGroupsLength;
	ULONG CapturedPrivilegeCount;
	PLUID_AND_ATTRIBUTES CapturedPrivileges;
	ULONG CapturedPrivilegesLength;
} PS_JOB_TOKEN_FILTER, *PPS_JOB_TOKEN_FILTER;
typedef struct _EJOB {
	KEVENT Event;
	LIST_ENTRY JobLinks;
	LIST_ENTRY ProcessListHead;
	ERESOURCE JobLock;
	LARGE_INTEGER TotalUserTime;
	LARGE_INTEGER TotalKernelTime;
	LARGE_INTEGER ThisPeriodTotalUserTime;
	LARGE_INTEGER ThisPeriodTotalKernelTime;
	ULONG TotalPageFaultCount;
	ULONG TotalProcesses;
	ULONG ActiveProcesses;
	ULONG TotalTerminatedProcesses;
	LARGE_INTEGER PerProcessUserTimeLimit;
	LARGE_INTEGER PerJobUserTimeLimit;
	ULONG LimitFlags;
	ULONG MinimumWorkingSetSize;
	ULONG MaximumWorkingSetSize;
	ULONG ActiveProcessLimit;
	KAFFINITY Affinity;
	UCHAR PriorityClass;
	ULONG UIRestrictionsClass;
	ULONG SecurityLimitFlags;
	PVOID Token;
	PPS_JOB_TOKEN_FILTER Filter;
	ULONG EndOfJobTimeAction;
	PVOID CompletionPort;
	PVOID CompletionKey;
	ULONG SessionId;
	ULONG SchedulingClass;
	ULONGLONG ReadOperationCount;
	ULONGLONG WriteOperationCount;
	ULONGLONG OtherOperationCount;
	ULONGLONG ReadTransferCount;
	ULONGLONG WriteTransferCount;
	ULONGLONG OtherTransferCount;
	IO_COUNTERS IoInfo;
	ULONG ProcessMemoryLimit;
	ULONG JobMemoryLimit;
	ULONG PeakProcessMemoryUsed;
	ULONG PeakJobMemoryUsed;
	ULONG CurrentJobMemoryUsed;
	FAST_MUTEX MemoryLimitsLock;
	LIST_ENTRY JobSetLinks;
	ULONG MemberLevel;
#define PS_JOB_FLAGS_CLOSE_DONE 0x1UL
	ULONG JobFlags;
} EJOB, *PEJOB;

typedef struct _EPROCESS_QUOTA_ENTRY {
	ULONG Usage;
	ULONG Limit;
	ULONG Peak;
	ULONG Return;
} EPROCESS_QUOTA_ENTRY, *PEPROCESS_QUOTA_ENTRY;

typedef struct _EPROCESS_QUOTA_BLOCK {
	EPROCESS_QUOTA_ENTRY QuotaEntry[3];
	LIST_ENTRY QuotaList;
	ULONG ReferenceCount;
	ULONG ProcessCount;
} EPROCESS_QUOTA_BLOCK, *PEPROCESS_QUOTA_BLOCK;
typedef struct _PAGEFAULT_HISTORY {
	ULONG CurrentIndex;
	ULONG MaxIndex;
	ULONG SpinLock;
	PVOID Reserved;
	PROCESS_WS_WATCH_INFORMATION WatchInfo[1];
} PAGEFAULT_HISTORY, *PPAGEFAULT_HISTORY;

typedef struct _HARDWARE_PTE {
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
			ULONGLONG CopyOnWrite : 1;
			ULONGLONG Prototype : 1;
			ULONGLONG reserved0 : 1;
			ULONGLONG PageFrameNumber : 26;
			ULONGLONG reserved1 : 26;
		};
		struct {
			ULONG LowPart;
			ULONG HighPart;
		};
	};
} HARDWARE_PTE, *PHARDWARE_PTE;

typedef struct _SE_AUDIT_PROCESS_CREATION_INFO {
	POBJECT_NAME_INFORMATION ImageFileName;
} SE_AUDIT_PROCESS_CREATION_INFO, *PSE_AUDIT_PROCESS_CREATION_INFO;

typedef struct _MMSUPPORT_FLAGS {
	ULONG SessionSpace : 1;
	ULONG BeingTrimmed : 1;
	ULONG SessionLeader : 1;
	ULONG TrimHard : 1;
	ULONG WorkingSetHard : 1;
	ULONG AddressSpaceBeingDeleted : 1;
	ULONG Available : 10;
	ULONG AllowWorkingSetAdjustment : 8;
	ULONG MemoryPriority : 8;
} MMSUPPORT_FLAGS;

typedef struct _MMWSLENTRY {
	ULONG Valid : 1;
	ULONG LockedInWs : 1;
	ULONG LockedInMemory : 1;
	ULONG Protection : 5;
	ULONG Hashed : 1;
	ULONG Direct : 1;
	ULONG Age : 2;
	ULONG VirtualPageNumber : 20;
} MMWSLENTRY, *PMMWSLENTRY;
typedef struct _MMWSLE {
	union {
		PVOID VirtualAddress;
		ULONG_PTR Long;
		MMWSLENTRY e1;
	} u1;
} MMWSLE, *PMMWSLE;

typedef struct _MMWSLE_HASH {
	PVOID Key;
	ULONG Index;
} MMWSLE_HASH, *PMMWSLE_HASH;

typedef struct _MMWSL {
	ULONG Quota;
	ULONG FirstFree;
	ULONG FirstDynamic;
	ULONG LastEntry;
	ULONG NextSlot;
	PMMWSLE Wsle;
	ULONG LastInitializedWsle;
	ULONG NonDirectCount;
	PMMWSLE_HASH HashTable;
	ULONG HashTableSize;
	ULONG NumberOfCommittedPageTables;
	PVOID HashTableStart;
	PVOID HighestPermittedHashAddress;
	ULONG NumberOfImageWaiters;
	ULONG VadBitMapHint;
	USHORT UsedPageTableEntries[1536];
	ULONG CommittedPageTables[48];
} MMWSL, *PMMWSL;

typedef struct _MMSUPPORT {
	LARGE_INTEGER LastTrimTime;
	MMSUPPORT_FLAGS Flags;
	ULONG PageFaultCount;
	ULONG PeakWorkingSetSize;
	ULONG WorkingSetSize;
	ULONG MinimumWorkingSetSize;
	ULONG MaximumWorkingSetSize;
	PMMWSL VmWorkingSetList;
	LIST_ENTRY WorkingSetExpansionLinks;
	ULONG Claim;
	ULONG NextEstimationSlot;
	ULONG NextAgingSlot;
	ULONG EstimatedAvailable;
	ULONG GrowthSinceLastEstimate;
} MMSUPPORT, *PMMSUPPORT;
typedef struct _CURDIR {
	UNICODE_STRING DosPath;
	PVOID Handle;
} CURDIR, *PCURDIR;


typedef struct _RTL_CRITICAL_SECTION_DEBUG {
	USHORT Type;
	USHORT CreatorBackTraceIndex;
	struct _RTL_CRITICAL_SECTION *CriticalSection;
	LIST_ENTRY ProcessLocksList;
	ULONG EntryCount;
	ULONG ContentionCount;
	ULONG Spare[2];
} RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION {
	PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
	LONG LockCount;
	LONG RecursionCount;
	PVOID OwningThread;
	PVOID LockSemaphore;
	ULONG SpinCount;
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;


typedef struct _ACTIVATION_CONTEXT_STACK {
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	PVOID ActiveFrame;
	LIST_ENTRY FrameListCache;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH {
	ULONG Offset;
	ULONG HDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _Wx86ThreadState {
	PULONG CallBx86Eip;
	PVOID DeallocationCpu;
	UCHAR UseKnownWx86Dll;
	char OleStubInvoked;
} Wx86ThreadState, *PWx86ThreadState;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
	ULONG Flags;
	PCHAR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME *Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

typedef struct _TEB {
	NT_TIB NtTib;
	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;
	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	ULONG CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	PVOID SystemReserved1[54];
	LONG ExceptionCode;
	ACTIVATION_CONTEXT_STACK ActivationContextStack;
	UCHAR SpareBytes1[24];
	GDI_TEB_BATCH GdiTebBatch;
	CLIENT_ID RealClientId;
	PVOID GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocalInfo;
	ULONG Win32ClientInfo[62];
	PVOID glDispatchTable[233];
	ULONG glReserved1[29];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;
	ULONG LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	USHORT StaticUnicodeBuffer[261];
	PVOID DeallocationStack;
	PVOID TlsSlots[64];
	LIST_ENTRY TlsLinks;
	PVOID Vdm;
	PVOID ReservedForNtRpc;
	PVOID DbgSsReserved[2];
	ULONG HardErrorsAreDisabled;
	PVOID Instrumentation[16];
	PVOID WinSockData;
	ULONG GdiBatchCount;
	UCHAR InDbgPrint;
	UCHAR FreeStackOnTermination;
	UCHAR HasFiberData;
	UCHAR IdealProcessor;
	ULONG Spare3;
	PVOID ReservedForPerf;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	Wx86ThreadState Wx86Thread;
	PVOID *TlsExpansionSlots;
	ULONG ImpersonationLocale;
	ULONG IsImpersonating;
	PVOID NlsCache;
	PVOID pShimData;
	ULONG HeapVirtualAffinity;
	PVOID CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME ActiveFrame;
	UCHAR SafeThunkCall;
	UCHAR BooleanSpare[3];
} TEB, *PTEB;

typedef struct _EPROCESS {
	KPROCESS Pcb;
	EX_PUSH_LOCK ProcessLock;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER ExitTime;
	EX_RUNDOWN_REF RundownProtect;
	HANDLE UniqueProcessId;
	LIST_ENTRY ActiveProcessLinks;
	ULONG QuotaUsage[3];
	ULONG QuotaPeak[3];
	ULONG CommitCharge;
	ULONG PeakVirtualSize;
	ULONG VirtualSize;
	LIST_ENTRY SessionProcessLinks;
	PVOID DebugPort;
	PVOID ExceptionPort;
	PHANDLE_TABLE ObjectTable;
	EX_FAST_REF Token;
	FAST_MUTEX WorkingSetLock;
	ULONG WorkingSetPage;
	FAST_MUTEX AddressCreationLock;
	ULONG HyperSpaceLock;
	PETHREAD ForkInProgress;
	ULONG HardwareTrigger;
	PVOID VadRoot;
	PVOID VadHint;
	PVOID CloneRoot;
	ULONG NumberOfPrivatePages;
	ULONG NumberOfLockedPages;
	PVOID Win32Process;
	PEJOB Job;
	PVOID SectionObject;
	PVOID SectionBaseAddress;
	PEPROCESS_QUOTA_BLOCK QuotaBlock;
	PPAGEFAULT_HISTORY WorkingSetWatch;
	PVOID Win32WindowStation;
	PVOID InheritedFromUniqueProcessId;
	PVOID LdtInformation;
	PVOID VadFreeHint;
	PVOID VdmObjects;
	PVOID DeviceMap;
	LIST_ENTRY PhysicalVadList;
	union {
		HARDWARE_PTE PageDirectoryPte;
		ULONG64 Filler;
	};
	PVOID Session;
	UCHAR ImageFileName[16];
	LIST_ENTRY JobLinks;
	PVOID LockedPagesList;
	LIST_ENTRY ThreadListHead;
	PVOID SecurityPort;
	PVOID PaeTop;
	ULONG ActiveThreads;
	ULONG GrantedAccess;
	ULONG DefaultHardErrorProcessing;
	NTSTATUS LastThreadExitStatus;
	PPEB Peb;
	EX_FAST_REF PrefetchTrace;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	ULONG CommitChargeLimit;
	ULONG CommitChargePeak;
	PVOID AweInfo;
	SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;
	MMSUPPORT Vm;
	ULONG LastFaultCount;
	ULONG ModifiedPageCount;
	ULONG NumberOfVads;
	ULONG JobStatus;
	union {
		ULONG Flags;
		struct {
			ULONG CreateReported : 1;
			ULONG NoDebugInherit : 1;
			ULONG ProcessExiting : 1;
			ULONG ProcessDelete : 1;
			ULONG Wow64SplitPages : 1;
			ULONG VmDeleted : 1;
			ULONG OutswapEnabled : 1;
			ULONG Outswapped : 1;
			ULONG ForkFailed : 1;
			ULONG HasPhysicalVad : 1;
			ULONG AddressSpaceInitialized : 2;
			ULONG SetTimerResolution : 1;
			ULONG BreakOnTermination : 1;
			ULONG SessionCreationUnderway : 1;
			ULONG WriteWatch : 1;
			ULONG ProcessInSession : 1;
			ULONG OverrideAddressSpace : 1;
			ULONG HasAddressSpace : 1;
			ULONG LaunchPrefetched : 1;
			ULONG InjectInpageErrors : 1;
			ULONG VmTopDown : 1;
			ULONG Unused3 : 1;
			ULONG Unused4 : 1;
			ULONG VdmAllowed : 1;
			ULONG Unused : 5;
			ULONG Unused1 : 1;
			ULONG Unused2 : 1;
		};
	};
	NTSTATUS ExitStatus;
	USHORT NextPageColor;
	union {
		struct {
			UCHAR SubSystemMinorVersion;
			UCHAR SubSystemMajorVersion;
		};
		USHORT SubSystemVersion;
	};
	UCHAR PriorityClass;
	UCHAR WorkingSetAcquiredUnsafe;
	ULONG Cookie;
} EPROCESS;

typedef struct _KQUEUE {
	DISPATCHER_HEADER Header;
	LIST_ENTRY EntryListHead;
	ULONG CurrentCount;
	ULONG MaximumCount;
	LIST_ENTRY ThreadListHead;
} KQUEUE, *PKQUEUE;

typedef struct _KTRAP_FRAME {
	ULONG DbgEbp;
	ULONG DbgEip;
	ULONG DbgArgMark;
	ULONG DbgArgPointer;
	ULONG TempSegCs;
	ULONG TempEsp;
	ULONG Dr0;
	ULONG Dr1;
	ULONG Dr2;
	ULONG Dr3;
	ULONG Dr6;
	ULONG Dr7;
	ULONG SegGs;
	ULONG SegEs;
	ULONG SegDs;
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;
	ULONG PreviousPreviousMode;
	PEXCEPTION_REGISTRATION_RECORD ExceptionList;
	ULONG SegFs;
	ULONG Edi;
	ULONG Esi;
	ULONG Ebx;
	ULONG Ebp;
	ULONG ErrCode;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG HardwareEsp;
	ULONG HardwareSegSs;
	ULONG V86Es;
	ULONG V86Ds;
	ULONG V86Fs;
	ULONG V86Gs;
} KTRAP_FRAME, *PKTRAP_FRAME;

typedef KTRAP_FRAME *PKEXCEPTION_FRAME;

typedef struct _TERMINATION_PORT {
	struct _TERMINATION_PORT *Next;
	PVOID Port;
} TERMINATION_PORT, *PTERMINATION_PORT;
typedef struct _KAPC_STATE {
	LIST_ENTRY ApcListHead[2];
	struct _KPROCESS *Process;
	UCHAR KernelApcInProgress;
	UCHAR KernelApcPending;
	UCHAR UserApcPending;
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;
typedef struct _KTHREAD {
	DISPATCHER_HEADER Header;
	LIST_ENTRY MutantListHead;
	PVOID InitialStack;
	PVOID StackLimit;
	PVOID Teb;
	PVOID TlsArray;
	PVOID KernelStack;
	UCHAR DebugActive;
	UCHAR State;
	UCHAR Alerted[2];
	UCHAR Iopl;
	UCHAR NpxState;
	char Saturation;
	char Priority;
	KAPC_STATE ApcState;
	ULONG ContextSwitches;
	UCHAR IdleSwapBlock;
	UCHAR VdmSafe;
	UCHAR Spare0[2];
	NTSTATUS WaitStatus;
	UCHAR WaitIrql;
	char WaitMode;
	UCHAR WaitNext;
	UCHAR WaitReason;
	PKWAIT_BLOCK WaitBlockList;
	union {
		LIST_ENTRY WaitListEntry;
		SINGLE_LIST_ENTRY SwapListEntry;
	};
	ULONG WaitTime;
	char BasePriority;
	UCHAR DecrementCount;
	char PriorityDecrement;
	char Quantum;
	KWAIT_BLOCK WaitBlock[4];
	PVOID LegoData;
	ULONG KernelApcDisable;
	ULONG UserAffinity;
	UCHAR SystemAffinityActive;
	UCHAR PowerState;
	UCHAR NpxIrql;
	UCHAR InitialNode;
	PVOID ServiceTable;
	PKQUEUE Queue;
	ULONG ApcQueueLock;
	KTIMER Timer;
	LIST_ENTRY QueueListEntry;
	ULONG SoftAffinity;
	ULONG Affinity;
	UCHAR Preempted;
	UCHAR ProcessReadyQueue;
	UCHAR KernelStackResident;
	UCHAR NextProcessor;
	PVOID CallbackStack;
	PVOID Win32Thread;
	PKTRAP_FRAME TrapFrame;
	PKAPC_STATE ApcStatePointer[2];
	char PreviousMode;
	UCHAR EnableStackSwap;
	UCHAR LargeStack;
	UCHAR ResourceIndex;
	ULONG KernelTime;
	ULONG UserTime;
	KAPC_STATE SavedApcState;
	UCHAR Alertable;
	UCHAR ApcStateIndex;
	UCHAR ApcQueueable;
	UCHAR AutoAlignment;
	PVOID StackBase;
	KAPC SuspendApc;
	KSEMAPHORE SuspendSemaphore;
	LIST_ENTRY ThreadListEntry;
	char FreezeCount;
	char SuspendCount;
	UCHAR IdealProcessor;
	UCHAR DisableBoost;
} KTHREAD;

typedef struct _PS_IMPERSONATION_INFORMATION {
	PVOID Token;
	UCHAR CopyOnOpen;
	UCHAR EffectiveOnly;
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
} PS_IMPERSONATION_INFORMATION, *PPS_IMPERSONATION_INFORMATION;
typedef struct _ETHREAD {
	KTHREAD Tcb;
	union {
		LARGE_INTEGER CreateTime;
		struct {
			UCHAR NestedFaultCount : 2;
			UCHAR ApcNeeded : 1;
		};
	};
	union {
		LARGE_INTEGER ExitTime;
		LIST_ENTRY LpcReplyChain;
		LIST_ENTRY KeyedWaitChain;
	};
	union {
		NTSTATUS ExitStatus;
		PVOID OfsChain;
	};
	LIST_ENTRY PostBlockList;
	union {
		PTERMINATION_PORT TerminationPort;
		PETHREAD ReaperLink;
		PVOID KeyedWaitValue;
	};
	ULONG ActiveTimerListLock;
	LIST_ENTRY ActiveTimerListHead;
	CLIENT_ID Cid;
	union {
		KSEMAPHORE LpcReplySemaphore;
		KSEMAPHORE KeyedWaitSemaphore;
	};
	union {
		PVOID LpcReplyMessage;
		PVOID LpcWaitingOnPort;
	};
	PPS_IMPERSONATION_INFORMATION ImpersonationInfo;
	LIST_ENTRY IrpList;
	ULONG TopLevelIrp;
	PDEVICE_OBJECT DeviceToVerify;
	PEPROCESS ThreadsProcess;
	PVOID StartAddress;
	union {
		PVOID Win32StartAddress;
		ULONG LpcReceivedMessageId;
	};
	LIST_ENTRY ThreadListEntry;
	EX_RUNDOWN_REF RundownProtect;
	EX_PUSH_LOCK ThreadLock;
	ULONG LpcReplyMessageId;
	ULONG ReadClusterSize;
	ULONG GrantedAccess;
	union {
		ULONG CrossThreadFlags;
		struct {
			ULONG Terminated : 1;
			ULONG DeadThread : 1;
			ULONG HideFromDebugger : 1;
			ULONG ActiveImpersonationInfo : 1;
			ULONG SystemThread : 1;
			ULONG HardErrorsAreDisabled : 1;
			ULONG BreakOnTermination : 1;
			ULONG SkipCreationMsg : 1;
			ULONG SkipTerminationMsg : 1;
		};
	};
	union {
		ULONG SameThreadPassiveFlags;
		struct {
			ULONG ActiveExWorker : 1;
			ULONG ExWorkerCanWaitUser : 1;
			ULONG MemoryMaker : 1;
		};
	};
	union {
		ULONG SameThreadApcFlags;
		struct {
			ULONG LpcReceivedMsgIdValid : 1;
			ULONG LpcExitThreadCalled : 1;
			ULONG AddressSpaceOwner : 1;
		};
	};
	UCHAR ForwardClusterOnly;
	UCHAR DisablePageFaultClustering;
	ULONG KernelStackReference;
} ETHREAD;
typedef struct _PORT_MESSAGE {
	union {
		struct {
			CSHORT DataLength;
			CSHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union {
		struct {
			CSHORT Type;
			CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union {
		CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG MessageId;
	union {
		ULONG ClientViewSize;
		ULONG CallbackId;
	};
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef enum _DBGKM_APINUMBER {
	DbgKmExceptionApi,
	DbgKmCreateThreadApi,
	DbgKmCreateProcessApi,
	DbgKmExitThreadApi,
	DbgKmExitProcessApi,
	DbgKmLoadDllApi,
	DbgKmUnloadDllApi,
	DbgKmMaxApiNumber
} DBGKM_APINUMBER;

typedef struct _DBGKM_EXCEPTION {
	EXCEPTION_RECORD ExceptionRecord;
	ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD {
	ULONG SubSystemKey;
	PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS {
	ULONG SubSystemKey;
	HANDLE FileHandle;
	PVOID BaseOfImage;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD {
	NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS {
	NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL {
	HANDLE FileHandle;
	PVOID BaseOfDll;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL {
	PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;
typedef struct _DBGKM_APIMSG {
	PORT_MESSAGE h;
	DBGKM_APINUMBER ApiNumber;
	NTSTATUS ReturnedStatus;
	union {
		DBGKM_EXCEPTION Exception;
		DBGKM_CREATE_THREAD CreateThread;
		DBGKM_CREATE_PROCESS CreateProcessInfo;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	} u;
} DBGKM_APIMSG, *PDBGKM_APIMSG;

typedef struct _DEBUG_EVENT {
	LIST_ENTRY EventList;
	KEVENT ContinueEvent;
	CLIENT_ID ClientId;
	PEPROCESS Process;
	PETHREAD Thread;
	NTSTATUS Status;
	ULONG Flags;
	PETHREAD BackoutThread;
	DBGKM_APIMSG ApiMsg;
} DEBUG_EVENT, *PDEBUG_EVENT;

typedef enum _DBG_STATE {
	DbgIdle,
	DbgReplyPending,
	DbgCreateThreadStateChange,
	DbgCreateProcessStateChange,
	DbgExitThreadStateChange,
	DbgExitProcessStateChange,
	DbgExceptionStateChange,
	DbgBreakpointStateChange,
	DbgSingleStepStateChange,
	DbgLoadDllStateChange,
	DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

typedef struct _DBGUI_CREATE_THREAD {
	HANDLE HandleToThread;
	DBGKM_CREATE_THREAD NewThread;
} DBGUI_CREATE_THREAD, *PDBGUI_CREATE_THREAD;

typedef struct _DBGUI_CREATE_PROCESS {
	HANDLE HandleToProcess;
	HANDLE HandleToThread;
	DBGKM_CREATE_PROCESS NewProcess;
} DBGUI_CREATE_PROCESS, *PDBGUI_CREATE_PROCESS;

typedef struct _DBGUI_WAIT_STATE_CHANGE {
	DBG_STATE NewState;
	CLIENT_ID AppClientId;
	union {
		DBGKM_EXCEPTION Exception;
		DBGUI_CREATE_THREAD CreateThread;
		DBGUI_CREATE_PROCESS CreateProcessInfo;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	} StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;

typedef enum _DEBUGOBJECTINFOCLASS {
	DebugObjectFlags = 1,
	MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;
typedef struct _FNSAVE_FORMAT {
	ULONG ControlWord;
	ULONG StatusWord;
	ULONG TagWord;
	ULONG ErrorOffset;
	ULONG ErrorSelector;
	ULONG DataOffset;
	ULONG DataSelector;
	UCHAR RegisterArea[80];
} FNSAVE_FORMAT, *PFNSAVE_FORMAT;

typedef struct _FXSAVE_FORMAT {
	USHORT ControlWord;
	USHORT StatusWord;
	USHORT TagWord;
	USHORT ErrorOpcode;
	ULONG ErrorOffset;
	ULONG ErrorSelector;
	ULONG DataOffset;
	ULONG DataSelector;
	ULONG MXCsr;
	ULONG MXCsrMask;
	UCHAR RegisterArea[128];
	UCHAR Reserved3[128];
	UCHAR Reserved4[224];
	UCHAR Align16Byte[8];
} FXSAVE_FORMAT, *PFXSAVE_FORMAT;

typedef struct _FX_SAVE_AREA {
	union {
		FNSAVE_FORMAT FnArea;
		FXSAVE_FORMAT FxArea;
	} U;
	ULONG NpxSavedCpu;
	ULONG Cr0NpxState;
} FX_SAVE_AREA, *PFX_SAVE_AREA;

typedef struct _PP_LOOKASIDE_LIST {
	PVOID Pgl;
	PVOID Lgl;
} PP_LOOKASIDE_LIST, *PPP_LOOKASIDE_LIST;

typedef struct _DESCRIPTOR {
	USHORT Pad;
	USHORT Limit;
	ULONG Base;
} DESCRIPTOR, *PDESCRIPTOR;

typedef struct _KSPECIAL_REGISTERS {
	ULONG Cr0;
	ULONG Cr2;
	ULONG Cr3;
	ULONG Cr4;
	ULONG KernelDr0;
	ULONG KernelDr1;
	ULONG KernelDr2;
	ULONG KernelDr3;
	ULONG KernelDr6;
	ULONG KernelDr7;
	DESCRIPTOR Gdtr;
	DESCRIPTOR Idtr;
	USHORT Tr;
	USHORT Ldtr;
	ULONG Reserved[6];
} KSPECIAL_REGISTERS, *PKSPECIAL_REGISTERS;
typedef struct _KPROCESSOR_STATE {
	CONTEXT ContextFrame;
	KSPECIAL_REGISTERS SpecialRegisters;
} KPROCESSOR_STATE, *PKPROCESSOR_STATE;

typedef struct _PROCESSOR_IDLE_TIMES {
	ULONG64 StartTime;
	ULONG64 EndTime;
	ULONG IdleHandlerReserved[4];
} PROCESSOR_IDLE_TIMES, *PPROCESSOR_IDLE_TIMES;

typedef struct _PROCESSOR_POWER_STATE {
	PVOID IdleFunction;
	ULONG Idle0KernelTimeLimit;
	ULONG Idle0LastTime;
	PVOID IdleHandlers;
	PVOID IdleState;
	ULONG IdleHandlersCount;
	ULONG64 LastCheck;
	PROCESSOR_IDLE_TIMES IdleTimes;
	ULONG IdleTime1;
	ULONG PromotionCheck;
	ULONG IdleTime2;
	UCHAR CurrentThrottle;
	UCHAR ThermalThrottleLimit;
	UCHAR CurrentThrottleIndex;
	UCHAR ThermalThrottleIndex;
	ULONG LastKernelUserTime;
	ULONG LastIdleThreadKernelTime;
	ULONG PackageIdleStartTime;
	ULONG PackageIdleTime;
	ULONG DebugCount;
	ULONG LastSysTime;
	ULONG64 TotalIdleStateTime[3];
	ULONG TotalIdleTransitions[3];
	ULONG64 PreviousC3StateTime;
	UCHAR KneeThrottleIndex;
	UCHAR ThrottleLimitIndex;
	UCHAR PerfStatesCount;
	UCHAR ProcessorMinThrottle;
	UCHAR ProcessorMaxThrottle;
	UCHAR EnableIdleAccounting;
	UCHAR LastC3Percentage;
	UCHAR LastAdjustedBusyPercentage;
	ULONG PromotionCount;
	ULONG DemotionCount;
	ULONG ErrorCount;
	ULONG RetryCount;
	ULONG Flags;
	LARGE_INTEGER PerfCounterFrequency;
	ULONG PerfTickCount;
	KTIMER PerfTimer;
	KDPC PerfDpc;
	struct _PROCESSOR_PERF_STATE *PerfStates;
	PLONG PerfSetThrottle;
	ULONG LastC3KernelUserTime;
	ULONG LastPackageIdleTime;
} PROCESSOR_POWER_STATE, *PPROCESSOR_POWER_STATE;

typedef struct _KPRCB {
	USHORT MinorVersion;
	USHORT MajorVersion;
	struct _KTHREAD *CurrentThread;
	struct _KTHREAD *NextThread;
	struct _KTHREAD *IdleThread;
	CCHAR Number;
	CCHAR Reserved;
	USHORT BuildType;
	ULONG SetMember;
	CCHAR CpuType;
	CCHAR CpuID;
	USHORT CpuStep;
	KPROCESSOR_STATE ProcessorState;
	ULONG KernelReserved[16];
	ULONG HalReserved[16];
	UCHAR PrcbPad0[92];
	KSPIN_LOCK_QUEUE LockQueue[16];
	UCHAR PrcbPad1[8];
	struct _KTHREAD *NpxThread;
	ULONG InterruptCount;
	ULONG KernelTime;
	ULONG UserTime;
	ULONG DpcTime;
	ULONG DebugDpcTime;
	ULONG InterruptTime;
	ULONG AdjustDpcThreshold;
	ULONG PageColor;
	ULONG SkipTick;
	UCHAR MultiThreadSetBusy;
	UCHAR Spare2[3];
	struct _KNODE *ParentNode;
	ULONG MultiThreadProcessorSet;
	struct _KPRCB * MultiThreadSetMaster;
	ULONG ThreadStartCount[2];
	ULONG CcFastReadNoWait;
	ULONG CcFastReadWait;
	ULONG CcFastReadNotPossible;
	ULONG CcCopyReadNoWait;
	ULONG CcCopyReadWait;
	ULONG CcCopyReadNoWaitMiss;
	ULONG KeAlignmentFixupCount;
	ULONG KeContextSwitches;
	ULONG KeDcacheFlushCount;
	ULONG KeExceptionDispatchCount;
	ULONG KeFirstLevelTbFills;
	ULONG KeFloatingEmulationCount;
	ULONG KeIcacheFlushCount;
	ULONG KeSecondLevelTbFills;
	ULONG KeSystemCalls;
	ULONG SpareCounter0[1];
	PP_LOOKASIDE_LIST PPLookasideList[16];
	PP_LOOKASIDE_LIST PPNPagedLookasideList[32];
	PP_LOOKASIDE_LIST PPPagedLookasideList[32];
	ULONG PacketBarrier;
	ULONG ReverseStall;
	PVOID IpiFrame;
	UCHAR PrcbPad2[52];
	PVOID CurrentPacket[3];
	ULONG TargetSet;
	PVOID WorkerRoutine;
	ULONG IpiFrozen;
	UCHAR PrcbPad3[40];
	ULONG RequestSummary;
	struct _KPRCB *SignalDone;
	UCHAR PrcbPad4[56];
	LIST_ENTRY DpcListHead;
	PVOID DpcStack;
	ULONG DpcCount;
	ULONG DpcQueueDepth;
	ULONG DpcRoutineActive;
	ULONG DpcInterruptRequested;
	ULONG DpcLastCount;
	ULONG DpcRequestRate;
	ULONG MaximumDpcQueueDepth;
	ULONG MinimumDpcRate;
	ULONG QuantumEnd;
	UCHAR PrcbPad5[16];
	ULONG DpcLock;
	UCHAR PrcbPad6[28];
	KDPC CallDpc;
	PVOID ChainedInterruptList;
	LONG LookasideIrpFloat;
	ULONG SpareFields0[6];
	UCHAR VendorString[13];
	UCHAR InitialApicId;
	UCHAR LogicalProcessorsPerPhysicalProcessor;
	ULONG MHz;
	ULONG FeatureBits;
	LARGE_INTEGER UpdateSignature;
	FX_SAVE_AREA NpxSaveArea;
	PROCESSOR_POWER_STATE PowerState;
} KPRCB, *PKPRCB, *PRKPRCB;
#define RPL_MASK     3

#define KGDT_R3_TEB     56

#define KGDT_R3_CODE    24

#define KGDT_R3_DATA    32

#define EXCEPTION_EXECUTE_FAULT       8

#define CONTEXT_ALIGN   (sizeof(ULONG))

#define EFLAGS_V86_MASK       0x00020000L

#define KF_GLOBAL_32BIT_EXECUTE 0x40000000

#define CONTEXT_ROUND   (CONTEXT_ALIGN - 1)

#define KF_GLOBAL_32BIT_NOEXECUTE 0x80000000

#define PF_NX_ENABLED                      12

#define KI_EXCEPTION_INTERNAL               0x10000000

#define KI_EXCEPTION_ACCESS_VIOLATION       (KI_EXCEPTION_INTERNAL | 0x4)

#define CONTEXT_ALIGNED_SIZE ((sizeof(CONTEXT) + CONTEXT_ROUND) & ~CONTEXT_ROUND)

#define SANITIZE_SEG(segCS, mode) (        \
	((mode) == KernelMode ? \
	((0x00000000L) | ((segCS)& 0xfffc)) : \
	((0x00000003L) | ((segCS)& 0xffff))))

typedef enum _THREAD_STATE {
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown
} THREAD_STATE;
typedef enum _USER_THREAD_STATE_CLASS {
	UserThreadStateFocusWindow,
	UserThreadStateActiveWindow,
	UserThreadStateCaptureWindow,
	UserThreadStateDefaultImeWindow,
	UserThreadStateDefaultInputContext
}USER_THREAD_STATE_CLASS, *PUSER_THREAD_STATE_CLASS;

typedef enum _SYSTEM_HANDLE_TYPE {
	OB_TYPE_UNKNOWN = 0,   //0
	OB_TYPE_TYPE,    // 1,fixed
	OB_TYPE_DIRECTORY,   // 2,fixed
	OB_TYPE_SYMBOLIC_LINK, // 3,fixed
	OB_TYPE_TOKEN,    // 4,fixed
	OB_TYPE_PROCESS,   // 5,fixed
	OB_TYPE_THREAD,    // 6,fixed
	OB_TYPE_JOB,    // 7,fixed
	OB_TYPE_DEBUG_OBJECT, // 8,fixed
	OB_TYPE_EVENT,    // 9,fixed
	OB_TYPE_EVENT_PAIR,   //10,fixed
	OB_TYPE_MUTANT,    //11,fixed
	OB_TYPE_CALLBACK,   //12,fixed
	OB_TYPE_SEMAPHORE,   //13,fixed
	OB_TYPE_TIMER,    //14,fixed
	OB_TYPE_PROFILE,   //15,fixed
	OB_TYPE_KEYED_EVENT, //16,fixed
	OB_TYPE_WINDOWS_STATION,//17,fixed
	OB_TYPE_DESKTOP,   //18,fixed
	OB_TYPE_SECTION,   //19,fixed
	OB_TYPE_KEY,    //20,fixed
	OB_TYPE_PORT,    //21,fixed 
	OB_TYPE_WAITABLE_PORT, //22,fixed
	OB_TYPE_ADAPTER,   //23,fixed
	OB_TYPE_CONTROLLER,   //24,fixed
	OB_TYPE_DEVICE,    //25,fixed
	OB_TYPE_DRIVER,    //26,fixed
	OB_TYPE_IOCOMPLETION, //27,fixed
	OB_TYPE_FILE,    //28,fixed
	OB_TYPE_WMIGUID    //29,fixed
} SYSTEM_HANDLE_TYPE;
typedef struct TCPAddrEntry {
	ULONG tae_ConnState;
	ULONG tae_ConnLocalAddress;
	ULONG tae_ConnLocalPort;
	ULONG tae_ConnRemAddress;
	ULONG tae_ConnRemPort;
} TCPAddrEntry;

typedef struct TCPAddrExEntry {
	ULONG tae_ConnState;
	ULONG tae_ConnLocalAddress;
	ULONG tae_ConnLocalPort;
	ULONG tae_ConnRemAddress;
	ULONG tae_ConnRemPort;
	ULONG pid;
} TCPAddrExEntry;

typedef struct {
	unsigned long tei_entity;
	unsigned long tei_instance;
} TDIEntityID;

typedef struct {
	TDIEntityID toi_entity;
	unsigned long toi_class;
	unsigned long toi_type;
	unsigned long toi_id;
} TDIObjectID;

#define CONTEXT_SIZE 16
typedef struct tcp_request_query_information_ex {
	TDIObjectID	ID;
	ULONG_PTR	Context[CONTEXT_SIZE / sizeof(ULONG_PTR)];
} TCP_REQUEST_QUERY_INFORMATION_EX, *PTCP_REQUEST_QUERY_INFORMATION_EX;
typedef struct _OBJECT_TYPE_INFORMATION { // Information Class 2
	UNICODE_STRING Name;
	ULONG HandleCount;
	ULONG ObjectCount;
	ULONG Reserved1[4];
	ULONG PeakHandleCount;
	ULONG PeakObjectCount;
	ULONG Reserved2[4];
	ACCESS_MASK InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ACCESS_MASK ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;
typedef struct _OBJECT_ALL_INFORMATION { // Information Class 3
	ULONG NumberOfTypes;
	OBJECT_TYPE_INFORMATION TypeInformation[1];
} OBJECT_ALL_INFORMATION, *POBJECT_ALL_INFORMATION;
typedef struct _CONTROL_AREA {
	PVOID Segment;
	LIST_ENTRY DereferenceList;
	ULONG NumberOfSectionReferences;
	ULONG NumberOfPfnReferences;
	ULONG NumberOfMappedViews;
	USHORT NumberOfSubsections;
	USHORT FlushInProgressCount;
	ULONG NumberOfUserReferences;
	DWORD unnamed;
	PFILE_OBJECT FilePointer;
	PVOID WaitingForDeletion;
	USHORT ModifiedWriteCount;
	USHORT NumberOfSystemCacheViews;
} CONTROL_AREA, *PCONTROL_AREA;

typedef struct _SEGMENT {
	PCONTROL_AREA ControlArea; //Ptr32 _CONTROL_AREA
	ULONG TotalNumberOfPtes; //Uint4B
	ULONG NonExtendedPtes; //Uint4B
	ULONG WritableUserReferences; //Uint4B
	ULONGLONG SizeOfSegment; //Uint8B
	ULONGLONG SegmentPteTemplate; //_MMPTE
	ULONG NumberOfCommittedPages; //Uint4B
	PVOID ExtendInfo; //Ptr32 _MMEXTEND_INFO
	PVOID SystemImageBase; //Ptr32 Void
	PVOID BasedAddress; //Ptr32 Void
	DWORD ui; //__unnamed
	DWORD u2; //__unnamed
	PVOID PrototypePte; //Ptr32 _MMPTE
	ULONGLONG ThePtes[1]; //[1] _MMPTE
} SEGMENT, *PSEGMENT;

typedef struct _SECTION_OBJECT {
	PVOID StartingVa; //Ptr32 Void
	PVOID EndingVa; //Ptr32 Void
	PVOID Parent; //Ptr32 Void
	PVOID LeftChild; //Ptr32 Void
	PVOID RightChild; //Ptr32 Void
	PSEGMENT Segment; //Ptr32 _SEGMENT
} SECTION_OBJECT, *PSECTION_OBJECT;

typedef VOID *SSTAT[];

typedef SSTAT *LPSSTAT; // LPSSTAT is a pointer to an SSTAT

typedef UCHAR SSTPT[];

typedef SSTPT *LPSSTPT; // LPSSTPT is a pointer to an SSTPT



//附加进程
NTSYSAPI VOID NTAPI KeAttachProcess(PVOID Process);

NTSYSAPI VOID NTAPI KeStackAttachProcess(IN PVOID Process, OUT PRKAPC_STATE ApcState);

//分离进程
NTSYSAPI VOID NTAPI KeDetachProcess();

NTSYSAPI VOID NTAPI KeUnstackDetachProcess(IN PRKAPC_STATE ApcState);

NTSYSAPI
KPROCESSOR_MODE
KeGetPreviousMode(VOID);
NTSYSAPI NTSTATUS NTAPI ObCreateObject(KPROCESSOR_MODE ProbeMode,
									   POBJECT_TYPE ObjectType,
									   POBJECT_ATTRIBUTES ObjectAttributes,
									   KPROCESSOR_MODE OwnershipMode,
									   PVOID ParseContext OPTIONAL,
									   ULONG ObjectBodySize,
									   ULONG PagedPoolCharge,
									   ULONG NonPagedPoolCharge,
									   PVOID *Object);

NTSYSAPI NTSTATUS NTAPI ObInsertObject(PVOID Object,
									   PACCESS_STATE PassedAccessState,
									   ACCESS_MASK DesiredAccess,
									   ULONG ObjectPointerBias,
									   PVOID *NewObject,
									   PHANDLE Handle);
//由指针打开对象
NTSYSAPI NTSTATUS NTAPI ObOpenObjectByPointer(PVOID Object,
											  ULONG HandleAttributes,
											  PACCESS_STATE PassedAccessState OPTIONAL,
											  ACCESS_MASK DesiredAccess OPTIONAL,
											  POBJECT_TYPE ObjectType OPTIONAL,
											  KPROCESSOR_MODE AccessMode,
											  PHANDLE Handle);

NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(PVOID Base);


NTSYSAPI
NTSTATUS
NTAPI
ZwFlushInstructionCache(IN HANDLE 	ProcessHandle,
						IN PVOID 	BaseAddress,
						IN ULONG 	NumberOfBytesToFlush
						);

NTSYSAPI
VOID
NTAPI
ExRaiseException(IN PEXCEPTION_RECORD ExceptionRecord);
//----------------------------------------------------

#define DEBUG_READ_EVENT        (0x0001)
#define DEBUG_PROCESS_ASSIGN    (0x0002)
#define DEBUG_SET_INFORMATION   (0x0004)
#define DEBUG_QUERY_INFORMATION (0x0008)
#define DEBUG_ALL_ACCESS     (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|DEBUG_READ_EVENT|DEBUG_PROCESS_ASSIGN|\
	DEBUG_SET_INFORMATION|DEBUG_QUERY_INFORMATION)

#define OBJECT_TO_OBJECT_HEADER( o ) CONTAINING_RECORD( (o), OBJECT_HEADER, Body )

UCHAR *PsGetProcessImageFileName(__in PEPROCESS eprocess);

NTSTATUS
PsLookupProcessByProcessId(
						   IN HANDLE ProcessId,
						   OUT PEPROCESS *Process
						   );

NTKERNELAPI
PEPROCESS
IoThreadToProcess (
				   IN PETHREAD Thread
				   );

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(   
	IN ULONG SystemInformationClass,   
	IN PVOID SystemInformation,   
	IN ULONG SystemInformationLength,   
	OUT PULONG ReturnLength);

typedef BOOLEAN (*EX_ENUMERATE_HANDLE_ROUTINE)(
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
	);

typedef NTSTATUS (__stdcall *PSeDefaultObjectMethod) (
	__in PVOID Object,
	__in SECURITY_OPERATION_CODE OperationCode,
	__in PSECURITY_INFORMATION SecurityInformation,
	__inout PSECURITY_DESCRIPTOR SecurityDescriptor,
	__inout_opt PULONG CapturedLength,
	__deref_inout PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
	__in POOL_TYPE PoolType,
	__in PGENERIC_MAPPING GenericMapping,
	__in ULONG_PTR unkonew
	);

typedef BOOLEAN (*__ExEnumHandleTable)(
									   IN PHANDLE_TABLE HandleTable,
									   IN EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
									   IN PVOID EnumParameter,
									   OUT PHANDLE Handle OPTIONAL
									   );

NTSYSAPI
NTSTATUS
NTAPI
ZwDuplicateObject(
				   HANDLE SourceProcessHandle,
				   HANDLE SourceHandle,
				   HANDLE TargetProcessHandle,
				   PHANDLE TargetHandle,
				   ACCESS_MASK DesiredAccess,
				   ULONG HandleAttributes,
				   ULONG Options
				  );

NTSTATUS ZwQueryObject(
					   HANDLE Handle,
					   OBJECT_INFORMATION_CLASS ObjectInformationClass,
					   PVOID ObjectInformation,
					   ULONG ObjectInformationLength,
					   PULONG ReturnLength);



NTSTATUS
ObCloseHandle(
			  __in HANDLE Handle,
			  __in KPROCESSOR_MODE PreviousMode
			  );
