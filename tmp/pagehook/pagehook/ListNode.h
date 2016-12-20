#pragma once
#define LISTNODE_MEM_TAG 'lsnd'
typedef BOOL (*PLISTNODE_ENUMCALLBACK)(PVOID Item,PVOID Context);
typedef ULONG32
	(*PListNode_CompareRoutine)(
	PVOID Item1,
	PVOID Item2
	);
typedef void (*PLISTROUTINE_LOCK)(PVOID pRootNode, BOOLEAN bLockForWrite);
typedef void (*PLISTROUTINE_UNLOCK)(PVOID pRootNode);
typedef struct PHK_LIST_ROOT_NODE {
	LIST_ENTRY RootEntry;
	ERESOURCE Lock;
	BOOLEAN Initialized;
	ULONG volatile LockCount;
	PListNode_CompareRoutine CmpRoutine;
	PLISTNODE_ENUMCALLBACK EnumRoutine;
	PLISTROUTINE_LOCK LockRoutine;
	PLISTROUTINE_UNLOCK UnLockRoutine;
} PHK_LIST_ROOT_NODE;

typedef struct PHK_INFO_NODE {
	LIST_ENTRY ListEntry;
	ULONG RefCount;			// 引用计数 
	BYTE Info[1];
} PHK_INFO_NODE;

VOID PHK_List_ListInit(PHK_LIST_ROOT_NODE * pRootNode);
VOID PHK_List_ListShutdown(PHK_LIST_ROOT_NODE * pRootNode);
BOOLEAN PHK_List_ListInitialized(PHK_LIST_ROOT_NODE * pRootNode);
BOOL _PHK_List_ListLock(PHK_LIST_ROOT_NODE * pRootNode, BOOLEAN bLockForWrite);
BOOL _PHK_List_ListUnlock(PHK_LIST_ROOT_NODE * pRootNode,BOOL PreLockResult);
void _PHK_List_NodeRelease(PHK_LIST_ROOT_NODE * pRootNode, PHK_INFO_NODE * pNode);
PHK_INFO_NODE * _List_NodeCreate(
	PHK_LIST_ROOT_NODE * pRootNode,
	PVOID Item,ULONG32 SizeItem);

BOOLEAN PHK_List_NodeRemove(PHK_LIST_ROOT_NODE * pRootNode, PVOID Item,PListNode_CompareRoutine CompareCallback);
BOOLEAN PHK_List_NodeAppend (
	PHK_LIST_ROOT_NODE * pRootNode,
	PVOID Item,ULONG32 SizeItem,PListNode_CompareRoutine CompareCallback);
BOOLEAN _PHK_List_IsNodeInList(
	PHK_LIST_ROOT_NODE * pRootNode,
	PVOID Item,PListNode_CompareRoutine CompareCallback,
	OUT PHK_INFO_NODE ** ppInfoNode);
VOID PHK_List_ListClear (PHK_LIST_ROOT_NODE * pRootNode );

VOID PHK_List_Enum(PHK_LIST_ROOT_NODE *pRootNode,PLISTNODE_ENUMCALLBACK EnumCallBack,PVOID Context);
UINT PHK_List_DeleteSameItem(PHK_LIST_ROOT_NODE *pRootNode,PListNode_CompareRoutine CmpRoutine,PVOID Item);