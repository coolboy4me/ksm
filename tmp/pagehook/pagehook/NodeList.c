#include "stdafx.h"
#include "ListNode.h"
VOID PHK_List_ListInit(PHK_LIST_ROOT_NODE * pRootNode)
{
	//PAGED_CODE();
	InitializeListHead(&pRootNode->RootEntry);
	//	ExInitializeFastMutex(&pRootNode->mLock);
	ExInitializeResourceLite(&pRootNode->Lock);
	pRootNode->Initialized = TRUE;
	pRootNode->LockCount = 0;
}

VOID PHK_List_ListShutdown(PHK_LIST_ROOT_NODE * pRootNode)
{
	PHK_List_ListClear(pRootNode);
	pRootNode->Initialized = FALSE;
	ExDeleteResourceLite(&pRootNode->Lock);
}


BOOLEAN PHK_List_ListInitialized(PHK_LIST_ROOT_NODE * pRootNode)
{
	//PAGED_CODE();
	return pRootNode->Initialized;
}

BOOL _PHK_List_ListLock(PHK_LIST_ROOT_NODE * pRootNode, BOOLEAN bLockForWrite)
{
	BOOL bLocked = FALSE;
	ASSERT(pRootNode->Initialized);
	pRootNode->LockCount++;
	//DbgPrint("AgpListLock");
	if (KeGetCurrentIrql()<=APC_LEVEL)
	{
		bLocked =TRUE;
		KeEnterCriticalRegion();
		if (bLockForWrite) {
			ExAcquireResourceExclusiveLite(&pRootNode->Lock, TRUE);
		} else {
			ExAcquireResourceSharedLite(&pRootNode->Lock, TRUE);
		}
	}
	return bLocked;

}

BOOL _PHK_List_ListUnlock(PHK_LIST_ROOT_NODE * pRootNode,BOOL PreLockResult)
{
	ASSERT(pRootNode->Initialized);
	if(PreLockResult)
	{
		ExReleaseResourceLite(&pRootNode->Lock);
		KeLeaveCriticalRegion();
	}
	pRootNode->LockCount--;
	//DbgPrint("AGPListUnLock");
	return TRUE;
}

void _PHK_List_NodeRelease(PHK_LIST_ROOT_NODE * pRootNode, PHK_INFO_NODE * pNode)
{
	pRootNode;
	if (pNode) {
		ExFreePoolWithTag(pNode, LISTNODE_MEM_TAG);
	}
}

PHK_INFO_NODE * _PHK_List_NodeCreate(
	PHK_LIST_ROOT_NODE * pRootNode,
	PVOID Item,ULONG32 SizeItem)
{
	PHK_INFO_NODE * pNode = NULL;
	BOOLEAN bRs = FALSE;

	//PAGED_CODE();

	do 
	{
		pNode = (PHK_INFO_NODE *) 
			ExAllocatePoolWithTag(NonPagedPool, sizeof(PHK_INFO_NODE)+SizeItem+0x100, LISTNODE_MEM_TAG);
		if (NULL == pNode) { break; }

		RtlZeroMemory(pNode, sizeof(PHK_INFO_NODE)+SizeItem);

		RtlCopyMemory(pNode->Info,Item,SizeItem);
		pNode->RefCount = 1;

		bRs = TRUE;
	} while (FALSE);

	if (FALSE == bRs) {
		_PHK_List_NodeRelease(pRootNode, pNode);
		pNode = NULL;
	}

	return pNode;
}


// 判断是否在链表中 
BOOLEAN _PHK_List_IsNodeInList(
	PHK_LIST_ROOT_NODE * pRootNode,
	PVOID Item,PListNode_CompareRoutine CompareCallback,
	OUT PHK_INFO_NODE ** ppInfoNode)
{
	PLIST_ENTRY pIter = NULL;
	PHK_INFO_NODE * pNode = NULL;
	BOOLEAN bFind = FALSE;

	for(pIter = pRootNode->RootEntry.Flink;
		pIter != &pRootNode->RootEntry;
		pIter = pIter->Flink)
	{
		pNode = CONTAINING_RECORD(pIter, PHK_INFO_NODE, ListEntry);

		if (CompareCallback(Item,pNode->Info)==0) 
		{
			if (ppInfoNode) {
				*ppInfoNode = pNode;
			}

			bFind = TRUE;
			break;
		}
	} 

	return bFind;
}

// 追加一个节点. 这个函数有加锁来保证只插入一个, 不会重复插入. 
BOOLEAN PHK_List_NodeAppend (
	PHK_LIST_ROOT_NODE * pRootNode,
	PVOID Item,ULONG32 SizeItem,PListNode_CompareRoutine CompareCallback)
{
	BOOL bLock =FALSE;
	BOOLEAN bRs = FALSE;
	PHK_INFO_NODE * pNode = NULL;
	ASSERT(PHK_List_ListInitialized(pRootNode));
	bLock = _PHK_List_ListLock(pRootNode, TRUE); // 加锁并查找 

	do 
	{
		// 查找 
		if (_PHK_List_IsNodeInList(pRootNode, Item,CompareCallback,&pNode)) {
			pNode->RefCount ++ ;
			bRs = TRUE;
			break;
		}

		pNode = _PHK_List_NodeCreate(pRootNode, Item,SizeItem);
		if (NULL == pNode) {
			break;
		}

		// 插入到链表里。
		InsertHeadList(&pRootNode->RootEntry, 
			& pNode->ListEntry);

		bRs = TRUE;
	} while (FALSE);

	_PHK_List_ListUnlock(pRootNode,bLock); // 释放锁 

	return bRs;
}


BOOLEAN PHK_List_NodeRemove(PHK_LIST_ROOT_NODE * pRootNode, PVOID Item,PListNode_CompareRoutine CompareCallback)
{
	BOOLEAN bRs = FALSE;
	PLIST_ENTRY pIter = NULL;
	PHK_INFO_NODE * pNode = NULL;
	BOOL bLock;
	ASSERT(PHK_List_ListInitialized(pRootNode));
	bLock = _PHK_List_ListLock(pRootNode, TRUE);

	if (_PHK_List_IsNodeInList(pRootNode,Item,CompareCallback,&pNode)) {
		bRs =TRUE;
		pNode->RefCount --;
		if (0 == pNode->RefCount) {
			RemoveEntryList(&pNode->ListEntry);
			_PHK_List_NodeRelease(pRootNode, pNode);
		}
	}

	_PHK_List_ListUnlock(pRootNode,bLock);

	return bRs;
}

VOID PHK_List_ListClear (PHK_LIST_ROOT_NODE * pRootNode )
{
	PLIST_ENTRY pIter = NULL;
	PHK_INFO_NODE * pNode = NULL;
	BOOL bLock =FALSE;
	bLock = _PHK_List_ListLock(pRootNode, TRUE);
	while(!IsListEmpty(&pRootNode->RootEntry)) {
		pIter = RemoveHeadList(&pRootNode->RootEntry);
		pNode = CONTAINING_RECORD(pIter, PHK_INFO_NODE, ListEntry);
		_PHK_List_NodeRelease(pRootNode, pNode);
	}
	_PHK_List_ListUnlock(pRootNode,bLock);
}

VOID PHK_List_Enum(PHK_LIST_ROOT_NODE *pRootNode,PLISTNODE_ENUMCALLBACK EnumCallBack,PVOID Context)
{
	PLIST_ENTRY pIter = NULL;
	PHK_INFO_NODE * pNode = NULL;
	BOOL bLock=FALSE;
	ASSERT(PHK_List_ListInitialized(pRootNode));
	bLock = _PHK_List_ListLock(pRootNode, TRUE);
	for(pIter = pRootNode->RootEntry.Flink;
		pIter != &pRootNode->RootEntry;
		pIter = pIter->Flink)
	{
		pNode = CONTAINING_RECORD(pIter, PHK_INFO_NODE, ListEntry);

		if (!EnumCallBack(pNode,Context)) 
		{
			//返回FALSE停止枚举!
			break;
		}
	} 
	_PHK_List_ListUnlock(pRootNode,bLock);
}
UINT PHK_List_DeleteSameItem(PHK_LIST_ROOT_NODE *pRootNode,PListNode_CompareRoutine CmpRoutine,PVOID Item)
{
	PLIST_ENTRY pIter = NULL;
	PHK_INFO_NODE * pNode = NULL;
	BOOL bLock=FALSE;
	UINT nRet=0;
	UINT nDeleted=0;
	ASSERT(PHK_List_ListInitialized(pRootNode));
	bLock = _PHK_List_ListLock(pRootNode, TRUE);
	for(pIter = pRootNode->RootEntry.Flink;
		pIter != &pRootNode->RootEntry;
		pIter = pIter->Flink)
	{
		pNode = CONTAINING_RECORD(pIter, PHK_INFO_NODE, ListEntry);

		if (CmpRoutine(pNode,Item)==0) 
		{
			//返回FALSE停止枚举!
			nRet++;
		}
	} 
	nDeleted =nRet;
	while (nDeleted!=0)
	{
		for(pIter = pRootNode->RootEntry.Flink;
			pIter != &pRootNode->RootEntry;
			pIter = pIter->Flink)
		{
			pNode = CONTAINING_RECORD(pIter, PHK_INFO_NODE, ListEntry);

			if (CmpRoutine(pNode,Item)==0) 
			{
				//返回FALSE停止枚举!
				RemoveEntryList(&pNode->ListEntry);
				_PHK_List_NodeRelease(pRootNode, pNode);
				nDeleted--;
				break;
			}
		} 
	}
	_PHK_List_ListUnlock(pRootNode,bLock);
	return nRet;
}