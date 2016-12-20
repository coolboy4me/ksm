#include "stdafx.h"
#include "pagehack.h"
#include "ListNode.h"
#include "ldasm.h"
#include "idthook.h"


ULONG volatile pfTotalCount = 0;
PHK_LIST_ROOT_NODE PfList = { 0 };
UCHAR g_SavedSwapPte[0x8]={0x90};
BOOL bPAEOn=FALSE;
BOOL bpfStepBreak=FALSE;
ULONG32 dwPfEip=0;
PEPROCESS HackProcess=NULL;
PVOID OldTrap01=NULL;
PVOID OldTrap03 = NULL;
PVOID OldTrap0E=NULL;
PHK_LIST_ROOT_NODE BpList = { 0 };
void ClearPFStep()
{
	bpfStepBreak = FALSE;
	dwPfEip = 0;
}

BOOLEAN    TestBit(ULONG value, ULONG bit)
{
	if (value & (1 << bit))
		return TRUE;
	return FALSE;
}

ULONG32 getCR4(void)
{
	ULONG32 rc;
	__asm
	{
		_emit 0x0F;				//0F20E0        mov     eax, cr4
		_emit 0x20;
		_emit 0xE0;
		mov rc, eax;
	}
	return rc;
}

ULONG WPOFF()
{
	ULONG OldCr0;
	__asm
	{
			push eax
			mov eax, cr0
			mov OldCr0, eax
			and eax, 0FFFEFFFFh
			mov cr0, eax
			pop eax
			cli
	}
	return OldCr0;
}
void WPON(ULONG OldCr0)
{
	__asm
	{
			sti
			push eax
			mov eax, OldCr0
			mov cr0, eax
			pop eax
	}
}
BOOL CheckPAE()
{
	//检查PAE
	ULONG32 cr4=getCR4();
	if (TestBit(cr4,5))
	{
		return TRUE;
	}
	return FALSE;
}
void __stdcall OnPteSwap(PHARDWARE_PTE_X86PAE Page)
{

	if (Page->Valid==1)
	{
		//不在单步模式下才会改XX
		BOOL bInSingle=FALSE;
		//DbgPrint("vmx:OnPteSwap\n");
		if (IsPageHooked(IoGetCurrentProcess(),Page,TRUE,&bInSingle,NULL))
		{
			if(!bInSingle)
				Page->ExecuteDisable=1;
		}
	}
}
VOID __declspec(naked) KeInterlockedSwapPte()
{

	//
	// 这里的代码适用于xp,WRK压栈的是ULONG64,不是指针,要修改
	//

	//         ; ULONGLONG
	//         ; InterlockedExchangePte (
	//         ;     IN OUT PMMPTE Destination,
	//         ;     IN ULONGLONG Exchange
	//         ;     )
	// 
	//         push    ebx
	//          push    esi
	//         mov     ebx, [esp] + 16         ; ebx = NewPteContents lowpart
	//         mov     ecx, [esp] + 20         ; ecx = NewPteContents highpart
	//         mov     esi, [esp] + 12         ; esi = PtePointer


	__asm 
	{
			push    ebx
			push    esi
			mov     ebx, dword ptr [esp+10h]        // ebx = pointer to Exchange
			mov     esi, dword ptr [esp+0Ch]        // esi = PtePointer
			mov     ecx, dword ptr [ebx+4]                // ecx = NewPteContents highpart
			mov     ebx, dword ptr [ebx]                // ebx = NewPteContents lowpart
			mov     edx, dword ptr [esi+4]                // edx = OldPteContents highpart
			mov     eax, dword ptr [esi]                // eax = OldPteContents lowpart, return old contents in edx:eax

__swapagain:

		lock        cmpxchg8b qword ptr [esi]
		jne        __swapagain                        // if z clear, exchange failed

			pushad                                        // if debuggee, fuck up nx
			push esi
			call OnPteSwap
			popad
			pop     esi
			pop     ebx
			ret     8
	}
}

VOID HookKeInterlockedSwapPte(DWORD Func)
{
	ULONG old;
	ULONG  func = Func;
	ULONG  newlowpart, newhighpart;
	UCHAR  opcode[8] = {0x90};
	opcode[0] = 0xE9;
	*(PULONG)&opcode[1] = (ULONG)KeInterlockedSwapPte - (func+5);

	newlowpart  = *(PULONG)&opcode[0];
	newhighpart = *(PULONG)&opcode[4];
	//DbgPrint("KeInterlockedSwapPte:%08x\r\n",func);
	old = WPOFF();


	__asm {
			cli
			pushad
			mov   esi, func
			mov   edi, offset g_SavedSwapPte
			mov   edx, [esi+4]
			mov   [edi+4], edx  // save the old opcode
			mov   eax, [esi]
			mov   [edi], eax

			mov   ecx, newhighpart
			mov   ebx, newlowpart

__swapagain:
			lock  cmpxchg8b qword ptr [esi]
			jne   __swapagain        
			popad
			sti
	}

	WPON(old);

	DbgPrint("Hook KeInterlockedSwapPte OK\r\n");
}


unsigned long strtoul_pg(const char *cp, char **endp, unsigned int base)
{
	unsigned long result = 0, value;

	if (!base) {
		base = 10;
		if (*cp == '0') {
			base = 8;
			cp++;
			if ((tolower(*cp) == 'x') && isxdigit(cp[1])) {
				cp++;
				base = 16;
			}
		}
	}
	else if (base == 16) {
		if (cp[0] == '0' && tolower(cp[1]) == 'x')
			cp += 2;
	}
	while (isxdigit(*cp) &&
		(value = isdigit(*cp) ? *cp - '0' : tolower(*cp) - 'a' + 10) < base) {
		result = result*base + value;
		cp++;
	}
	if (endp)
		*endp = (char *)cp;
	return result;
}

BOOL ScanNativeAddress_pg(
	IN ULONG StartAddress,
	IN ULONG EndAdrress,
	IN char* szData,
	OUT ULONG* lpdwAddress)
{
	ULONG dwStartAddress;//代码开始地址
	ULONG dwEndAdrress;//代码结束地址
	BYTE byReadData[MAX_PATH];
	ULONG dwLen;
	BYTE *btData = NULL;
	ULONG i;
	ULONG dwAddress;

	dwStartAddress = StartAddress;//代码开始地
	dwEndAdrress = EndAdrress;//代码结束地址

	if (strlen(szData) % 2 != 0)//一定要是双数
		return FALSE;

	dwLen = strlen(szData) / 2;
	btData = (BYTE*)ExAllocatePoolWithTag(NonPagedPool, dwLen, 'kis4');
	for (i = 0; i < dwLen; i++)
	{
		char szchar[] = { szData[i * 2], szData[i * 2 + 1], '\0' };
		if (strcmp(szchar, "??") == NULL)
		{
			btData[i] = '?';
		}
		else
		{
			btData[i] = (BYTE)strtoul_pg(szchar, NULL, 16);
		}
	}

	for (dwAddress = StartAddress; dwAddress < (EndAdrress - dwLen); dwAddress++)
	{
		BOOLEAN bSuccess = FALSE;
		ULONG dwPostion;

		RtlZeroMemory(byReadData, MAX_PATH);
		RtlMoveMemory(byReadData, (VOID*)dwAddress, dwLen);

		for (dwPostion = 0; dwPostion < dwLen; dwPostion++)
		{
			if (btData[dwPostion] == '?')
				continue;
			if (btData[dwPostion] != byReadData[dwPostion])
			{
				bSuccess = TRUE;
				break;
			}
		}
		if (FALSE == bSuccess)
		{
			*lpdwAddress = dwAddress;
			ExFreePool(btData);
			return TRUE;
		}
		bSuccess = FALSE;
	}

	ExFreePool(btData);
	return FALSE;
}

DWORD GetKeInterlockedSwapPteAddress()
{
	DWORD dwPtr = 0;
	DWORD StartAddress = 0;
	UNICODE_STRING usMmMapUserAddressesToPage;
	RtlInitUnicodeString(&usMmMapUserAddressesToPage, L"MmMapUserAddressesToPage");
	StartAddress = (DWORD)MmGetSystemRoutineAddress(&usMmMapUserAddressesToPage);
	if (StartAddress)
	{
		__try
		{
			DWORD Length = 0;
			PUCHAR pOpcode;
			for (dwPtr = 0; dwPtr < 0x1000; dwPtr += Length)
			{
				Length = SizeOfCode((PUCHAR)(dwPtr + StartAddress), &pOpcode);
				if (Length == 5 && pOpcode[0] == 0xE8)
				{
					BYTE *sig = (BYTE *)(dwPtr + StartAddress - 5);
					if (sig[0] == 0x50 && sig[1] == 0x56)
					{
						DWORD dwRet = *(DWORD *)(dwPtr + StartAddress + 1);
						dwRet += dwPtr;
						dwRet += StartAddress;
						dwRet += 5;
						return dwRet;
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return 0;
		}

	}
	return 0;
}
BOOL InitPageHack()
{
	DWORD dwKeInterlockedSwapPte=0;
	IDTINFO		    idt_info;
	IDTENTRY*	    idt_entries;
	//判断是否PAE，没有PAE,什么DEP啊，SMEP啊都是浮云！！！
	if (!CheckPAE())
	{
		return FALSE;
	}
	//初始化hook表
	PHK_List_ListInit(&BpList);
	//初始化页表
	PHK_List_ListInit(&PfList);
	//MmMapUserAddressesToPage
	dwKeInterlockedSwapPte = GetKeInterlockedSwapPteAddress();
	DbgPrint("vmx:找到了:%p\n", dwKeInterlockedSwapPte);
	if (dwKeInterlockedSwapPte)
	{
		HookKeInterlockedSwapPte(dwKeInterlockedSwapPte);
		HookIDT(0x01,(PVOID)GetDBHanlderAddress(),&OldTrap01,-1);
		HookIDT(0x0E,(PVOID)GetPFHanlderAddress(),&OldTrap0E,-1);
		__asm sidt idt_info
		idt_entries = (IDTENTRY*)MAKELONG(idt_info.LowIDTbase, idt_info.HiIDTbase);
		OldTrap03 = (PVOID)MAKELONG(idt_entries[3].LowOffset, idt_entries[3].HiOffset);
		DbgPrint("vmx:OldTrap03:%p\n", OldTrap03);
	}
	return TRUE;
}
BOOL HookPage(PUCHAR Page)
{
	ULONG32 tmp32 = 0;
	PHARDWARE_PTE_X86PAE PointerPte;
	__try {


		__asm
		{      
			push eax
				mov   eax, Page        
				mov   eax, [eax]
			pop eax
		}

		PointerPte = (PHARDWARE_PTE_X86PAE)MiGetPteAddressPae(Page);
		//DbgPrint("vmx:HookPage:%p\n", PointerPte);
		//table 4-10 
		//IA32_EFER.NXE = 1; wrmsr
		/*
		
		
		Table 35-2. IA-32 Architectural MSRs (Contd.)
		//11位  写1
		Execute Disable Bit Enable:
		IA32_EFER.NXE (R/W)
		*/
		__asm {
			pushad
			mov ecx, 0xc0000080
				rdmsr
				mov tmp32, eax
				popad
		}
		tmp32 |= (1 << 11);
		
		__asm{
			pushad
				mov edx, 0
				mov eax, tmp32
				mov ecx, 0xc0000080
				wrmsr
				popad
		}

		tmp32 = 0;
		__asm {
			pushad
				mov ecx, 0xc0000080
				rdmsr
				mov tmp32, eax
				popad
		}

		if (PointerPte->Valid == 1) {
			PointerPte->ExecuteDisable = 1;
			__asm
			{
				push eax
					mov eax,Page
					invlpg [eax]
				pop eax
			}
			return TRUE;
		}
		else
		{
			DbgPrint("HookPage On InValidPage");
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER){

		DbgPrint("Exception captured while hooking page");
		return FALSE;
	}
	return TRUE;
}
BOOL UnHookPage(PUCHAR Page)
{
	PHARDWARE_PTE_X86PAE PointerPte;

	__try {

		__asm 
		{
			push eax
				mov  eax, Page        
				mov  eax, [eax]
			pop eax
		}

		PointerPte = (PHARDWARE_PTE_X86PAE)MiGetPteAddressPae(Page);

		if (PointerPte->Valid == 1) 
		{
			PointerPte->ExecuteDisable=0;
			__asm
			{
				push eax
					mov eax,Page
					invlpg [eax]
				pop eax
			}
			return TRUE;
		}
		else
		{
			DbgPrint("unhook page invalid page\r\n");
			return FALSE;
		}
	} 
	__except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("Exception captured while unhooking page");
		return FALSE;
	}
	return TRUE;
}
ULONG32 CmpPageFaultInfo(
	PVOID Item1,
	PVOID Item2
	)
{
	PFITEM *p1,*p2;
	p1=(PFITEM *)Item1;
	p2=(PFITEM *)Item2;
	if (p1->Process==p2->Process&&p1->Pte==p2->Pte) 
	{
		return 0;
	}
	return 1;
}
void HookMemoryPage(PEPROCESS Process,ULONG32 Address)
{
	KAPC_STATE ApcState;
	PHARDWARE_PTE_X86PAE xPte=NULL;
	KeStackAttachProcess(Process,&ApcState);
	//首先OD不会附加自己，所以不考虑Process==CurrentProcess这种情况，我们直接XX
	if(HookPage((PUCHAR)Address))
	{
		xPte = (PHARDWARE_PTE_X86PAE)MiGetPteAddressPae((PUCHAR)Address);
	}
	KeUnstackDetachProcess(&ApcState);
	if (xPte)
	{
		PFITEM pfItem;
		RtlZeroMemory(&pfItem,sizeof(pfItem));
		pfItem.Process = Process;
		pfItem.Pte = xPte;
		pfItem.bSingle=FALSE;
		pfItem.StepEip = 0;
		PHK_List_NodeAppend(&PfList,&pfItem,sizeof(PFITEM),CmpPageFaultInfo);
	}
}
void UnHookMemoryPage(PEPROCESS Process,ULONG32 Address)
{
	KAPC_STATE ApcState;
	PHARDWARE_PTE_X86PAE xPte=NULL;
	KeStackAttachProcess(Process,&ApcState);
	if(UnHookPage((PUCHAR)Address))
	{
		xPte = (PHARDWARE_PTE_X86PAE)MiGetPteAddressPae((PUCHAR)Address);
	}
	KeUnstackDetachProcess(&ApcState);
	if (xPte)
	{
		PFITEM pfItem;
		RtlZeroMemory(&pfItem,sizeof(pfItem));
		pfItem.Process = Process;
		pfItem.Pte = xPte;
		PHK_List_NodeRemove(&PfList,&pfItem,CmpPageFaultInfo);
	}
}
BOOL __stdcall IsAddressHooked(PEPROCESS Process,ULONG32 Address)
{
	PHARDWARE_PTE_X86PAE pte = (PHARDWARE_PTE_X86PAE)MiGetPteAddressPae(Address);
	return IsPageHooked(Process,pte,FALSE,NULL,NULL);
}
BOOL __stdcall IsPageHooked(PEPROCESS Process,PHARDWARE_PTE_X86PAE Page,BOOL bInVT,BOOL* dwSingle,DWORD *dwStepEip)
{
	BOOL bHooked=FALSE;
	PFITEM pfItem;
	PHK_INFO_NODE *pNode;
	BOOL bLock=FALSE;
	RtlZeroMemory(&pfItem,sizeof(PFITEM));
	pfItem.Process=Process;
	pfItem.Pte = Page;
	if(!bInVT)
		bLock = _PHK_List_ListLock(&PfList, TRUE);
	if (_PHK_List_IsNodeInList(&PfList, &pfItem,CmpPageFaultInfo,&pNode))
	{
		bHooked =TRUE;
		if (dwSingle)
		{
			*dwSingle = ((PFITEM *)pNode->Info)->bSingle;
		}
		if (dwStepEip)
		{
			*dwStepEip = ((PFITEM *)pNode->Info)->StepEip;
		}
	}
	if(!bInVT)
		_PHK_List_ListUnlock(&PfList,bLock);
	return bHooked;
}
void SetPageStepBreak(PEPROCESS Process,PHARDWARE_PTE_X86PAE Page,BOOL bInVT,BOOL bStepBreak,ULONG32 StepEip)
{
	PFITEM pfItem;
	PHK_INFO_NODE *pNode;
	BOOL bLock =FALSE;
	RtlZeroMemory(&pfItem,sizeof(PFITEM));
	pfItem.Process=Process;
	pfItem.Pte = Page;
	if(!bInVT)
		bLock = _PHK_List_ListLock(&PfList, TRUE);
	if (_PHK_List_IsNodeInList(&PfList, &pfItem,CmpPageFaultInfo,&pNode))
	{
		((PFITEM *)pNode->Info)->bSingle=bStepBreak;
		((PFITEM *)pNode->Info)->StepEip = StepEip;
	}
	if(!bInVT)
		_PHK_List_ListUnlock(&PfList,bLock);
	return ;
}
void __stdcall FlushTLB(ULONG32 FaultAddress)
{
	PHARDWARE_PTE_X86PAE Page = (PHARDWARE_PTE_X86PAE)MiGetPteAddressPae(FaultAddress);
	if (Page->Valid==1)
	{
		Page->ExecuteDisable = 0;
		__asm
		{
			push eax
			mov eax,FaultAddress
			invlpg [eax]
			mov eax,FaultAddress
			mov eax,[eax]
			pop eax
		}
		Page->ExecuteDisable = 1;
	}

}
ULONG32 OnPageFault(ULONG32 Eip,ULONG32 FaultAddress,ULONG32 ErrorCode,ULONG32 RegCr3)
{
	PEPROCESS Process;
	ULONG32 Exception=0;
	PHARDWARE_PTE_X86PAE Page;
	Page = (PHARDWARE_PTE_X86PAE)MiGetPteAddressPae(FaultAddress);
	Process = IoGetCurrentProcess();
	if (!TestBit(ErrorCode,0))
	{
		//只有present的page才是我们要搞的！！！
		return Exception;
	}
	if (IsPageHooked(Process,Page,TRUE,NULL,NULL))
	{
		//DbgPrint("int0e pf address :%08x Eip %08x\r\n",FaultAddress,Eip);
		Exception = PF_NEED_CHECK;
	}
	return Exception;
}

ULONG32 __stdcall HandlePageFault(PPF_CONTEXT pPageFaulCtx)
{
	ULONG32 tmp32 = 0;
	PEPROCESS Process;
	PHARDWARE_PTE_X86PAE myPte;
	ULONG32 FaultAddress =0;
	ULONG32 Eip =0;
	Eip = pPageFaulCtx->regEip;
	FaultAddress = pPageFaulCtx->regCr2;
	Process = IoGetCurrentProcess();
	myPte = (PHARDWARE_PTE_X86PAE)MiGetPteAddressPae(FaultAddress);
	
	if (!TestBit(pPageFaulCtx->regErrorCode,0))
	{
		//not present page!!!
		return PF_PASS_INT0E;
	}
	if (!IsPageHooked(Process,myPte,FALSE,NULL,NULL))
	{
		//不是我们hook的
		return PF_PASS_INT0E;
	}

	__asm {
		pushad
			mov ecx, 0xc0000080
			rdmsr
			mov tmp32, eax
			popad
	}

	if (FaultAddress==Eip)
	{
		//执行时
		//设置单步,让DBTrap来工作
		ULONG32 DbReturn = GetBP(Process,Eip,FALSE);
		DbgPrint("vmx:页异常:%s[%p][%p]\n", PsGetProcessImageFileName(Process), FaultAddress, DbReturn);
		if(DbReturn==0)
		{
			pPageFaulCtx->regEflags |= 0x100;
			//unhook
			UnHookPage((PUCHAR)Eip);
			//设置Swap状态和当前eip
			SetPageStepBreak(Process, myPte, FALSE, TRUE, Eip);
			bpfStepBreak = TRUE;
			dwPfEip = Eip;
			return PF_CONTINUE_EXECUTION;
		}
		if (DbReturn == 3)//如果发生pf地址就是手动下断的地址，就恢复hook，就转到int3例程去处理了
		{
			if (UnHookPage((PUCHAR)Eip))
				DbgPrint("vmx:UnHookPage is success\n");
			else
				DbgPrint("vmx:UnHookPage is unsuccess\n");
			return PF_INTO_INT3;
		}
	}
	return PF_PASS_INT0E;
}
ULONG32 __stdcall HandleTrap01(PDBTRAP_CONTEXT pTrapDbCtx)
{
	PEPROCESS Process;
	ULONG32 EipAddress;
	ULONG32 Eflags=0;
	Process = IoGetCurrentProcess();
	EipAddress = pTrapDbCtx->regEip;
	Eflags = pTrapDbCtx->regEflags;
	//其实EIP是可以改的嘿嘿，改了就那啥了哦哦
	if ((Eflags&0x100)==0x100)
	{
		//Single
		BOOL bSB=FALSE;
		ULONG32 OldEip=0;
		PHARDWARE_PTE_X86PAE myPte=(PHARDWARE_PTE_X86PAE)MiGetPteAddressPae(EipAddress);
		if (IsPageHooked(Process,myPte,FALSE,&bSB,&OldEip))
		{
			if (bSB)
			{
				ULONG32 DbReturn = GetBP(Process,EipAddress,FALSE);
				DbgPrint("vmx:单步异常:%s[%p][%p][%p]\n", PsGetProcessImageFileName(Process), EipAddress, OldEip, DbReturn);
				if (DbReturn == 3)
				{
					//取消单步
					pTrapDbCtx->regEflags &= ~0x100;
					//重新hook page
					HookPage((PUCHAR)EipAddress);
					//设置SwapPte
					SetPageStepBreak(Process, myPte, FALSE, FALSE, EipAddress);
					//转发为int3
					ClearPFStep();
					return DB_PASS_TRAP03;
				}
				if (DbReturn == 0 && OldEip != EipAddress)
				{
					//取消单步
					pTrapDbCtx->regEflags &= ~0x100;
					//重新hook page
					HookPage((PUCHAR)EipAddress);
					//设置SwapPte
					SetPageStepBreak(Process, myPte, FALSE, FALSE, EipAddress);
					//继续执行
					ClearPFStep();
					return DB_CONTINUE_EXECUTION;
				}
				if (DbReturn == 0)
				{
					return DB_CONTINUE_EXECUTION;
				}
			}
		}
		else
		{
			if (bpfStepBreak)
			{
				if (EipAddress!=dwPfEip)
				{
					//取消单步
					pTrapDbCtx->regEflags &=~0x100;
					//重新hook上次的页面
					HookPage((PUCHAR)dwPfEip);
					//取消上次页面的单步
					SetPageStepBreak(Process,(PHARDWARE_PTE_X86PAE)MiGetPteAddressPae(dwPfEip),FALSE,FALSE,0);
					ClearPFStep();
					return DB_CONTINUE_EXECUTION;
				}
			}
		}
	}
	return DB_PASS_INT01;
}

void TestPrintf()
{
	DbgPrint("vmx:这里\n");
}

volatile __declspec(naked) void MyPageFault()
{
	__asm
	{

			pushad
			pushfd
			push ds
			push es
			push fs

			push eax
			mov eax, 0x23
			mov ds, ax
			mov es, ax
			mov eax, 0x30
			mov fs, ax
			pop eax

			cli
			mov eax,cr2
			push eax
			mov eax,esp
			push eax
			call HandlePageFault
			cmp eax, PF_PASS_INT0E
			je PassToPF
			cmp eax, PF_CONTINUE_EXECUTION
			je DoIretd
			cmp eax, PF_INTO_INT1
			je DoInt1
			pop eax//这里要恢复cr2
			mov cr2, eax//就是这里
			pop fs
			pop es
			pop ds
			popfd
			popad
			add esp, 4
			inc dword ptr[esp]
			
			jmp OldTrap03
DoIretd :
			pop eax
			mov cr2, eax
			pop fs
			pop es
			pop ds
			popfd
			popad
			add esp, 4
			iretd
DoInt1 :
		pop eax
			mov cr2, eax
			pop fs
			pop es
			pop ds
			popfd
			popad
			add esp, 4
			jmp  OldTrap01
PassToPF :
		pop eax
			mov cr2, eax
			pop fs
			pop es
			pop ds
			popfd
			popad
			jmp OldTrap0E
	}
}

ULONG32 GetPFHanlderAddress()
{
	return (ULONG32)MyPageFault;
}
volatile __declspec(naked) void MyTrap01()
{
	__asm
	{

			pushad
			pushfd
			push ds
			push es
			push fs

			push eax
			mov eax, 0x23
			mov ds, ax
			mov es, ax
			mov eax, 0x30
			mov fs, ax
			pop eax

			cli
			mov eax,esp
			push eax
			call HandleTrap01
			cmp eax, DB_PASS_INT01
			je PassToTrap01
			cmp eax, DB_CONTINUE_EXECUTION
			je DbIretd
			pop fs
			pop es
			pop ds
			popfd
			popad
			inc dword ptr[esp]
			jmp OldTrap03
PassToTrap01 :
			pop fs
				pop es
				pop ds
				popfd
				popad
				jmp OldTrap01
DbIretd :
			pop fs
				pop es
				pop ds
				popfd
				popad
				iretd
	}
}
ULONG32 GetDBHanlderAddress()
{
	return (ULONG32)MyTrap01;
}
BOOL IsPassToTrap01(ULONG32 Address)
{
	PEPROCESS Process= IoGetCurrentProcess();
	if (bpfStepBreak)
	{
		return FALSE;
	}
	if (IsPageHooked(Process,(PHARDWARE_PTE_X86PAE)MiGetPteAddressPae(Address),TRUE,NULL,NULL))
	{
		//DbgPrint("need myint1\r\n");
		return FALSE;
	}
	return TRUE;
}

ULONG32 CmpSuperBpInfo(
	PVOID Item1,
	PVOID Item2
	)
{
	BPITEM *p1,*p2;
	p1=(BPITEM *)Item1;
	p2=(BPITEM *)Item2;
	if (p1->Address==p2->Address&&p1->Process==p2->Process) 
	{
		return 0;
	}
	return 1;
}
BOOL AddBP(PEPROCESS Process,ULONG32 Address,ULONG32 ExceptionType)
{
	BPITEM bpItem;
	RtlZeroMemory(&bpItem,sizeof(BPITEM));
	bpItem.Address = Address;
	bpItem.ExceptionType = ExceptionType;
	bpItem.Process = Process;
	if(PHK_List_NodeAppend(&BpList, &bpItem,sizeof(BPITEM),CmpSuperBpInfo))
	{
		//修改page的地方在里！
		HookMemoryPage(Process,Address);
		return TRUE;
	}
	return FALSE;
}

BOOL DelBP(PEPROCESS Process,ULONG32 Address,ULONG32 ExceptionType)
{
	BPITEM bpItem;
	RtlZeroMemory(&bpItem,sizeof(BPITEM));
	bpItem.Address = Address;
	bpItem.ExceptionType = ExceptionType;
	bpItem.Process = Process;
	if (PHK_List_NodeRemove(&BpList,&bpItem,CmpSuperBpInfo))
	{
		UnHookMemoryPage(Process,Address);
		return TRUE;
	}
	return FALSE;
}

ULONG32 GetBP(PEPROCESS Process,ULONG32 Address,BOOL bFormVt)
{
	ULONG32 ExceptionType=0;
	BPITEM bpItem;
	BOOL bLock = FALSE;
	PHK_INFO_NODE * pNode = NULL;
	RtlZeroMemory(&bpItem,sizeof(BPITEM));
	bpItem.Address = Address;
	bpItem.Process = Process;
	if(!bFormVt)
		bLock = _PHK_List_ListLock(&BpList, TRUE);
	if (_PHK_List_IsNodeInList(&BpList, &bpItem,CmpSuperBpInfo,&pNode))
	{
		ExceptionType = ((BPITEM *)pNode->Info)->ExceptionType;	
	}
	if(!bFormVt)
		_PHK_List_ListUnlock(&BpList,bLock);
	return ExceptionType;
}