#pragma once
#include <ntddk.h>
#include <windef.h>
#include <tchar.h>

#define		MAX_INSTRUCTIONS	0x30
#define		MAX_SHELLCODE_LEN	0x50
#define	    HOOK_INST_LEN		0x20


#define mem_protect_close()	_disable(); __writecr0(__readcr0() & (~(0x10000)));
#define mem_protect_open()	__writecr0(__readcr0() ^ 0x10000);  _enable();

typedef unsigned int        UINT;

#define FORMAT_PATCH_FUNC_ST(hook_info,func,new_func)	{hook_info.isHook = FALSE;hook_info.fnOrigAddress = (ULONG_PTR)func;hook_info.fnNewAddress = (ULONG_PTR)new_func;hook_info.fnNormalExec = 0;RtlZeroMemory(hook_info.origCode,HOOK_INST_LEN);}
#define CALL_NORNAL_API(call_type,hook_info)			((call_type)hook_info.fnNormalExec)

typedef struct _HOOK_INFO
{
	BOOLEAN		isHook;
	ULONG32	    fnOrigAddress;	//原始函数地址
	ULONG32	    fnNewAddress;	//new函数地址
	ULONG32	    fnNormalExec;	//正常执行函数
	UCHAR		origCode[HOOK_INST_LEN];
	UCHAR       copyCodeSize;
}HOOK_INFO,*PHOOK_INFO;

BOOLEAN inlineHook(HOOK_INFO *lpHookInfo);
void unInlineHook(HOOK_INFO *lpHookInfo);

