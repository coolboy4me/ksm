#pragma once
#include <ntddk.h>
#include <windef.h>
#include <tchar.h>
#include "BaseStructDKK.h"



extern PEPROCESS g_debugProcess;






BOOLEAN TestBit(ULONG value, ULONG bit);
BOOLEAN bIsProcessDebuger(PEPROCESS process);
PEPROCESS HandleToProcess(HANDLE hProcess, BOOL bThread);