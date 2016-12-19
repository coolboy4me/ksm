// r3.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include <string>

#define		FILE_DEVICE_PH			0x00008821
#define		PAGE_HACKING_CTL        (ULONG) CTL_CODE(FILE_DEVICE_PH, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _PAGE_HACK_XT_
{
	HANDLE pid;
	PVOID src;
	PVOID dst;
}PAGE_HACK_XT, *PPAGE_HACK_XT;



int ret1()
{
	return 1;
}

int ret0()
{
	return 0;
}

unsigned char bufRet[10] = { 0xc3 };
int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE device_handle_ = CreateFileA("\\\\.\\ksm",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (device_handle_ != INVALID_HANDLE_VALUE)
	{
		printf("CreateFileA success\n");
		PAGE_HACK_XT *pph = new PAGE_HACK_XT;
		HMODULE hm = LoadLibraryA("Kernel32.dll");
		if (hm)
		{
			PVOID hLoad = GetProcAddress(hm, "LoadLibraryA");
			printf("hLoad %p\n", hLoad);
			pph->src = (PVOID)ret1;
			pph->pid = (HANDLE)GetCurrentProcessId();
			pph->dst = (PVOID)ret0;

			DWORD ret;
			if (DeviceIoControl(device_handle_, PAGE_HACKING_CTL,
				pph,
				sizeof(*pph),
				NULL,
				0,
				&ret,
				NULL))
			{
				printf("DeviceIoControl success\n");
			}
			else
			{
				printf("DeviceIoControl fail:%d\n", GetLastError());
			}
		}

		CloseHandle(device_handle_);
	}
	else
	{
		printf("CreateFile err %d\n", GetLastError());
	}

	__debugbreak();
	printf("%d\n", ret1());
	for (int i = 0; i < 20; i++)
	{
		printf("%x\n", *((PUCHAR)ret1 + i));
	}
	getchar();
	return 0;
}