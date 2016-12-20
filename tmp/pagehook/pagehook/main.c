#include "stdafx.h"
#include "pagehack.h"
#include "NtWriteVirtualMemory.h"
#include "NtDebugActiveProcess.h"
#include "ContextThread.h"
#include "KiDispatchException.h"
//通信定义
#define		FILE_DEVICE_PH		 0x00008821
#define		PAGE_HACKING_CTL        (ULONG) CTL_CODE(FILE_DEVICE_PH, 0x808, METHOD_NEITHER, FILE_ANY_ACCESS)

//名字
#define NT_DEVICE_NAME L"\\Device\\PageHack"
#define DOS_DEVICE_NAME L"\\DosDevices\\PageHack"

PDRIVER_OBJECT g_DriverObject=NULL;

typedef struct _PAGE_HACK_XT_
{
	HANDLE hProcessId;
	ULONG Address;
	ULONG ExceptionType;
}PAGE_HACK_XT,*PPAGE_HACK_XT;


//////////////////////////////////////////////////////////////////////////
//这里做处理
//////////////////////////////////////////////////////////////////////////
VOID ProPageHack(PVOID InBuffer)
{
	NTSTATUS ns;
	PEPROCESS ProcessObject=NULL;
	PPAGE_HACK_XT pBuff = (PPAGE_HACK_XT)InBuffer;
	ns = PsLookupProcessByProcessId(pBuff->hProcessId,&ProcessObject);
	if (NT_SUCCESS(ns))
	{
		AddBP(ProcessObject,pBuff->Address,pBuff->ExceptionType);
		ObDereferenceObject(ProcessObject);
	}
}

BOOLEAN OnDeviceControl( 
	IN PFILE_OBJECT FileObject,
	IN BOOLEAN bWait,
	IN PVOID InputBuffer, IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer, IN ULONG OutputBufferLength,
	IN ULONG IoControlCode, OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject)
{
	NTSTATUS stat ;
	ULONG	RetLen ; 
	UNICODE_STRING ImagePath;
	BOOL bFailCheckFile=TRUE;
	IoStatus->Status = STATUS_UNSUCCESSFUL ;
	IoStatus->Information = 0;

	//set the status success
	//set the information to 0 
	switch( IoControlCode)
	{
	case PAGE_HACKING_CTL:
		{
			
			//懒得写检查buffer大小，读写属性的代码了。
			ProPageHack(InputBuffer);
		}
		break;
	default:
		IoStatus->Status = STATUS_INVALID_DEVICE_REQUEST;
		//return error
		break;
	}
	return TRUE;
}
NTSTATUS
	DeviceControl(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP pIrp
	)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irpStack;
	PVOID inputBuffer, outputBuffer;
	ULONG inputBufferLength, outputBufferLength;
	ULONG ioControlCode;

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	irpStack = IoGetCurrentIrpStackLocation( pIrp);

	//get the current Irp stack location 

	if (irpStack -> MajorFunction == IRP_MJ_DEVICE_CONTROL )
	{

		//we only need the device io control
		inputBuffer = pIrp->AssociatedIrp.SystemBuffer;

		inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;

		outputBuffer = pIrp->AssociatedIrp.SystemBuffer;

		outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;


		//system use the same buffer in device io control  

		ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;


		if( (ioControlCode&3) == METHOD_NEITHER){
			outputBuffer = pIrp->UserBuffer;
		}

		OnDeviceControl( irpStack->FileObject, TRUE,
			inputBuffer, inputBufferLength,
			outputBuffer, outputBufferLength,
			ioControlCode, &pIrp->IoStatus, DeviceObject);

	}
	IoCompleteRequest( pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS
	CreateClose(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest( Irp, IO_NO_INCREMENT );

	return STATUS_SUCCESS;
}

VOID
	DrvUnload(
	IN PDRIVER_OBJECT DriverObject
	)
{
	PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
	UNICODE_STRING uniWin32NameString;
	NTSTATUS        ntStatus;

	RtlInitUnicodeString( &uniWin32NameString, DOS_DEVICE_NAME );

	IoDeleteSymbolicLink( &uniWin32NameString );

	//ntStatus = UnSetupDispatchHandler()

	if ( deviceObject != NULL )
	{
		IoDeleteDevice( deviceObject );
	}
	UnHookKiDispatchException();
	UnHookNtWriteVirtualMemory();
	UnHookNtDebugActiveProcess();
	UnhookContextThread();
}

NTSTATUS
	DriverEntry(
	IN PDRIVER_OBJECT		DriverObject,
	IN PUNICODE_STRING		RegistryPath
	)
{
	NTSTATUS        ntStatus;
	PDEVICE_OBJECT  DeviceObject = NULL;
	UNICODE_STRING  UniDeviceName;
	UNICODE_STRING  UniSymLink;
	g_DriverObject = DriverObject;


	RtlInitUnicodeString(&UniDeviceName, NT_DEVICE_NAME);

	ntStatus = IoCreateDevice(
		DriverObject,
		0,
		&UniDeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject);

	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	RtlInitUnicodeString(&UniSymLink, DOS_DEVICE_NAME);
	ntStatus = IoCreateSymbolicLink(&UniSymLink, &UniDeviceName);
	if (!NT_SUCCESS(ntStatus))
	{
		DrvUnload(DriverObject);
		return ntStatus;
	}

	__asm int 3
	HookKiDispatchException();
	HookNtWriteVirtualMemory();
	HookNtDebugActiveProcess();
	HookContextThread();
	if (!InitPageHack())
	{
		DrvUnload(DriverObject);
		return STATUS_UNSUCCESSFUL;
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = 
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	DriverObject->DriverUnload = DrvUnload;//不可卸载的！！！


	return STATUS_SUCCESS;
}