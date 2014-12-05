#include "Driver.h"
#include "ntdll.h"


#pragma INITCODE
NTSTATUS DriverEntry (
			IN PDRIVER_OBJECT pDriverObject,
			IN PUNICODE_STRING pRegistryPath	) 
{
	NTSTATUS status = STATUS_SUCCESS;

	PVOID OldImageBase;
	PVOID NewImageBase;

	pDriverObject->DriverUnload = HelloDDKUnload;

	KdPrint(("加载驱动成功!\n"));

	OldImageBase = GetModuleBase("ntoskrnl.exe");
	if(NULL != OldImageBase)
	{
		NewImageBase = KeLoadLibrary(L"\\??\\C:\\windows\\system32\\ntoskrnl.exe", OldImageBase);
	}
	else
	{
		OldImageBase = GetModuleBase("ntkrnlpa.exe");
		NewImageBase = KeLoadLibrary(L"\\??\\C:\\windows\\system32\\ntkrnlpa.exe", OldImageBase);
	}
	
	FixNewKiServiceTable(NewImageBase, OldImageBase);
	SetSysenterHook();

	SetDebugPortDrxHook();
	

	return status;
}

/************************************************************************
* º¯ÊýÃû³Æ:CreateDevice
* ¹¦ÄÜÃèÊö:³õÊ¼»¯Éè±¸¶ÔÏó
* ²ÎÊýÁÐ±í:
      pDriverObject:´ÓI/O¹ÜÀíÆ÷ÖÐ´«½øÀ´µÄÇý¶¯¶ÔÏó
* ·µ»Ø Öµ:·µ»Ø³õÊ¼»¯×´Ì¬
*************************************************************************/
#pragma INITCODE
NTSTATUS CreateDevice (
		IN PDRIVER_OBJECT	pDriverObject) 
{
	NTSTATUS status;
	PDEVICE_OBJECT pDevObj;
	PDEVICE_EXTENSION pDevExt;
	
	UNICODE_STRING devName;
	UNICODE_STRING symLinkName;

	RtlInitUnicodeString(&devName,L"\\Device\\MyDDKDevice");
	
	status = IoCreateDevice( pDriverObject,
						sizeof(DEVICE_EXTENSION),
						&devName,
						FILE_DEVICE_UNKNOWN,
						0, TRUE,
						&pDevObj );
	if (!NT_SUCCESS(status))
		return status;

	pDevObj->Flags |= DO_BUFFERED_IO;
	pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
	pDevExt->pDevice = pDevObj;
	pDevExt->ustrDeviceName = devName;
	
	RtlInitUnicodeString(&symLinkName,L"\\??\\HelloDDK");
	pDevExt->ustrSymLinkName = symLinkName;
	status = IoCreateSymbolicLink( &symLinkName,&devName );
	if (!NT_SUCCESS(status)) 
	{
		IoDeleteDevice( pDevObj );
		return status;
	}
	return STATUS_SUCCESS;
}

/************************************************************************
* º¯ÊýÃû³Æ:HelloDDKUnload
* ¹¦ÄÜÃèÊö:¸ºÔðÇý¶¯³ÌÐòµÄÐ¶ÔØ²Ù×÷
* ²ÎÊýÁÐ±í:
      pDriverObject:Çý¶¯¶ÔÏó
* ·µ»Ø Öµ:·µ»Ø×´Ì¬
*************************************************************************/
#pragma PAGEDCODE
VOID HelloDDKUnload (IN PDRIVER_OBJECT pDriverObject) 
{
	UnSysenterHook();
	UnDebugPortDrxHook();
	KdPrint(("Çý¶¯Ð¶ÔØ³É¹¦!\n"));
}

/************************************************************************
* º¯ÊýÃû³Æ:HelloDDKDispatchRoutine
* ¹¦ÄÜÃèÊö:¶Ô¶ÁIRP½øÐÐ´¦Àí
* ²ÎÊýÁÐ±í:
      pDevObj:¹¦ÄÜÉè±¸¶ÔÏó
      pIrp:´ÓIOÇëÇó°ü
* ·µ»Ø Öµ:·µ»Ø×´Ì¬
*************************************************************************/
#pragma PAGEDCODE
NTSTATUS HelloDDKDispatchRoutine(IN PDEVICE_OBJECT pDevObj,
								 IN PIRP pIrp) 
{
	NTSTATUS status = STATUS_SUCCESS;	

	KdPrint(("Enter HelloDDKDispatchRoutine\n"));

	// Íê³ÉIRP
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;	// bytes xfered
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	KdPrint(("Leave HelloDDKDispatchRoutine\n"));
	return status;
}
