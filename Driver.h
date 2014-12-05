#ifndef __DRIVER__H__
#define __DRIVER__H__

#ifdef __cplusplus
extern "C"{
#endif

#include <NTDDK.h>
#include "HookSysenter.h"
#include "KeLoadLibrary.h"
#include "KeDrxHook.h"

// 函数声明
NTSTATUS PsLookupProcessByProcessId(
        IN ULONG ulProcId, 
        OUT PEPROCESS * pEProcess
        );



#ifdef __cplusplus
}
#endif



#define PAGEDCODE code_seg("PAGE")
#define LOCKEDCODE code_seg()
#define INITCODE code_seg("INIT")

#define PAGEDDATA data_seg("PAGE")
#define LOCKEDDATA data_seg()
#define INITDATA data_seg("INIT")

#define arraysize(p) (sizeof(p)/sizeof((p)[0]))

typedef struct _DEVICE_EXTENSION {
	PDEVICE_OBJECT pDevice;
	UNICODE_STRING ustrDeviceName;	//设备名称
	UNICODE_STRING ustrSymLinkName;	//符号链接名
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

NTSTATUS CreateDevice (IN PDRIVER_OBJECT pDriverObject);
VOID HelloDDKUnload (IN PDRIVER_OBJECT pDriverObject);
NTSTATUS HelloDDKDispatchRoutine(IN PDEVICE_OBJECT pDevObj,
								 IN PIRP pIrp);



#endif