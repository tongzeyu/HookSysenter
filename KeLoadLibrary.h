#ifndef __KELOADLIBRARY__H__
#define __KELOADLIBRARY__H__

#include <NTDDK.h>

PVOID KeLoadLibrary(PCWSTR lpLibFileName, PVOID OldImageBase);
PVOID KeImageFile(unsigned char* FileBuffer, PVOID OldImageBase);
void FixImportTable(IN PVOID ImageBase);
PVOID GetModuleBase(PCHAR szModuleBase);
PVOID
MiFindExportedRoutineByName (
    IN PVOID DllBase,
    IN PANSI_STRING AnsiImageRoutineName
    );
void FixBaseRelocTable(IN PVOID ImageBase, IN PVOID OldImageBase);
PVOID FixNewKiServiceTable(IN PVOID ImageBase, IN PVOID OldImageBase);

PVOID GetNtOsName(PCHAR szModuleBase);


#define NUMBER_SERVICE_TABLES 2

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PULONG Base;					// SSDT (System Service Dispatch Table)的基地址
    PULONG Count;						// 用于 checked builds, 包含 SSDT 中每个服务被调用的次数
    ULONG Limit;						// 服务函数的个数, NumberOfService * 4 就是整个地址表的大小
    PUCHAR Number;						// SSPT(System Service Parameter Table)的基地址
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

//导出由 ntoskrnl.exe 所导出的 SSDT
extern PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;
extern KSERVICE_TABLE_DESCRIPTOR NewKeServiceDescriptorTable;

#endif