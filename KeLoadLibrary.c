#include "KeLoadLibrary.h"
#include <ntimage.h>
#include "un_export.h"

KSERVICE_TABLE_DESCRIPTOR NewKeServiceDescriptorTable;

//  L"\\??\\C:\\a.dat"
PVOID KeLoadLibrary(PCWSTR lpLibFileName, PVOID OldImageBase)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING ObjName;


	HANDLE hFileHandle;
	IO_STATUS_BLOCK IoStatus;

	FILE_STANDARD_INFORMATION FileInfo;
	PVOID FileBuffer, ImageBase;
	LARGE_INTEGER byteoffset = {0};

	RtlInitUnicodeString(&ObjName, lpLibFileName);
	InitializeObjectAttributes(&ObjectAttributes, &ObjName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwCreateFile(&hFileHandle, FILE_READ_DATA, &ObjectAttributes, &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, \
				FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("打开文件失败%ws", lpLibFileName));
		ZwClose(hFileHandle);
		return NULL;
	}

	status = ZwQueryInformationFile(hFileHandle, &IoStatus, &FileInfo, sizeof(FILE_STANDARD_INFORMATION), \
		FileStandardInformation);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("查询文件信息失败%ws", lpLibFileName));
		ZwClose(hFileHandle);
		return NULL;
	}

	FileBuffer = ExAllocatePool(PagedPool, FileInfo.EndOfFile.LowPart);
	if(NULL == FileBuffer)
	{
		KdPrint(("分配文件内存失败%ws", lpLibFileName));
		ZwClose(hFileHandle);
		return NULL;
	}

	status = ZwReadFile(hFileHandle, NULL, NULL, NULL, &IoStatus, FileBuffer, FileInfo.EndOfFile.LowPart, \
		&byteoffset, NULL);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("读取文件到内存失败%ws", lpLibFileName));
		ExFreePool(FileBuffer);
		ZwClose(hFileHandle);
		return NULL;
	}
	ZwClose(hFileHandle);

	ImageBase = KeImageFile(FileBuffer, OldImageBase);
	if(NULL == ImageBase)
	{
		KdPrint(("映射文件失败!"));
		ExFreePool(FileBuffer);
		return NULL;
	}
	ExFreePool(FileBuffer);

	return ImageBase;
}

#define AlignSize(Size, Align) (Size+Align-1)/Align*Align
PVOID KeImageFile(unsigned char* FileBuffer, PVOID OldImageBase)
{
	PIMAGE_DOS_HEADER ImageDosHeader;
	PIMAGE_NT_HEADERS ImageNtHeader;

	ULONG ImageBufferSize;
	unsigned char* ImageBase;

	PIMAGE_SECTION_HEADER ImageSectionHeader;

	int i;

	ImageDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if(ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}
	ImageNtHeader = (PIMAGE_NT_HEADERS)(FileBuffer+ImageDosHeader->e_lfanew);
	if(ImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}
	
	ImageBufferSize = AlignSize(ImageNtHeader->OptionalHeader.SizeOfImage, ImageNtHeader->OptionalHeader.SectionAlignment);
	ImageBase = ExAllocatePool(NonPagedPool, ImageBufferSize);
	if(NULL == ImageBase)
	{
		return NULL;
	}

	RtlZeroMemory(ImageBase, ImageBufferSize);
	RtlCopyMemory(ImageBase, FileBuffer, ImageNtHeader->OptionalHeader.SizeOfHeaders);
	ImageSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG)ImageNtHeader + sizeof(ImageNtHeader->Signature) + \
		 sizeof(ImageNtHeader->FileHeader) + ImageNtHeader->FileHeader.SizeOfOptionalHeader);

	for(i = 0; i < ImageNtHeader->FileHeader.NumberOfSections ; i++)
	{
		RtlCopyMemory(ImageBase + ImageSectionHeader[i].VirtualAddress, \
			FileBuffer + ImageSectionHeader[i].PointerToRawData, ImageSectionHeader[i].Misc.VirtualSize);
	}
	KdPrint(("ImageBase:%08X, ImageSize:%08X  OldImageBase:%08X", ImageBase, ImageBufferSize, OldImageBase));
	
	FixImportTable(ImageBase);
	FixBaseRelocTable(ImageBase, OldImageBase);

	return ImageBase;
}

void FixImportTable(IN PVOID ImageBase)
{
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
	ULONG ImportSize;

	PIMAGE_THUNK_DATA OriginalFirstThunk, FirstThunk;

	ImportDescriptor = RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ImportSize);
	while(ImportDescriptor->OriginalFirstThunk && ImportDescriptor->Name)
	{
		PVOID DllBase;
		//KdPrint(("dll名字:%s", (PUCHAR)ImageBase + ImportDescriptor->Name));
		DllBase = GetModuleBase((PUCHAR)ImageBase + ImportDescriptor->Name);
		if(DllBase == NULL)
		{
			KdPrint(("没找到模块!"));
			break;
		}

		OriginalFirstThunk = (PIMAGE_THUNK_DATA)((ULONG)ImageBase + ImportDescriptor->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)((ULONG)ImageBase + ImportDescriptor->FirstThunk);
		while(OriginalFirstThunk->u1.Ordinal)
		{
			PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)((PUCHAR)ImageBase + OriginalFirstThunk->u1.AddressOfData);
			//序号导入
			if(IMAGE_SNAP_BY_ORDINAL32(OriginalFirstThunk->u1.Ordinal))
			{
				//内核中貌似没有序号导出的
				KdPrint(("导入序号:%d", ImageImportByName->Hint));
			}
			else
			{
				ANSI_STRING AnsiImageRoutineName;
				RtlInitAnsiString(&AnsiImageRoutineName, ImageImportByName->Name);
				FirstThunk->u1.Function = (ULONG)MiFindExportedRoutineByName(DllBase, &AnsiImageRoutineName);
				//KdPrint(("名字:%s, Adress:%08X", ImageImportByName->Name, FirstThunk->u1.Function ));
			}
			OriginalFirstThunk++;
			FirstThunk++;
		}
		ImportDescriptor++;
	}

	KdPrint(("fix import ok!!"));
	return ;
}

PVOID GetModuleBase(PCHAR szModuleBase)
{
    PVOID pBuffer  = NULL;
	ULONG ReturnLength = 0;
    PSYSTEM_MODULE_INFORMATION pInfo;
	ULONG i;

	if(STATUS_INFO_LENGTH_MISMATCH == ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &ReturnLength))
	{
		pBuffer = ExAllocatePool(NonPagedPool, ReturnLength);
		if(pBuffer)
		{
			ZwQuerySystemInformation(SystemModuleInformation, pBuffer, ReturnLength, 0);
		}
		else
		{
			return NULL;
		}
	}
	else
	{
		return NULL;
	}

    pInfo = (PSYSTEM_MODULE_INFORMATION)pBuffer;
    for(i = 0; i < pInfo->ModulesCount; i++)
    {
		_strlwr(szModuleBase);
		_strlwr(pInfo->Modules[i].ImageName);
		//KdPrint(("%s, %s", szModuleBase, pInfo->Modules[i].ImageName));
		if(strstr(pInfo->Modules[i].ImageName, szModuleBase))
		{
			PVOID ulBase;
			//KdPrint(("Name:%s  Base:%08X  Size:%08X", pInfo->Modules[i].ImageName, pInfo->Modules[i].Base, pInfo->Modules[i].Size));
			ulBase = pInfo->Modules[i].Base;
			ExFreePool(pBuffer);
			return ulBase;
		}
    }
    ExFreePool(pBuffer);
	return NULL;
}

PVOID
MiFindExportedRoutineByName (
    IN PVOID DllBase,
    IN PANSI_STRING AnsiImageRoutineName
    )

/*++

Routine Description:

    This function searches the argument module looking for the requested
    exported function name.

Arguments:

    DllBase - Supplies the base address of the requested module.

    AnsiImageRoutineName - Supplies the ANSI routine name being searched for.

Return Value:

    The virtual address of the requested routine or NULL if not found.

--*/

{
    USHORT OrdinalNumber;
    PULONG NameTableBase;
    PUSHORT NameOrdinalTableBase;
    PULONG Addr;
    LONG High;
    LONG Low;
    LONG Middle;
    LONG Result;
    ULONG ExportSize;
    PVOID FunctionAddress;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;

//    PAGED_CODE();

    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY) RtlImageDirectoryEntryToData (
                                DllBase,
                                TRUE,
                                IMAGE_DIRECTORY_ENTRY_EXPORT,
                                &ExportSize);

    if (ExportDirectory == NULL) {
        return NULL;
    }

    //
    // Initialize the pointer to the array of RVA-based ansi export strings.
    //

    NameTableBase = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNames);

    //
    // Initialize the pointer to the array of USHORT ordinal numbers.
    //

    NameOrdinalTableBase = (PUSHORT)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);

    //
    // Lookup the desired name in the name table using a binary search.
    //

    Low = 0;
    Middle = 0;
    High = ExportDirectory->NumberOfNames - 1;

    while (High >= Low) {

        //
        // Compute the next probe index and compare the import name
        // with the export name entry.
        //

        Middle = (Low + High) >> 1;

        Result = strcmp (AnsiImageRoutineName->Buffer,
                         (PCHAR)DllBase + NameTableBase[Middle]);

        if (Result < 0) {
            High = Middle - 1;
        }
        else if (Result > 0) {
            Low = Middle + 1;
        }
        else {
            break;
        }
    }

    //
    // If the high index is less than the low index, then a matching
    // table entry was not found. Otherwise, get the ordinal number
    // from the ordinal table.
    //

    if (High < Low) {
        return NULL;
    }

    OrdinalNumber = NameOrdinalTableBase[Middle];

    //
    // If the OrdinalNumber is not within the Export Address Table,
    // then this image does not implement the function.  Return not found.
    //

    if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions) {
        return NULL;
    }

    //
    // Index into the array of RVA export addresses by ordinal number.
    //

    Addr = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfFunctions);

    FunctionAddress = (PVOID)((PCHAR)DllBase + Addr[OrdinalNumber]);

    //
    // Forwarders are not used by the kernel and HAL to each other.
    //

    ASSERT ((FunctionAddress <= (PVOID)ExportDirectory) ||
            (FunctionAddress >= (PVOID)((PCHAR)ExportDirectory + ExportSize)));

    return FunctionAddress;
}

void FixBaseRelocTable(IN PVOID ImageBase, IN PVOID OldImageBase)
{
	PIMAGE_BASE_RELOCATION ImageBaseReloc;
	ULONG RelocSize;
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(ImageDosHeader->e_lfanew + (ULONG)ImageBase);	


	ImageBaseReloc = RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &RelocSize);
	if(NULL == ImageBaseReloc)
	{
		KdPrint(("get reloc fail!!"));
		return ;
	}

	do
	{
		ULONG ItemCount;
		ULONG i;
		USHORT TypeOffset;
		ULONG RelocAddr;

		ItemCount = (ImageBaseReloc->SizeOfBlock - 8) / 2;
		for(i = 0; i < ItemCount; i++)
		{

			TypeOffset = ((PUSHORT)((ULONG)ImageBaseReloc+8))[i];
			if(TypeOffset>>12 == IMAGE_REL_BASED_HIGHLOW)
			{
				RelocAddr = ImageBaseReloc->VirtualAddress + (TypeOffset & 0x0FFF) + (ULONG)ImageBase;
				if(OldImageBase == NULL)
				{
					*(PULONG)RelocAddr = *(PULONG)RelocAddr + (ULONG)ImageBase - ImageNtHeaders->OptionalHeader.ImageBase;
				}
				else
				{
					*(PULONG)RelocAddr = *(PULONG)RelocAddr + (ULONG)OldImageBase - ImageNtHeaders->OptionalHeader.ImageBase;
				}
			}
		}
		ImageBaseReloc = (PIMAGE_BASE_RELOCATION)((ULONG)ImageBaseReloc + ImageBaseReloc->SizeOfBlock);

	}while(ImageBaseReloc->VirtualAddress);  //第一个VirtualAddress可能是0

	KdPrint(("fix reloc ok!!"));
}

#include "Driver.h"

PVOID FixNewKiServiceTable(IN PVOID ImageBase, IN PVOID OldImageBase)
{
	PIMAGE_BASE_RELOCATION ImageBaseReloc;
	ULONG RelocSize;
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(ImageDosHeader->e_lfanew + (ULONG)ImageBase);	

	ImageBaseReloc = RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &RelocSize);
	if(NULL == ImageBaseReloc)
	{
		KdPrint(("get reloc fail!!"));
		return NULL;
	}

	do
	{
		ULONG ItemCount;
		ULONG i;
		USHORT TypeOffset;
		ULONG RelocAddr;

		ItemCount = (ImageBaseReloc->SizeOfBlock - 8) / 2;
		for(i = 0; i < ItemCount; i++)
		{
			TypeOffset = ((PUSHORT)((ULONG)ImageBaseReloc+8))[i];
			if(TypeOffset>>12 == IMAGE_REL_BASED_HIGHLOW)
			{
				RelocAddr = ImageBaseReloc->VirtualAddress + (TypeOffset & 0x0FFF) + (ULONG)ImageBase;
				if(*(PULONG)RelocAddr == (ULONG)(KeServiceDescriptorTable))
				{
					// mov ds:_KeServiceDescriptorTable, offset _KiServiceTable
					if(*(PUSHORT)(RelocAddr - 2) == 0x05C7)
					{	
						ULONG j;
						PULONG NewKiServiceBase;

						NewKiServiceBase = (PULONG)(*(PULONG)(RelocAddr+4) - (ULONG)OldImageBase + (ULONG)ImageBase);
						for(j = 0; j < KeServiceDescriptorTable->Limit; j++)
						{
							NewKiServiceBase[j] = (ULONG)(KeServiceDescriptorTable->Base[j]) - \
								(ULONG)OldImageBase + (ULONG)ImageBase;
						}
						NewKeServiceDescriptorTable.Base = NewKiServiceBase;
						NewKeServiceDescriptorTable.Count = KeServiceDescriptorTable->Count;
						NewKeServiceDescriptorTable.Limit = KeServiceDescriptorTable->Limit;
						NewKeServiceDescriptorTable.Number = KeServiceDescriptorTable->Number;
						KdPrint(("Fix Service Table ok!!"));
						return NULL;
					}
				}
			}
		}
		ImageBaseReloc = (PIMAGE_BASE_RELOCATION)((ULONG)ImageBaseReloc + ImageBaseReloc->SizeOfBlock);
	}while(ImageBaseReloc->VirtualAddress);
	return NULL;
}
