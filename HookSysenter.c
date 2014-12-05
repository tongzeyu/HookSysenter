#include "HookSysenter.h"
#include "KeLoadLibrary.h"

ULONG display(ULONG ServiceTableBase,ULONG FuncIndex,ULONG OrigFuncAddress)
{
	if(ServiceTableBase == (ULONG)KeServiceDescriptorTable->Base)
	{
		if (!strncmp((char*)PsGetCurrentProcess()+0x174,"Olly", 4))
		{
			//KdPrint(("ProcessName:%s", (char*)PsGetCurrentProcess()+0x174));
			//return OrigFuncAddress;
			return NewKeServiceDescriptorTable.Base[FuncIndex];
		}
	}
	return OrigFuncAddress;
}


ULONG ulHookSysenter;
VOID __declspec(naked) MyKiFastCallEntry()
{
	_asm
	{

		pushad
		pushfd
		
		push  ebx
		push  eax
		push  edi
		call  display
		//再返回前修改堆栈里的数据
		mov    [esp+0x14],eax
		popfd
		popad

		sub     esp,ecx
		shr     ecx,2
		jmp ulHookSysenter
	}
}

VOID SetSysenterHook()
{
	LONG pfKiFastCallEntry;
	_asm
	{
		mov ecx, 0x176
		rdmsr
		mov pfKiFastCallEntry, eax
	}
	KdPrint(("KiFastCallEntry:%08X", pfKiFastCallEntry));
	ulHookSysenter = SundayFind("\x2B\xE1\xC1\xE9\x02\x8B\xFC", 7, (PCHAR)pfKiFastCallEntry, 1000);
	if(-1 == ulHookSysenter)
		return ;

	KdPrint(("hook sysenter 位置%08X", ulHookSysenter));
	SetHook(ulHookSysenter, (ULONG)(MyKiFastCallEntry));
	ulHookSysenter += 5;
}

VOID UnSysenterHook()
{
	UnHook((PUCHAR)"\x2B\xE1\xC1\xE9\x02\x8B\xFC", 7, (PVOID)(ulHookSysenter-5));
}

VOID SetHook(ULONG ulHookAddr, ULONG ulHookProc)
{
	CloseWP();
	*(PUCHAR)ulHookAddr = 0xE9;
	*(PULONG)(ulHookAddr+1) = ulHookProc - ulHookAddr - 5;
	OpenWP();
}

VOID UnHook(PUCHAR pat, ULONG patLength, PVOID ulHookAddr)
{
	CloseWP();
	memcpy(ulHookAddr, pat, patLength);
	OpenWP();
}

ULONG SetSSDTHook(PULONG ServiceTableBase, ULONG index, ULONG ulHookProc)
{
	ULONG pfAddr = ServiceTableBase[index];
	CloseWP();
	ServiceTableBase[index] = ulHookProc;
	OpenWP();
	return pfAddr;
}

VOID UnSSDTHook(PULONG ServiceTableBase, ULONG index, ULONG ulHookProc)
{
	CloseWP();
	ServiceTableBase[index] = ulHookProc;
	OpenWP();
}

ULONG MmGetSystemFunAddress(PWSTR Buffer)
{
	UNICODE_STRING SystemRoutineName;
	RtlInitUnicodeString(&SystemRoutineName, Buffer);
	return (ULONG)MmGetSystemRoutineAddress(&SystemRoutineName);
}


ULONG SundayFind(PUCHAR pat, ULONG patLength, PUCHAR text, ULONG textLength)
{
	UCHAR MovDistance[0x100];
	ULONG i = 0;
	PUCHAR tx = text;

	if(textLength <= 0)
		return -1;

	memset(MovDistance, patLength+1, 0x100);
	for(i = 0; i < patLength; i++)
	{
		MovDistance[pat[i]] = (UCHAR)(patLength - i);
	}
	
	while(tx+patLength <= text+textLength)
	{
		UCHAR *p = pat, *t = tx;
		ULONG i = 0;
		for(i = 0; i < patLength; i++)
		{
			if(p[i] != t[i])
				break;
		}
		if(i == patLength)
			return (ULONG)tx;
		if(tx+patLength == text+textLength)
			return -1;
		tx += MovDistance[tx[patLength]];
	}
	return -1;
}
