#ifndef __HOOKSYSENTER__H__
#define __HOOKSYSENTER__H__

#include <NTDDK.h>

VOID SetSysenterHook();
VOID UnSysenterHook();
VOID SetHook(ULONG ulHookAddr, ULONG ulHookProc);
VOID UnHook(PUCHAR pat, ULONG patLength, PVOID ulHookAddr);
ULONG SundayFind(PUCHAR pat, ULONG patLength, PUCHAR text, ULONG textLength);

#define CloseWP() \
		_asm{cli}\
		_asm{mov eax, cr0}\
		_asm{and eax, ~0x10000}\
		_asm{mov cr0, eax}
#define OpenWP() \
		_asm{mov eax, cr0}\
		_asm{or eax, 0x10000}\
		_asm{mov cr0, eax}\
		_asm{sti}

#endif