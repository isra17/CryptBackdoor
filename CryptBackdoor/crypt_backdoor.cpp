#include <windows.h>
#include <stdio.h>
#include <cassert>
#include "mhook-lib/mhook.h"

const wchar_t* kAdvapi32 = L"advapi32.dll";
bool gCryptHooked = false;

typedef BOOL(WINAPI *CryptGenKeyPtr)(_In_  HCRYPTPROV, _In_  ALG_ID, _In_  DWORD, _Out_ HCRYPTKEY*);
CryptGenKeyPtr SavedCryptGenKey = nullptr;

BOOL WINAPI CryptGenKeyHook(
	_In_  HCRYPTPROV hProv,
	_In_  ALG_ID     Algid,
	_In_  DWORD      dwFlags,
	_Out_ HCRYPTKEY  *phKey) 
{
	puts("In CryptGenKeyHook");
	return SavedCryptGenKey(hProv, Algid, dwFlags, phKey);
}

void HookCrypt() {
	HMODULE hAdvapi32 = GetModuleHandle(kAdvapi32);
	SavedCryptGenKey = (CryptGenKeyPtr)GetProcAddress(hAdvapi32, "CryptGenKey");
	assert(SavedCryptGenKey);

	Mhook_SetHook((PVOID*)&SavedCryptGenKey, CryptGenKeyHook);

	gCryptHooked = true;
}

void UnhookCrypt() {
	if (gCryptHooked) {
		Mhook_Unhook((PVOID*)&SavedCryptGenKey);
	}
}

INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved) {
	switch (Reason) {
	case DLL_PROCESS_ATTACH:
		printf("Hello from injected dll [%x], reason %d\n", (unsigned int)hDLL, Reason);
		HookCrypt();
		break;
	case DLL_PROCESS_DETACH:
		printf("Unhooking injected dll...");
		UnhookCrypt();
		break;
	}
	return TRUE;
}