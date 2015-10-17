#include <windows.h>
#include <stdio.h>
#include <cassert>
#include "mhook-lib/mhook.h"

const wchar_t* kAdvapi32 = L"advapi32.dll";
bool gCryptHooked = false;

typedef BOOL(WINAPI *CryptGenKeyPtr)(_In_  HCRYPTPROV, _In_  ALG_ID, _In_  DWORD, _Out_ HCRYPTKEY*);
CryptGenKeyPtr SavedCryptGenKey = nullptr;


struct PLAINTEXTKEYBLOB_t {
	BLOBHEADER hdr;
	DWORD      dwKeySize;
	BYTE       rgbKeyData[];
};

BOOL GenWeakKey(DWORD keySize, ALG_ID algid, BYTE** blob, DWORD* blobSize) {
	*blobSize = sizeof(PLAINTEXTKEYBLOB_t) + keySize;
	PLAINTEXTKEYBLOB_t* keyBlob = (PLAINTEXTKEYBLOB_t*)malloc(*blobSize);
	*blob = (BYTE*)keyBlob;
	keyBlob->hdr.bType = PLAINTEXTKEYBLOB;
	keyBlob->hdr.bVersion = CUR_BLOB_VERSION;
	keyBlob->hdr.reserved = 0;
	keyBlob->hdr.aiKeyAlg = algid;
	keyBlob->dwKeySize = keySize;
	memset(keyBlob->rgbKeyData, 0, keySize);

	return TRUE;
}

BOOL WINAPI CryptGenKeyHook(
	_In_  HCRYPTPROV hProv,
	_In_  ALG_ID     Algid,
	_In_  DWORD      dwFlags,
	_Out_ HCRYPTKEY  *phKey) 
{

	puts("In CryptGenKeyHook...");

	DWORD keySize = dwFlags >> 16;
	if (keySize) {
		BYTE* keyBlob;
		DWORD keyBlobSize;
		if (GenWeakKey(keySize, Algid, &keyBlob, &keyBlobSize)) {
			printf("Generate weak key, size: %d, blob: %d", keySize, keyBlobSize);
			return CryptImportKey(hProv, keyBlob, keyBlobSize, 0, 0, phKey);
		}
	}

	puts("Using true CryptGenKey...");
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