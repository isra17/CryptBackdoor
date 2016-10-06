#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>

void PrintHex(char* data, int size) {
  for (int i = 0; i < size; i++) {
    printf("%02X ", (unsigned char)data[i]);
    if (i % 4 == 3)
      printf(" ");
    if (i % 8 == 7)
      printf(" ");
    if (i % 16 == 15)
      printf("\n");
  }
}

void PrintError(char* name) {
  fprintf(stderr, "Error: %s: %x\n", name, GetLastError());
}

int main(int argc, char* argv[]) {
  HCRYPTPROV hProv;
  HCRYPTKEY hKey;

  if (argc != 2) {
    fprintf(stderr, "Usage: CryptTest <data>\n");
    exit(1);
  }

  char* plaintext = argv[1];

  if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL,
                            CRYPT_VERIFYCONTEXT)) {
    PrintError("CryptAcquireContext");
  }

  while (1) {
    puts("Generating key...");

    if (!CryptGenKey(hProv, CALG_RC2, 0x800000, &hKey)) {
      PrintError("CryptGenKey");
    }

    puts("New key generated...");

    DWORD plaintextSize = strlen(plaintext);
    DWORD cipherSize = plaintextSize;
    if (!CryptEncrypt(hKey, 0, 1, 0, 0, &cipherSize, 0)) {
      PrintError("CryptEncrypt[0]");
    }

    BYTE* data = (BYTE*)malloc(cipherSize);
    strncpy_s(data, cipherSize, plaintext, plaintextSize);
    if (!CryptEncrypt(hKey, 0, 1, 0, data, &plaintextSize, cipherSize)) {
      PrintError("CryptEncrypt[0]");
    }

    puts("Encrypted data:");
    PrintHex(data, cipherSize);
    puts("\n\n");

    if (!CryptDestroyKey(hKey)) {
      PrintError("CryptDestroyKey");
    }

    Sleep(5000);
  }

  if (!CryptReleaseContext(hProv, 0)) {
    PrintError("CryptReleaseContext");
  }
  getchar();
  return 0;
}
