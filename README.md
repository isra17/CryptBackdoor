# CryptBackdoor
This project injects a DLL in a running process (Using PID or process name) to hook and 
intercept call to `CryptGenKey`. If possible, a null key is imported instead of an 
unknown random key. The hook is really simple and might not work for every case.

This backdoor can be useful when doing network analysis encrypted with session key 
from CryptGenKey on a machine controlled by the analyst.

# Usage
To load the CryptBackdoor in the process and generate a null key, use:
```
HookLoader.exe -n CryptTest.exe CryptBackdoor.dll
```
After running this command, running CryptTest.exe processes should now generate the same
key on each message.

# Projects
## CryptTest
Small utility that generate a key in loop and encrypt a given plaintext. Used to test
the CryptBackdoor loader and DLL.

## HookLoader
Utility to load a DLL in a process from its name or PID.

## CryptBackdoor
DLL that hook to CryptGenKey and generate a weak known key instead of a random key. The 
hook is set up by the [mhook](https://github.com/martona/mhook) projet.
