#include <iostream>
#include <vector>
#include <string>
#include <codecvt>
#include <locale>
#include <cassert>

#include <windows.h>
#include <tlhelp32.h>

using namespace std;

const wchar_t kUsage[] = L"Usage: HookLoader [-p pid] [-n name] [pids...] hooked_dll";

vector<int> FindProcessesPid(const wstring& processName) {
	vector<int> pids;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	BOOL bProcess = Process32First(hTool32, &pe32);
	if (bProcess == TRUE)
	{
		while ((Process32Next(hTool32, &pe32)) == TRUE) {
			if (processName == pe32.szExeFile) {
				pids.push_back(pe32.th32ProcessID);
			}
    }
	}
	CloseHandle(hTool32);

	return pids;
}

bool IsFlag(const wstring& opt) {
	return opt[0] == L'-';
}

bool FileExists(const wstring& path) {
  if (FILE *file = _wfopen(path.c_str(), L"r")) {
    fclose(file);
    return true;
  } else {
    return false;
  }
}

struct Options {
	vector<int> pids;
  std::wstring hookedDllPath;

	static Options Parse(int argc, wchar_t** argv) {
		Options options;
		if (argc < 4) {
			wcerr << kUsage << endl;
			exit(1);
		}

		options.hookedDllPath = argv[argc - 1];
		if (!FileExists(options.hookedDllPath)) {
			wcerr << "Hooked dll '" << options.hookedDllPath << "' does not exist" << endl;
			exit(1);
		}
		argv[argc - 1] = 0;

		wchar_t** parg = argv + 1;

		while (*parg) {
			wchar_t* arg = parg[0];
			if (IsFlag(arg)) {
				if (!parg[0]) {
					wcerr << "Expecting value for option '" << arg << "'" << endl;
					wcerr << kUsage << endl;
					exit(1);
				}

				switch (arg[1]) {
				case L'p':
					options.pids.push_back(_wtoi(parg[1]));
					break;
				case L'n':
				{
					vector<int> pids = FindProcessesPid(parg[1]);
					options.pids.insert(options.pids.end(), pids.begin(), pids.end());
				}
					break;
				default:
					wcerr << "Unknown option '" << arg << "'" << endl;
					wcerr << kUsage << endl;
					exit(1);
				}

				parg += 2;
			}
			else {
				options.pids.push_back(_wtoi(arg));
				parg += 1;
			}
		}

		return options;
	}

};

void HookProcess(int pid, const wstring& hookedDllPath) {
	HANDLE hProcess = OpenProcess(
		PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , false, pid);
  assert(hProcess);

	LPVOID pLoadLibraryW = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
  assert(pLoadLibraryW);

	DWORD pathSize = (hookedDllPath.length() * 2 + 1);
	LPVOID lpParam = (LPVOID)VirtualAllocEx(hProcess, NULL, pathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  assert(lpParam);

	if (!WriteProcessMemory(hProcess, lpParam, hookedDllPath.c_str(), pathSize, NULL)) {
		perror("WriteProcessMemory");
	}

	HANDLE hTh = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryW, lpParam, NULL, NULL);
	wcout << "Hooked '" << hookedDllPath << "' in process [" << hProcess << "] from thread [" << hTh << "]" << endl;
	CloseHandle(hProcess);
}

extern "C" {

int wmain(int argc, wchar_t* argv[]) {
	Options options = Options::Parse(argc, argv);

	for (int pid : options.pids) {
		HookProcess(pid, options.hookedDllPath);
	}

	return 0;
}

} // extern "C"
