#include <iostream>
#include <vector>
#include <string>
#include <codecvt>
#include <filesystem>

#include <windows.h>
#include <Tlhelp32.h>

using namespace std;
namespace filesystem = std::experimental::filesystem;

const string kUsage = "Usage: HookLoader [-p pid] [-n name] [pids...] hooked_dll";

wstring utf8towcs(const string& utf8) {
	std::wstring_convert<codecvt<wchar_t, char, mbstate_t>> converter;
	return converter.from_bytes(utf8);
}

vector<int> FindProcessesPid(const wstring& processName) {
	vector<int> pids;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	BOOL bProcess = Process32First(hTool32, &pe32);
	if (bProcess == TRUE)
	{
		while ((Process32Next(hTool32, &pe32)) == TRUE)
			if (processName == pe32.szExeFile) {
				pids.push_back(pe32.th32ProcessID);
			}
	}
	CloseHandle(hTool32);

	return pids;
}

bool IsFlag(const string& opt) {
	return opt[0] == '-';
}

struct Options {
	vector<int> pids;
	filesystem::path hookedDllPath;

	static Options Parse(int argc, char** argv) {
		Options options;
		if (argc < 4) {
			cerr << kUsage << endl;
			exit(1);
		}

		options.hookedDllPath = filesystem::system_complete(utf8towcs(argv[argc - 1]));
		if (!filesystem::exists(options.hookedDllPath)) {
			cerr << "Hooked dll '" << options.hookedDllPath << "' does not exist" << endl;
			exit(1);
		}
		argv[argc - 1] = 0;

		char** parg = argv + 1;

		while (*parg) {
			char* arg = parg[0];
			if (IsFlag(arg)) {
				if (!parg[0]) {
					cerr << "Expecting value for option '" << arg << "'" << endl;
					cerr << kUsage << endl;
					exit(1);
				}

				switch (arg[1]) {
				case 'p':
					options.pids.push_back(atoi(parg[1]));
					break;
				case 'n':
				{
					vector<int> pids = FindProcessesPid(utf8towcs(parg[1]));
					options.pids.insert(options.pids.end(), pids.begin(), pids.end());
				}
					break;
				default:
					cerr << "Unknown option '" << arg << "'" << endl;
					cerr << kUsage << endl;
					exit(1);
				}

				parg += 2;
			}
			else {
				options.pids.push_back(atoi(arg));
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
	LPVOID pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	DWORD pathSize = (hookedDllPath.length() + 1) * 2;
	LPVOID lpParam = (LPVOID)VirtualAllocEx(hProcess, NULL, pathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!WriteProcessMemory(hProcess, lpParam, hookedDllPath.c_str(), pathSize, NULL)) {
		perror("WriteProcessMemory");
	}

	HANDLE hTh = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryW, lpParam, NULL, NULL);
	wcout << "Hooked '" << hookedDllPath << "' in process [" << hProcess << "] from thread [" << hTh << "]" << endl;
	CloseHandle(hProcess);
}

int main(int argc, char* argv[]) {
	Options options = Options::Parse(argc, argv);

	for (int pid : options.pids) {
		HookProcess(pid, options.hookedDllPath);
	}

	getchar();
	return 0;
}