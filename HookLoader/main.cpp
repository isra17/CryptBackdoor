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
const wstring kKernel32 = L"kernel32.dll";


struct ProcessInfo {
	DWORD pid;
	wstring exeFile;
	HMODULE hKernel32;
};

wstring utf8towcs(const string& utf8) {
	std::wstring_convert<codecvt<wchar_t, char, mbstate_t>> converter;
	return converter.from_bytes(utf8);
}


ProcessInfo ProcessInfoFromPid(int pid) {
	ProcessInfo process;
	process.pid = pid;

	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);
	BOOL bModule = Module32First(hTool32, &me32);
	if (bModule == TRUE)
	{
		process.exeFile = me32.szExePath;
		while ((Module32Next(hTool32, &me32)) == TRUE)
			if (kKernel32 == me32.szExePath) {
				process.hKernel32 = me32.hModule;
			}
	}
	CloseHandle(hTool32);

	return process;
}


vector<ProcessInfo> FindProcesses(const wstring& processName) {
	vector<ProcessInfo> processes;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	BOOL bProcess = Process32First(hTool32, &pe32);
	if (bProcess == TRUE)
	{
		while ((Process32Next(hTool32, &pe32)) == TRUE)
			if (processName == pe32.szExeFile) {
				processes.push_back(ProcessInfoFromPid(pe32.th32ProcessID));
			}
	}
	CloseHandle(hTool32);

	return processes;
}

bool IsFlag(const string& opt) {
	return opt[0] == '-';
}


struct Options {
	vector<ProcessInfo> processes;
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
					options.processes.push_back(ProcessInfoFromPid(atoi(parg[1])));
					break;
				case 'n':
				{
					vector<ProcessInfo> processes = FindProcesses(utf8towcs(parg[1]));
					options.processes.insert(options.processes.end(), processes.begin(), processes.end());
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
				options.processes.push_back(ProcessInfoFromPid(atoi(arg)));
				parg += 1;
			}
		}

		return options;
	}

};

void HookProcess(const ProcessInfo& process, const wstring& hookedDllPath) {
	HANDLE hProcess = OpenProcess(
		PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.pid);
	LPVOID pLoadLibraryW = GetProcAddress(process.hKernel32, "LoadLibraryW");
	DWORD pathSize = (hookedDllPath.length() + 1) * 2;
	LPVOID lpParam = (LPVOID)VirtualAllocEx(hProcess, NULL, pathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!WriteProcessMemory(hProcess, lpParam, hookedDllPath.c_str(), pathSize, NULL)) {
		perror("WriteProcessMemory");
	}

	HANDLE hTh = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryW, lpParam, NULL, NULL);
	wcout << "Hooked '" << hookedDllPath << "' in process " << process.exeFile << " [" << hProcess << "] from thread [" << hTh << "]" << endl;
	CloseHandle(hProcess);
}

int main(int argc, char* argv[]) {
	Options options = Options::Parse(argc, argv);

	for (auto process : options.processes) {
		HookProcess(process, options.hookedDllPath);
	}

	getchar();
	return 0;
}