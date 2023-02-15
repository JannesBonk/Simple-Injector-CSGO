#include <Windows.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <TlHelp32.h>
#include <algorithm>
#include <thread>
#include <Mmsystem.h>
#pragma comment (lib,"winmm.lib")  

using namespace std;
string namedll;
DWORD pid;
HANDLE process;
HWND hwndproc;
DWORD clientDLL;

DWORD get_proc_id(const char* proc_name)
{
	DWORD proc_id = 0;
	auto* const h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (h_snap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 proc_entry;
		proc_entry.dwSize = sizeof(proc_entry);

		if (Process32First(h_snap, &proc_entry))
		{
			do
			{
				if (!_stricmp(proc_entry.szExeFile, proc_name))
				{
					proc_id = proc_entry.th32ProcessID;
					break;
				}
			} while (Process32Next(h_snap, &proc_entry));
		}
	}

	CloseHandle(h_snap);
	return proc_id;
}

DWORD GetModule(DWORD pid, const char* name)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32 mEntry;
	mEntry.dwSize = sizeof(MODULEENTRY32);
	do
	{
		if (!strcmp(mEntry.szModule, name))
		{
			CloseHandle(snapshot);
			return (DWORD)mEntry.modBaseAddr;
		}
	} while (Module32Next(snapshot, &mEntry));
}

void main() noexcept
{
	SetConsoleTitle("Injector by JannesBonk#7012");
	hwndproc = FindWindowA(0, "Counter-Strike: Global Offensive - Direct3D 9");
	GetWindowThreadProcessId(hwndproc, &pid);
	process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	clientDLL = GetModule(pid, "client.dll");
	HWND status = FindWindowA(0, "Counter-Strike: Global Offensive - Direct3D 9");
	GetWindowThreadProcessId(status, &pid);
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	DWORD client = GetModule(pid, "client.dll");
	char dll_path[512];
	cout << "Enter DLL path or drag and drop your DLL here" << endl;
	cin >> dll_path;
	if (pid > 1)
	{
		{
			const char* proc_name = "csgo.exe";
			DWORD proc_id = 0;

			while (!proc_id)
			{
				proc_id = get_proc_id(proc_name);
				Sleep(30);
			}

			auto* const h_proc = OpenProcess(PROCESS_ALL_ACCESS, 0, proc_id);

			if (h_proc && h_proc != INVALID_HANDLE_VALUE)
			{
				const LPVOID nt_open_file = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");//ggez
				if (nt_open_file)
				{
					char original_bytes[5];
					memcpy(original_bytes, nt_open_file, 5);
					WriteProcessMemory(h_proc, nt_open_file, original_bytes, 5, nullptr);
				}

				auto* loc = VirtualAllocEx(h_proc, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				WriteProcessMemory(h_proc, loc, dll_path, strlen(dll_path) + 1, nullptr);
				auto* const h_thread = CreateRemoteThread(h_proc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), loc, 0, nullptr);

				if (h_thread)CloseHandle(h_thread);
			}
		}
		cout << "File injcected succesfully!" << endl;
		PlaySoundA(TEXT("C:\\Windows\\Media\\notify.wav"), 0, 0);
		system("pause");
	}
	else
	{
		cout << "CSGO is not detect, please open csgo so i can inject the DLL" << endl;
		while (true)
		{
			const char* proc_name = "csgo.exe";
			DWORD proc_id = 0;

			while (!proc_id)
			{
				proc_id = get_proc_id(proc_name);
				Sleep(30);
			}

			HWND status = FindWindow(0, "Counter-Strike: Global Offensive - Direct3D 9");
			GetWindowThreadProcessId(status, &pid);
			HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
			DWORD client = GetModule(pid, "client.dll");

			if (pid > 1)
			{
				cout << "CSGO found! Injecting DLL" << endl;
				break;
			}
		}
		Sleep(5500);
		{
			const char* proc_name = "csgo.exe";
			DWORD proc_id = 0;

			while (!proc_id)
			{
				proc_id = get_proc_id(proc_name);
				Sleep(30);
			}

			auto* const h_proc = OpenProcess(PROCESS_ALL_ACCESS, 0, proc_id);

			if (h_proc && h_proc != INVALID_HANDLE_VALUE)
			{
				const LPVOID nt_open_file = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");//ggez
				if (nt_open_file)
				{
					char original_bytes[5];
					memcpy(original_bytes, nt_open_file, 5);
					WriteProcessMemory(h_proc, nt_open_file, original_bytes, 5, nullptr);
				}

				auto* loc = VirtualAllocEx(h_proc, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				WriteProcessMemory(h_proc, loc, dll_path, strlen(dll_path) + 1, nullptr);
				auto* const h_thread = CreateRemoteThread(h_proc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), loc, 0, nullptr);

				if (h_thread)CloseHandle(h_thread);
			}
		}
		cout << "DLL injcected succesfully!" << endl;
		PlaySoundA("C:\\Windows\\Media\\notify.wav", 0, 0);
		system("pause");
	}
}
