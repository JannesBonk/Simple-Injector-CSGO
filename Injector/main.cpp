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

bool inject(DWORD pid, const char* dll)
{
	char myDLL[MAX_PATH];
	GetFullPathNameA(dll, MAX_PATH, myDLL, 0);
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
	LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, sizeof(myDLL), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, allocatedMem, myDLL, sizeof(myDLL), NULL);
	CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, allocatedMem, 0, 0);
	CloseHandle(hProcess);
	return TRUE;
}

DWORD GetModule(DWORD pid, const char* name)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32A mEntry;
	mEntry.dwSize = sizeof(MODULEENTRY32A);
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
	SetConsoleTitle("Injector by Jannes#7012");
	hwndproc = FindWindowA(0, "Counter-Strike: Global Offensive - Direct3D 9");
	GetWindowThreadProcessId(hwndproc, &pid);
	process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	clientDLL = GetModule(pid, "client.dll");
	HWND status = FindWindowA(0, "Counter-Strike: Global Offensive - Direct3D 9");
	GetWindowThreadProcessId(status, &pid);
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	DWORD client = GetModule(pid, "client.dll");
	char dllpath[512];
	if (pid > 1)
		cout << "CSGO detected!" << endl;
	else
		cout << "CSGO is not running, injector will auto-launch after entering dll path" << endl;
	cout << "" << endl;
	cout << "Enter DLL path or drag and drop your DLL here" << endl;
	cin >> dllpath;
	if (pid > 1)
	{
		inject(pid, dllpath);
		cout << "File injcected succesfully!" << endl;
		PlaySoundA(TEXT("C:\\Windows\\Media\\notify.wav"), 0, 0);
		system("pause");
	}
	else
	{
		ShellExecuteA(NULL, "open", "steam://rungameid/730", NULL, NULL, SW_SHOWNORMAL);
		while (true)
		{
			HWND status = FindWindow(0, "Counter-Strike: Global Offensive - Direct3D 9");
			GetWindowThreadProcessId(status, &pid);
			HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
			DWORD client = GetModule(pid, "client.dll");

			if (pid > 1)
				break;
		}
		Sleep(7500);
		inject(pid, dllpath);
		cout << "File injcected succesfully!" << endl;
		PlaySoundA("C:\\Windows\\Media\\notify.wav", 0, 0);
		system("pause");
	}
}
