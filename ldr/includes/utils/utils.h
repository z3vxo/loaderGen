#pragma once
#include "../../includes/core/core.h"
#include "../../includes/apis/apis.h"
#include <TlHelp32.h>








static inline HANDLE open_process_by_pid(DWORD pid) {
	HANDLE h = g_ldr->apis->OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	return h;
	
}

static inline HANDLE open_process_by_name(PWCHAR name) {
	if (!g_ldr->apis->pCreateToolhelp32Snapshot) {
		g_ldr->apis->pCreateToolhelp32Snapshot = (pCreateToolhelp32Snapshot)GetProc(g_ldr->apis->modules.kernel32, HASHED_CREATETOOLHELP32SNAPSHOT);
	}
	if (!g_ldr->apis->Process32NextW) {
		g_ldr->apis->Process32NextW = (pProcess32Next)GetProc(g_ldr->apis->modules.kernel32, HASHED_PROCESS32NEXTW);
	}
	if (!g_ldr->apis->Process32FirstW) {
		g_ldr->apis->Process32FirstW = (pProcess32First)GetProc(g_ldr->apis->modules.kernel32, HASHED_PROCESS32FIRSTW);
	}

	HANDLE s = g_ldr->apis->pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE hProc = NULL;

	if (g_ldr->apis->Process32FirstW(s, &pe)) {
		do {
			if (wcscmp(pe.szExeFile, name) == 0) {
				hProc = open_process_by_pid(pe.th32ProcessID);
				if (hProc) {
					g_ldr->apis->CloseHandle(s);
					return hProc;
				}
			}
		} while (g_ldr->apis->Process32NextW(s, &pe));
	}
	g_ldr->apis->CloseHandle(s);
	return hProc;
	Process32NextW
}

static inline HANDLE open_first_process() {
	if (!g_ldr->apis->pCreateToolhelp32Snapshot) {
		g_ldr->apis->pCreateToolhelp32Snapshot = (pCreateToolhelp32Snapshot)GetProc(g_ldr->apis->modules.kernel32, HASHED_CREATETOOLHELP32SNAPSHOT);
	}
	if (!g_ldr->apis->Process32NextW) {
		g_ldr->apis->Process32NextW = (pProcess32Next)GetProc(g_ldr->apis->modules.kernel32, HASHED_PROCESS32NEXTW);
	}
	if (!g_ldr->apis->Process32FirstW) {
		g_ldr->apis->Process32FirstW = (pProcess32First)GetProc(g_ldr->apis->modules.kernel32, HASHED_PROCESS32FIRSTW);
	}

	HANDLE s = g_ldr->apis->pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hProc = NULL;

	if (g_ldr->apis->Process32FirstW(s, &pe)) {
		do {
			hProc = g_ldr->apis->OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
			if (hProc) {
				g_ldr->apis->CloseHandle(s);
				break;
			}
		} while (g_ldr->apis->Process32NextW(s, &pe));
	}
	g_ldr->apis->CloseHandle(s);
	return hProc;
}

static inline HANDLE resolve_target_process() {
	if (g_ldr->config->remoteSettings.pid != 0) {
		HANDLE h = open_process_by_pid(g_ldr->config->remoteSettings.pid);
		if (h) return h;
	}

	if (g_ldr->config->remoteSettings.ProcessName[0] != '\0') {
		HANDLE h = open_process_by_name(g_ldr->config->remoteSettings.ProcessName);
		if (h) return h;
	}

	return open_first_process();
}


