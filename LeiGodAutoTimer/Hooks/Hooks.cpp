#include "Hooks.h"

#include "minhook/include/MinHook.h"

static void* function_walk(void* StartAddress, unsigned int TillByte = 0x6AEC8B55)
{
	unsigned int* m_cStep = (unsigned int*)StartAddress;
	while (*m_cStep != TillByte)
	{
		m_cStep = (unsigned int*)((uintptr_t)m_cStep + 1);
	}
	return m_cStep;
}

namespace Hooks
{
	void WaitForModule()
	{
	}

	int __stdcall hkWSASend(void* s, void* lpBuffers, int dwBufferCount, void* lpNumberOfBytesSent, int dwFlags, void* lpOverlapped, void* lpCompletionRoutine)
	{
		DWORD HttpHeader = *(DWORD*)((uintptr_t)lpBuffers + 0x8);
		if (HttpHeader == 0x20544547 || HttpHeader == 'POST') // GET  
		{
			std::fstream f("log.txt", std::ios::app);
			const char* HttpInfo = (const char*)((char*)lpBuffers + 0x8);
			char* HttpEnd = (char*)HttpInfo;
			while (*(DWORD*)HttpEnd != 0x0A0D0A0D)
			{
				HttpEnd++;
			}
			std::string HttpInfoCorrention(HttpInfo, (size_t)((uintptr_t)HttpEnd - (uintptr_t)HttpInfo));
			
			f << HttpInfoCorrention;
			f << "\n\n";
			f.close();
		}
		// 这里hook没截获到什么有用的信息...敌军尚有严防，有待明日再探
		return OWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
	}

	void Initialize()
	{
		LeiGodBase = GetModuleHandleA(NULL);
		if (!LeiGodBase)
		{
			ThrowError("错误:\n GetModuleHandleA(NULL) == 0");
			return;
		}

		if (MH_Initialize() != MH_OK)
		{
			ThrowError("错误:\n MinHook 初始化失败");
			return;
		}
		
		MH_CreateHookApi(L"ws2_32.dll", "WSASend", hkWSASend, (void**)&OWSASend);
		

		MH_EnableHook(MH_ALL_HOOKS);

		//CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)WaitForModule, 0, 0, 0));
	}
}