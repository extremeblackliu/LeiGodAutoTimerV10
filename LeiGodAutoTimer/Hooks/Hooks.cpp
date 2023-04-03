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
		while (!GetModuleHandleA("libcef.dll"))
		{
			Sleep(1000);
		}
	}
	void Initialize()
	{
		CreateThread();

		if (MH_Initialize() != MH_OK)
		{
			ThrowError("´íÎó:\n MinHook ³õÊ¼»¯Ê§°Ü");
			return;
		}

		
		if (!StartAccelerate)
		{
			ThrowError("´íÎó:\nº¯Êý StartAccelerate Î´ÕÒµ½");
			return;
		}
		uintptr_t* pLeiGodData = *(uintptr_t**)(PatternScan::Find(LeiGodBase, "A3 ? ? ? ? 8D B8 ? ? ? ? 8B D7 8D 8D ? ? ? ? E8 ? ? ? ? 84 C0") + 1);


		MH_EnableHook(MH_ALL_HOOKS);

		CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)WaitForModule, 0, 0, 0));
	}
}