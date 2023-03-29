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
		while (!GetModuleHandleA("xinput1_3.dll"))
		{
			Sleep(100);
		}

		// ����û���һ��ʹ�û����ϴγ��������⵼��ʱ�����������ţ���ʱֹͣ
		if (m_pLeiGodData->Valid() && !m_pLeiGodData->m_bSuspend)
		{
			SuspendUserTime();
		}

		return;
	}
	void Initialize()
	{
		LeiGodBase = GetModuleHandle(NULL);
		if (!LeiGodBase)
		{
			ThrowError("����:\n LeiGodBase δ�ҵ�");
			return;
		}

		if (MH_Initialize() != MH_OK)
		{
			ThrowError("����:\n MinHook ��ʼ��ʧ��");
			return;
		}

		void* StartAccelerate = PatternScan::Find(LeiGodBase, "55 8B EC 6A FF 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 F0 53 56 57 50 8D 45 F4 64 A3 ? ? ? ? 8B F9 8B 5D 08 8D 8D ? ? ? ? 8B 43 04 83 C0 08 50 E8 ? ? ? ? 68 ? ? ? ? 8D 85 ? ? ? ? C7 45 ? ? ? ? ? 6A 00 50");
		if (!StartAccelerate)
		{
			ThrowError("����:\n���� StartAccelerate δ�ҵ�");
			return;
		}

		void* pResumeUserTime = function_walk(PatternScan::Find(LeiGodBase, "FF 90 ? ? ? ? 8B 46 04 6A 01"));
		if (!pResumeUserTime)
		{
			ThrowError("����:\n���� ResumeUserTime δ�ҵ�");
			return;
		}

		void* pSuspendUserTime = function_walk((void*)((uintptr_t)pResumeUserTime + 0x4));
		if (!pSuspendUserTime)
		{
			ThrowError("����:\n���� SuspendUserTime δ�ҵ�");
			return;
		}
		SuspendUserTime = (fnSuspendUserTime)pSuspendUserTime;

		void* pStopAccelerate = PatternScan::Find(LeiGodBase, "55 8B EC 6A FF 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 F0 56 57 50 8D 45 F4 64 A3 ? ? ? ? 8B F9 E8 ? ? ? ? 8B C8");
		if (!pStopAccelerate)
		{
			ThrowError("����:\n���� StopAccelerate δ�ҵ�");
			return;
		}

		void* pOnExit = function_walk(PatternScan::Find(LeiGodBase, "8B CE C7 86 ? ? ? ? ? ? ? ? E8 ? ? ? ? 8B 4D F4 64 89 0D ? ? ? ? 59 5E 8B 4D F0 33 CD E8 ? ? ? ? 8B E5 5D C2 04 00"));
		if (!pOnExit)
		{
			ThrowError("����:\n���� OnExit δ�ҵ�");
			return;
		}

		void* pWndProc = PatternScan::Find(LeiGodBase, "55 8B EC 56 8B 75 10 57 8B 7D 0C 81 FF ? ? ? ? 74 60 81 FF ? ? ? ? 0F 85 ? ? ? ? 83 7E 14 00 75 1B 33 C9 8D 46 10 87 08 FF 75 14 56 57 FF 75 08 FF 15 ? ? ? ? 5F");
		if (!pWndProc)
		{
			ThrowError("����:\n���� WndProc δ�ҵ�");
			return;
		}

		uintptr_t* pLeiGodData = *(uintptr_t**)(PatternScan::Find(LeiGodBase, "A3 ? ? ? ? 8D B8 ? ? ? ? 8B D7 8D 8D ? ? ? ? E8 ? ? ? ? 84 C0") + 1);

		m_pLeiGodData = (LeiGodData*)pLeiGodData;

		MH_CreateHook(StartAccelerate, hk_StartAccelerate, (void**)&oStartAccelerate);
		MH_CreateHook(pStopAccelerate, hk_StopAccelerate, (void**)&oStopAccelerate);

		MH_CreateHook(pResumeUserTime, hk_ResumeUserTime, (void**)&oResumeUserTime);

		MH_CreateHook(pOnExit, hk_OnExit, (void**)&oOnExit);

		MH_CreateHook(pWndProc, hk_WndProc, (void**)&oWndProc);

		MH_EnableHook(MH_ALL_HOOKS);

		CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)WaitForModule, 0, 0, 0));
	}

	int __fastcall hk_StartAccelerate(void* ecx, void* edx, int a2)
	{
		m_pAccelerateInfo = (AccelerateInfo*)ecx; // Ӧ���и�ָ������ṹ��ָ�룬����������

		m_bInAccelerate = true;

		oResumeUserTime();

		return oStartAccelerate(ecx, edx, a2);
	}

	int __fastcall hk_StopAccelerate(void* ecx, void* edx, int a2, int a3)
	{
		m_bInAccelerate = false;

		int iRet = oStopAccelerate(ecx, edx, a2, a3);

		SuspendUserTime();

		return iRet;
	}

	int __cdecl hk_ResumeUserTime()
	{
		// �����������û���ٵ�ʱ�򷴶����˼���
		if (!m_bInAccelerate)
			return 0;

		if (m_pAccelerateInfo->Valid() && !m_pAccelerateInfo->m_bInAccelerate)
			return 0;

		return oResumeUserTime();
	}

	int __fastcall hk_OnExit(void* ecx, void* edx, int a2, int a3, int a4, int a5)
	{
		// �п��������˳�������Ҫ����Ƿ��������ڼ�ʱ״̬
		SuspendUserTime();

		return oOnExit(ecx, edx, a2, a3, a4, a5);
	}

	LRESULT __stdcall hk_WndProc(HWND hwnd,UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		if (uMsg == WM_ENDSESSION && wParam == 1)
		{
			SuspendUserTime();
		}
		if (uMsg == WM_QUERYENDSESSION)
		{
			SuspendUserTime();
		}

		return oWndProc(hwnd, uMsg, wParam, lParam);
	}
}