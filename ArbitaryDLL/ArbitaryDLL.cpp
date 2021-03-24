#include <Windows.h>

BOOL APIENTRY DllMain(
	HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	UNREFERENCED_PARAMETER(hModule);
	UNREFERENCED_PARAMETER(ul_reason_for_call);
	UNREFERENCED_PARAMETER(lpReserved);

	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}

	return TRUE;
}

extern "C" __declspec(dllexport) void TestMe(
	LPVOID lpUserdata,
	DWORD nUserdataLen)
{
	UNREFERENCED_PARAMETER(lpUserdata);
	UNREFERENCED_PARAMETER(nUserdataLen);

	OutputDebugStringA("Hello there :)");
}

extern "C" __declspec(dllexport) int TestMe2()
{
	char msg[] = { 'h','e','l','l','o', 0};
	OutputDebugStringA(msg);
	__debugbreak();
	return 10;
}
