/*
 * Copyright (c) 2021 Miroslav Stampar (miroslav@sqlmap.org)
 * Copyright (c) 2014 CORE Security Technologies
 *
 * This software is provided under under the Apache Software License.
 * See the accompanying LICENSE file for more information.
 *
 * Win32 DLL entry point.
 *
 */

#include <windows.h>


BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
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

