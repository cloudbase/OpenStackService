/*
Copyright 2012 Cloudbase Solutions Srl
All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
*/

#pragma region Includes
#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include "ServiceBase.h"
#include "OpenStackService.h"
#pragma endregion

int wmain(int argc, wchar_t *argv[])
{
    if(argc <= 2)
    {
        wprintf(L"Usage: OpenStackService <ServiceName> <PythonExe> [Arguments]\n");
        return -1;
    }

    TCHAR cmdLine[MAX_SVC_PATH];
    cmdLine[0] = NULL;
    for(int i = 2; i < argc; i++)
    {
        TCHAR buf[MAX_SVC_PATH];
        if(i > 2)
            _tcscat_s(cmdLine, MAX_SVC_PATH, _T(" "));
        _stprintf_s(buf, _T("\"%s\""), argv[i]);
        _tcscat_s(cmdLine, MAX_SVC_PATH, buf);
    }

    //wprintf(cmdLine);

    CWrapperService service(argv[1], cmdLine);
    if (!CServiceBase::Run(service))
    {
        wprintf(L"Service failed to run w/err 0x%08lx\n", GetLastError());
    }

    return 0;
}
