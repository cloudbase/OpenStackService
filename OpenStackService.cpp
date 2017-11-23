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
#include "OpenStackService.h"
#include <windows.h>
#include <strsafe.h>
#include <direct.h>
#include <string.h>
#include <locale>
#include <codecvt>
#include <regex>
#include <sstream>
#include <TlHelp32.h>
#pragma endregion

#define MAX_WAIT_CHILD_PROC (5 * 1000)

using namespace std;

CWrapperService::CWrapperService(LPCWSTR pszServiceName,
                                 LPCWSTR szCmdLine,
                                 LPCWSTR szExecStartPreCmdLine,
                                 const EnvMap& environment,
                                 BOOL fCanStop,
                                 BOOL fCanShutdown,
                                 BOOL fCanPauseContinue)
                                 : CServiceBase(pszServiceName, fCanStop, fCanShutdown, fCanPauseContinue)
{
    if(!environment.empty())
    {
        for (auto& kv : environment)
            m_envBuf += kv.first + L"=" + kv.second + L'\0';
        m_envBuf += L'\0';
    }

    if(szExecStartPreCmdLine)
        m_ExecStartPreCmdLine = szExecStartPreCmdLine;

    m_CmdLine = szCmdLine;
    m_WaitForProcessThread = NULL;
    m_dwProcessId = 0;
    m_hProcess = NULL;
    m_IsStopping = FALSE;
}

CWrapperService::~CWrapperService(void)
{
    if (m_hProcess)
    {
        ::CloseHandle(m_hProcess);
        m_hProcess = NULL;
    }

    if (m_WaitForProcessThread)
    {
        ::CloseHandle(m_WaitForProcessThread);
        m_WaitForProcessThread = NULL;
    }
}

PROCESS_INFORMATION CWrapperService::StartProcess(LPCWSTR cmdLine, bool waitForProcess)
{
    PROCESS_INFORMATION processInformation;
    STARTUPINFO startupInfo;
    memset(&processInformation, 0, sizeof(processInformation));
    memset(&startupInfo, 0, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);

    DWORD dwCreationFlags = CREATE_NO_WINDOW | NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT;

    LPVOID lpEnv = NULL;
    if (!m_envBuf.empty())
        lpEnv = &m_envBuf[0];

    DWORD tempCmdLineCount = lstrlen(cmdLine) + 1;
    LPWSTR tempCmdLine = new WCHAR[tempCmdLineCount];  //Needed since CreateProcessW may change the contents of CmdLine
    wcscpy_s(tempCmdLine, tempCmdLineCount, cmdLine);

    BOOL result = ::CreateProcess(NULL, tempCmdLine, NULL, NULL, FALSE, dwCreationFlags,
        lpEnv, NULL, &startupInfo, &processInformation);

    delete[] tempCmdLine;

    if (!result)
    {
        DWORD err = GetLastError();
        wostringstream os;
        os << L"Error " << hex << err << L" while spawning the process: " << cmdLine;
        WriteEventLogEntry(os.str().c_str(), EVENTLOG_ERROR_TYPE);

        string str = wstring_convert<codecvt_utf8<WCHAR>>().to_bytes(os.str());
        throw exception(str.c_str());
    }

    if(waitForProcess)
    {
        ::WaitForSingleObject(processInformation.hProcess, INFINITE);
        ::CloseHandle(processInformation.hProcess);
    }

    return processInformation;
}

void CWrapperService::OnStart(DWORD dwArgc, LPWSTR *lpszArgv)
{
    m_IsStopping = FALSE;

    if (!m_ExecStartPreCmdLine.empty())
    {
        wostringstream os;
        os << L"Running ExecStartPre command: " << m_ExecStartPreCmdLine;
        WriteEventLogEntry(os.str().c_str(), EVENTLOG_INFORMATION_TYPE);
        StartProcess(m_ExecStartPreCmdLine.c_str(), true);
    }

    wostringstream os;
    os << L"Starting service: " << m_CmdLine;
    WriteEventLogEntry(os.str().c_str(), EVENTLOG_INFORMATION_TYPE);
    auto processInformation = StartProcess(m_CmdLine.c_str());

    m_dwProcessId = processInformation.dwProcessId;
    m_hProcess = processInformation.hProcess;

    DWORD tid;
    m_WaitForProcessThread = ::CreateThread(NULL, 0, WaitForProcessThread, this, 0, &tid);

    /*
    // We will send CTRL+C to the child process to end it. Set the handler to NULL in parent process.
    if(!::SetConsoleCtrlHandler(NULL, TRUE))
    {
    throw GetLastError();
    }
    */
}

DWORD WINAPI CWrapperService::WaitForProcessThread(LPVOID lpParam)
{
    CWrapperService* self = (CWrapperService*)lpParam;

    ::WaitForSingleObject(self->m_hProcess, INFINITE);
    ::CloseHandle(self->m_hProcess);
    self->m_hProcess = NULL;

    // TODO: think about respawning the child process
    if(!self->m_IsStopping)
    {
        self->WriteEventLogEntry(L"Child process ended", EVENTLOG_ERROR_TYPE);
        ::ExitProcess(-1);
    }

    return 0;
}

void WINAPI CWrapperService::KillProcessTree(DWORD dwProcId)
{
    PROCESSENTRY32 pe;
    memset(&pe, 0, sizeof(PROCESSENTRY32));
    pe.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnap = :: CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (::Process32First(hSnap, &pe))
    {
        BOOL bContinue = TRUE;
        while (bContinue)
        {
            if (pe.th32ParentProcessID == dwProcId)
            {
                KillProcessTree(pe.th32ProcessID);

                HANDLE hProc = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
                if (hProc)
                {
                    ::TerminateProcess(hProc, 0);
                    ::CloseHandle(hProc);
                }
            }
            bContinue = ::Process32Next(hSnap, &pe);
        }

        HANDLE hProc = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcId);
        if (hProc)
        {
            ::TerminateProcess(hProc, 1);
            ::CloseHandle(hProc);
        }
    }

    ::CloseHandle(hSnap);
}

void CWrapperService::OnStop()
{
    WriteEventLogEntry(L"Stopping service", EVENTLOG_INFORMATION_TYPE);

    m_IsStopping = TRUE;

/*
    if(!::GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0))
        WriteEventLogEntry(L"Error while sending CTRL BREAK to a child process", EVENTLOG_WARNING_TYPE);

    if(::WaitForSingleObject(m_hProcess, MAX_WAIT_CHILD_PROC) != WAIT_OBJECT_0)
*/
    KillProcessTree(m_dwProcessId);

    ::CloseHandle(m_hProcess);
    m_hProcess = NULL;

    ::CloseHandle(m_WaitForProcessThread);
    m_WaitForProcessThread = NULL;
}
