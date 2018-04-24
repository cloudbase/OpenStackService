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
#include <fstream>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/join.hpp>
#include <TlHelp32.h>
#pragma endregion

#define MAX_WAIT_CHILD_PROC (5 * 1000)

using namespace std;


CWrapperService::CWrapperService(struct CWrapperService::ServiceParams &params)
                                 : CServiceBase(params.szServiceName, 
                                                params.stdOut,
                                                params.fCanStop, 
                                                params.fCanShutdown,
                                                params.fCanPauseContinue)
{
    if (params.szExecStartPre) {
        m_ExecStartPreCmdLine = params.szShellCmdPre;
        m_ExecStartPreCmdLine.append(params.szExecStartPre);
        m_ExecStartPreCmdLine.append(params.szShellCmdPost);
    }

    if (params.szExecStart) {
        m_ExecStartCmdLine = params.szShellCmdPre;
        m_ExecStartCmdLine.append(params.szExecStart);
        m_ExecStartCmdLine.append(params.szShellCmdPost);
    }

    if (params.szExecStartPost) {
        m_ExecStartPostCmdLine = params.szShellCmdPre;
        m_ExecStartPostCmdLine.append(params.szExecStartPost);
        m_ExecStartPostCmdLine.append(params.szShellCmdPost);
    }

    if (params.szExecStop) {
        m_ExecStopCmdLine = params.szShellCmdPre;
        m_ExecStopCmdLine.append(params.szExecStop);
        m_ExecStopCmdLine.append(params.szShellCmdPost);
    }

    if (params.szExecStopPost) {
        m_ExecStopPostCmdLine = params.szShellCmdPre;
        m_ExecStopPostCmdLine.append(params.szExecStopPost);
        m_ExecStopPostCmdLine.append(params.szShellCmdPost);
    }

    if (!params.files_before.empty()) {
        m_FilesBefore = params.files_before;
    }

    if (!params.services_before.empty()) {
        m_ServicesBefore = params.services_before;
    }

    if (!params.files_after.empty()) {
        m_FilesAfter = params.files_after;
    }

    if (!params.services_after.empty()) {
        m_ServicesAfter = params.services_after;
    }

    if (!params.files_requisite.empty()) {
        m_Requisite_Files = params.files_requisite;
    }

    if (!params.services_requisite.empty()) {
        m_Requisite_Services = params.services_requisite;
    }

    if (!params.environmentFiles.empty()) {
        m_EnvironmentFiles = params.environmentFiles;
    }

    if (!params.environmentVars.empty()) {
        m_EnvironmentVars = params.environmentVars;
    }

    if (!params.unitPath.empty()) {
        m_unitPath = params.unitPath;
    }
    else {
        // If not defined, etc expect it is the systemd active service diirectory
        m_unitPath = L"c:\\etc\\SystemD\\active\\";
    }

    m_ServiceName = params.szServiceName;

    m_StdErr = params.stdErr;
    m_StdOut = params.stdOut;

    m_WaitForProcessThread = NULL;
    m_dwProcessId = 0;
    m_hProcess   = NULL;
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


enum OUTPUT_TYPE CWrapperService::StrToOutputType( std::wstring val, std::wstring *path )

{
    if (val.compare(L"inherit") == 0) {
        return OUTPUT_TYPE_INHERIT;
    }
    else if (val.compare(L"null") == 0) {
        return OUTPUT_TYPE_NULL;
    }
    else if (val.compare(L"tty") == 0) {
        return OUTPUT_TYPE_TTY;
    }
    else if (val.compare(L"journal") == 0) {
        return OUTPUT_TYPE_JOURNAL;
    }
    else if (val.compare(L"syslog") == 0) {
        return OUTPUT_TYPE_SYSLOG;
    }
    else if (val.compare(L"kmsg") == 0) {
        return OUTPUT_TYPE_KMSG;
    }
    else if (val.compare(L"journal+console") == 0) {
        return OUTPUT_TYPE_JOURNAL_PLUS_CONSOLE;
    }
    else if (val.compare(L"syslog+console") == 0) {
        return OUTPUT_TYPE_SYSLOG_PLUS_CONSOLE;
    }
    else if (val.compare(L"kmsg+console") == 0) {
        return OUTPUT_TYPE_KMSG_PLUS_CONSOLE;
    }
    else if (val.compare(0, 5, L"file:path") == 0) {
        if (path != NULL ) {
            *path = val.substr(0, val.find_first_of(':')+1);
        }
        return OUTPUT_TYPE_FILE;
    }
    else if (val.compare(L"socket") == 0) {
        return OUTPUT_TYPE_SOCKET;
    }
    else if (val.compare(0, 3, L"fd:name. ") == 0) {
        if (path != NULL ) {
            *path = val.substr(0, val.find_first_of(':')+1);
        }
        return OUTPUT_TYPE_FD;
    }
    else {
        return OUTPUT_TYPE_INVALID;
    }
}



void CWrapperService::GetCurrentEnv()
{
    LPTCH tmpEnv = ::GetEnvironmentStrings();
    LPCWSTR envPair = (LPCWSTR)tmpEnv;
    while (envPair[0])
    {
        wregex rgx(L"^([^=]*)=(.*)$");
        wsmatch matches;
        wstring envPairStr = envPair;
        if (regex_search(envPairStr, matches, rgx))
        {
            auto name = matches[1].str();
            auto value = matches[2].str();
            m_Env[name] = value;
        }

        envPair = envPair + envPairStr.length() + 1;
    }
    ::FreeEnvironmentStrings(tmpEnv);
}

void CWrapperService::LoadEnvVarsFromFile(const wstring& path)
{
    wifstream inputFile(path);
    wstring line;

    while (getline(inputFile, line))
    {
        wregex rgx(L"^([^#][^=]*)=(.*)$");
        wsmatch matches;
        if (regex_search(line, matches, rgx))
        {
            auto name = boost::algorithm::trim_copy(matches[1].str());
            auto value = boost::algorithm::trim_copy(matches[2].str());
            m_Env[name] = value;
        }
    }
}

void CWrapperService::LoadPShellEnvVarsFromFile(const wstring& path)
{
    wifstream inputFile(path);
    wstring line;

    while (getline(inputFile, line))
    {
        wregex rgx(L"^\\s*\\$env:([^#=]*)=['\"](.*)['\"]$");
        wsmatch matches;
        if (regex_search(line, matches, rgx))
        {
            auto name = boost::algorithm::trim_copy(matches[1].str());
            auto value = boost::algorithm::trim_copy(matches[2].str());
            m_Env[name] = value;
        }
    }

}

PROCESS_INFORMATION CWrapperService::StartProcess(LPCWSTR cmdLine, bool waitForProcess)
{
    PROCESS_INFORMATION processInformation;
    STARTUPINFO startupInfo;
    memset(&processInformation, 0, sizeof(processInformation));
    memset(&startupInfo, 0, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);
    if (m_StdOut->GetHandle() != INVALID_HANDLE_VALUE) {
        startupInfo.dwFlags |= STARTF_USESTDHANDLES;
        startupInfo.hStdOutput = m_StdOut->GetHandle();
*logfile << L"has stdout " << std::endl;

        startupInfo.hStdInput = NULL;
    }

    if (m_StdErr->GetHandle() != INVALID_HANDLE_VALUE) {
        startupInfo.dwFlags |= STARTF_USESTDHANDLES;
        startupInfo.hStdError  = m_StdErr->GetHandle();
*logfile << L"has stderr " << std::endl;
        startupInfo.hStdInput = NULL;
    }

    DWORD dwCreationFlags = CREATE_NO_WINDOW | NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT;

    // Read the environment every time we start

    if (!m_EnvironmentFiles.empty() ||
        !m_EnvironmentFilesPS.empty())
    {
        GetCurrentEnv();
        for (auto envFile : m_EnvironmentFiles)
        {
            LoadEnvVarsFromFile(envFile);
        }
        for (auto envFile : m_EnvironmentFilesPS)
        {
            LoadPShellEnvVarsFromFile(envFile);
        }
    }

    LPVOID lpEnv = NULL;
    if (!m_envBuf.empty())
        lpEnv = &m_envBuf[0];

    DWORD tempCmdLineCount = lstrlen(cmdLine) + 1;
    LPWSTR tempCmdLine = new WCHAR[tempCmdLineCount];  //Needed since CreateProcessW may change the contents of CmdLine
    wcscpy_s(tempCmdLine, tempCmdLineCount, cmdLine);

    BOOL result = ::CreateProcess(NULL, tempCmdLine, NULL, NULL, TRUE, dwCreationFlags,
        lpEnv, NULL, &startupInfo, &processInformation);

    delete[] tempCmdLine;

    if (!result)
    {
        DWORD err = GetLastError();
        wostringstream os;
        *logfile << L"Error " << hex << err << L" while spawning the process: " << cmdLine;
        WriteEventLogEntry(os.str().c_str(), EVENTLOG_ERROR_TYPE);

        string str = wstring_convert<codecvt_utf8<WCHAR>>().to_bytes(os.str());
        throw exception(str.c_str());
    }

    if(waitForProcess)
    {
        ::WaitForSingleObject(processInformation.hProcess, INFINITE);

        DWORD exitCode = 0;
        BOOL result = ::GetExitCodeProcess(processInformation.hProcess, &exitCode);
        ::CloseHandle(processInformation.hProcess);

        if (!result || exitCode)
        {
            wostringstream os;
            if (!result) {
                *logfile << L"GetExitCodeProcess failed";
            }
            else {
                *logfile << L"Command \"" << cmdLine << L"\" failed with exit code: " << exitCode;
            }

            string str = wstring_convert<codecvt_utf8<WCHAR>>().to_bytes(os.str());
            throw exception(str.c_str());
        }
    }

    return processInformation;
}

void CWrapperService::OnStart(DWORD dwArgc, LPWSTR *lpszArgv)
{
    m_IsStopping = FALSE;

*logfile << L"start " << m_ServiceName << std::endl;

    // If files before exist, bail.
    for (auto before : this->m_FilesBefore) {
        *logfile << L"before file " << before << std::endl;

        wstring path = m_unitPath;
        path.append(before);
        wifstream wifs(path);
        if (wifs.is_open()) {
            *logfile << L"before file " << before << " is present, so don't run" << std::endl;
            wifs.close();
            throw exception("Before file is present, service not started");
            return;
        }
    }

for (auto before : this->m_ServicesBefore) {
   *logfile << L"before service" << before << std::endl;
}

    for (auto after : this->m_FilesAfter) {
        *logfile << L"after file " << after << std::endl;

        // If files after do not exist, bail.
        wstring path = m_unitPath;
        path.append(after);
        wifstream wifs(path);
        if (!wifs.is_open()) {
            *logfile << L"after file " << after << " is not present, so don't run" << std::endl;
            throw exception("After file is not present, service not started");
            return;
        }
        wifs.close();
    }


for (auto after : this->m_ServicesAfter) {
   *logfile << L"after service" << after << std::endl;
}

    if (!m_ExecStartPreCmdLine.empty())
    {
        wostringstream os;
        *logfile << L"Running ExecStartPre command: " << m_ExecStartPreCmdLine.c_str();
*logfile << L"execstartpre " <<  m_ExecStartPreCmdLine.c_str()  << std::endl;
        StartProcess(m_ExecStartPreCmdLine.c_str(), true);
    }

    *logfile << L"Starting service: " << m_ServiceName << std::endl;

*logfile << L"starting cmd " << m_ExecStartCmdLine.c_str() << std::endl;

    auto processInformation = StartProcess(m_ExecStartCmdLine.c_str());

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

    if (!m_ExecStartPostCmdLine.empty())
    {
        wostringstream os;
        os << L"Running ExecStartPost command: " << m_ExecStartPostCmdLine.c_str();
*logfile << os.str() << std::endl;
        WriteEventLogEntry(os.str().c_str(), EVENTLOG_INFORMATION_TYPE);
        StartProcess(m_ExecStartPostCmdLine.c_str(), true);
    }

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
*logfile << L"stopping service " << m_ServiceName.c_str() << std::endl;

    if (!m_ExecStopCmdLine.empty())
    {
        wostringstream os;
        os << L"Running ExecStop command: " << m_ExecStopCmdLine.c_str();
*logfile << os.str() << std::endl;
        WriteEventLogEntry(os.str().c_str(), EVENTLOG_INFORMATION_TYPE);
        StartProcess(m_ExecStopCmdLine.c_str(), true);
    }

/*
    if(!::GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0))
        WriteEventLogEntry(L"Error while sending CTRL BREAK to a child process", EVENTLOG_WARNING_TYPE);

    if(::WaitForSingleObject(m_hProcess, MAX_WAIT_CHILD_PROC) != WAIT_OBJECT_0)
*/
    KillProcessTree(m_dwProcessId);

    if (!m_ExecStopPostCmdLine.empty())
    {
        wostringstream os;
        os << L"Running ExecStopPost command: " << m_ExecStopPostCmdLine.c_str();
*logfile << os.str() << std::endl;
        WriteEventLogEntry(os.str().c_str(), EVENTLOG_INFORMATION_TYPE);
        StartProcess(m_ExecStopPostCmdLine.c_str(), true);
    }


    ::CloseHandle(m_hProcess);
    m_hProcess = NULL;

    ::CloseHandle(m_WaitForProcessThread);
    m_WaitForProcessThread = NULL;
}
