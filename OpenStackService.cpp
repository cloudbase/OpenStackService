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



// Generates flags mask and removes special executable prefix characters
unsigned 
CWrapperService::ProcessSpecialCharacters(std::wstring &ws)

{ unsigned mask = 0;

    wchar_t spec_char = ws[0]; 
    while (spec_char) {
        switch(spec_char) {
	case L'@':
	    mask |= EXECFLAG_ARG0;
            ws.erase(0, 1);
	    spec_char = ws[0];
	    break;
	case L'-':
	    mask |= EXECFLAG_IGNORE_FAIL;
            ws.erase(0, 1);
	    spec_char = ws[0];
	    break;

	case L'+':
	    mask |= EXECFLAG_FULL_PRIVELEGE;
            ws.erase(0, 1);
	    spec_char = ws[0];
	    if (spec_char == '!') {
	        *logfile << L"Illegal combination of special execuatble chars +, ! and !! in commandline " << ws << std::endl;
            }
	    break;

	case L'!':
	    if (ws[1] == L'!') {
	        mask |= EXECFLAG_AMBIENT_PRIVELEGE;
                ws.erase(0, 2);
            }
	    else {
	        mask |= EXECFLAG_ELEVATE_PRIVELEGE;
                ws.erase(0, 2);
            }
	    spec_char = ws[0];
	    break;

	default:
	     return mask;
	}
    }

    return mask;
}


CWrapperService::CWrapperService(struct CWrapperService::ServiceParams &params)
                                 : CServiceBase(params.szServiceName, 
                                                params.stdOut,
                                                params.fCanStop, 
                                                params.fCanShutdown,
                                                params.fCanPauseContinue)
{

    if (!params.execStartPre.empty()) {
        for (auto ws: params.execStartPre) {
	    m_ExecStartPreFlags.push_back(ProcessSpecialCharacters(ws));
            wstring cmdline = params.szShellCmdPre;
            cmdline.append(ws);
            cmdline.append(params.szShellCmdPost);
            m_ExecStartPreCmdLine.push_back(cmdline);
        }
    }

    if (!params.execStart.empty()) {
        m_ExecStartFlags = ProcessSpecialCharacters(params.execStart);
        m_ExecStartCmdLine = params.szShellCmdPre;
        m_ExecStartCmdLine.append(params.execStart);
        m_ExecStartCmdLine.append(params.szShellCmdPost);
    }

    if (!params.execStartPost.empty()) {
        for (auto ws: params.execStartPost) {
	    m_ExecStartPostFlags.push_back(ProcessSpecialCharacters(ws));
            wstring cmdline = params.szShellCmdPre;
            cmdline.append(ws);
            cmdline.append(params.szShellCmdPost);
            m_ExecStartPostCmdLine.push_back(cmdline);
        }
    }

    if (!params.execStop.empty()) {
        m_ExecStopFlags = ProcessSpecialCharacters(params.execStop);
        m_ExecStopCmdLine = params.szShellCmdPre;
        m_ExecStopCmdLine.append(params.execStop);
        m_ExecStopCmdLine.append(params.szShellCmdPost);
    }

    if (!params.execStopPost.empty()) {
        for (auto ws: params.execStopPost) {
	    m_ExecStopPostFlags.push_back(ProcessSpecialCharacters(ws));
            wstring cmdline = params.szShellCmdPre;
            cmdline.append(ws);
            cmdline.append(params.szShellCmdPost);
            m_ExecStopPostCmdLine.push_back(cmdline);
        }

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

    m_ConditionArchitecture  = params.conditionArchitecture;
    m_ConditionVirtualization = params.conditionVirtualization;
    m_ConditionHost           = params.conditionHost;
    m_ConditionKernelCommandLine = params.conditionKernelCommandLine;
    m_ConditionKernelVersion     = params.conditionKernelVersion;
    m_ConditionSecurity    = params.conditionSecurity;
    m_ConditionCapability  = params.conditionCapability;
    m_ConditionACPower     = params.conditionACPower;
    m_ConditionNeedsUpdate = params.conditionNeedsUpdate;
    m_ConditionFirstBoot   = params.conditionFirstBoot;
    m_ConditionPathExists        = params.conditionPathExists;
    m_ConditionPathExistsGlob    = params.conditionPathExistsGlob;
    m_ConditionPathIsDirectory   = params.conditionPathIsDirectory;
    m_ConditionPathIsSymbolicLink = params.conditionPathIsSymbolicLink;
    m_ConditionPathIsMountPoint  = params.conditionPathIsMountPoint;
    m_ConditionPathIsReadWrite   = params.conditionPathIsReadWrite;
    m_ConditionDirectoryNotEmpty = params.conditionDirectoryNotEmpty;
    m_ConditionFileNotEmpty      = params.conditionFileNotEmpty;
    m_ConditionFileIsExecutable  = params.conditionFileIsExecutable;
    m_ConditionUser  = params.conditionUser;
    m_ConditionGroup = params.conditionGroup;
    m_ConditionControlGroupController = params.conditionControlGroupController;

    m_ServiceName = params.szServiceName;
    m_ServiceType = params.serviceType;

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

    wchar_t *tmpEnv = ::GetEnvironmentStringsW();
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


PROCESS_INFORMATION CWrapperService::StartProcess(LPCWSTR cmdLine, bool waitForProcess, bool failOnError)

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

    LPVOID lpEnv = NULL;
    if (!m_envBuf.empty()) {
    wchar_t *tmpenv = (wchar_t*)m_envBuf.c_str();
        lpEnv = (LPVOID)m_envBuf.c_str();
    }
    
    DWORD tempCmdLineCount = lstrlen(cmdLine) + 1;
    LPWSTR tempCmdLine = new WCHAR[tempCmdLineCount];  //Needed since CreateProcessW may change the contents of CmdLine
    wcscpy_s(tempCmdLine, tempCmdLineCount, cmdLine);

*logfile << "create process " << cmdLine << std::endl;

    BOOL result = ::CreateProcessW(NULL, tempCmdLine, NULL, NULL, TRUE, dwCreationFlags,
        lpEnv, NULL, &startupInfo, &processInformation);

    delete[] tempCmdLine;

    if (!result)
    {
        DWORD err = GetLastError();
        wostringstream os;
        os << L"Error " << err << L" while spawning the process: " << cmdLine << std::endl;
        *logfile << os.str();
        string str = wstring_convert<codecvt_utf8<WCHAR>>().to_bytes(os.str());
        throw exception(str.c_str());
    }

    if(waitForProcess)
    {
*logfile << "waitfor process " << cmdLine << std::endl;
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
*logfile << "process success " << cmdLine << std::endl;
    }

    return processInformation;
}

void CWrapperService::OnStart(DWORD dwArgc, LPWSTR *lpszArgv)
{
    boolean waitforfinish = true;

    SetServiceStatus(SERVICE_RUNNING);
    if (!m_ServicesBefore.empty()) {
        if (!WaitForDependents()) {
            *logfile << L"Failure in WaitForDepenents" << std::endl;
            throw ERROR_SERVICE_DEPENDENCY_FAIL;
            return;
        }
    }

    if (m_ServiceType == SERVICE_TYPE_FORKING) {
        waitforfinish = false;
    }

    m_IsStopping = FALSE;

*logfile << L"start " << m_ServiceName << std::endl;
    if (!EvaluateConditions()) {
        SetServiceStatus(SERVICE_STOPPED);
	return;
    }

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

    // OK. We are going to launch. First resolve the environment

    GetCurrentEnv();
    for (auto envFile : m_EnvironmentFiles)
    {
        LoadEnvVarsFromFile(envFile);
    }
    for (auto envFile : m_EnvironmentFilesPS)
    {
        LoadPShellEnvVarsFromFile(envFile);
    }

    // Now we have the map, we can populate the buffer

    m_envBuf = L"";
    for(auto this_pair : m_Env) {
        m_envBuf.append(this_pair.first);
        m_envBuf.append(L"=");
        m_envBuf.append(this_pair.second);
        m_envBuf.push_back(L'\0');
    }
    m_envBuf.push_back(L'\0');

    SetServiceStatus(SERVICE_RUNNING);
    if (!m_ExecStartPreCmdLine.empty())
    {
        wostringstream os;
        for( int i = 0;  i < m_ExecStartPreCmdLine.size(); i++ ) {
            auto ws = m_ExecStartPreCmdLine[i];
            *logfile << L"Running ExecStartPre command: " << ws.c_str();
	          // to do, add special char processing
	          try {
                StartProcess(ws.c_str(), true); 
	          }
	          catch(...) {
	             if (!(m_ExecStartPreFlags[i] & EXECFLAG_IGNORE_FAIL)) {
                    *logfile << L"Error in ExecStartPre command: " << ws.c_str() << "exiting" << std::endl;
	        	   }
	         }
        }
    }

    *logfile << L"Starting service: " << m_ServiceName << std::endl;

*logfile << L"starting cmd " << m_ExecStartCmdLine.c_str() << std::endl;


    auto processInformation = StartProcess(m_ExecStartCmdLine.c_str(), true);

#if 0
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

#endif

    if (!m_ExecStartPostCmdLine.empty())
    {
        wostringstream os;

        for( int i = 0;  i < m_ExecStartPostCmdLine.size(); i++ ) {
            auto ws = m_ExecStartPostCmdLine[i];
            os << L"Running ExecStartPost command: " << ws.c_str();
            *logfile << os.str() << std::endl;
	    try {
                StartProcess(ws.c_str(), true);
	    }
	    catch(...) {
	        if (!(m_ExecStartPreFlags[i] & EXECFLAG_IGNORE_FAIL)) {
                    *logfile << L"Error in ExecStartPre command: " << ws.c_str() << "exiting" << std::endl;
		}
	    }
        }
    }

    if (m_ServiceType == SERVICE_TYPE_SIMPLE || m_ServiceType == SERVICE_TYPE_ONESHOT) {
        SetServiceStatus(SERVICE_STOPPED);
    }	

*logfile << L"exit service OnStart: " << std::endl;
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

    KillProcessTree(m_dwProcessId);

    if (!m_ExecStopPostCmdLine.empty())
    {
        wostringstream os;

        for( auto ws: m_ExecStopPostCmdLine) {
            os << L"Running ExecStopPost command: " << ws.c_str();
            *logfile << os.str() << std::endl;
            StartProcess(ws.c_str(), true);
        }
    }


    ::CloseHandle(m_hProcess);
    m_hProcess = NULL;

    ::CloseHandle(m_WaitForProcessThread);
    m_WaitForProcessThread = NULL;
}


boolean
CWrapperService::EvaluateConditions()

{
    if (!m_ConditionArchitecture.empty()) {
       for( auto ws: m_ConditionArchitecture) {
           if (!EvalConditionArchitecture(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionVirtualization.empty()) {
       for( auto ws: m_ConditionVirtualization) {
           if (!EvalConditionVirtualization(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionHost.empty()) {
       for( auto ws: m_ConditionHost) {
           if (!EvalConditionHost(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionKernelCommandLine.empty()) {
       for( auto ws: m_ConditionKernelCommandLine) {
           if (!EvalConditionKernelCommandLine(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionKernelVersion.empty()) {
       for( auto ws: m_ConditionKernelVersion) {
           if (!EvalConditionKernelVersion(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionSecurity.empty()) {
       for( auto ws: m_ConditionSecurity) {
           if (!EvalConditionSecurity(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionCapability.empty()) {
       for( auto ws: m_ConditionCapability) {
           if (!EvalConditionCapability(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionACPower.empty()) {
       for( auto ws: m_ConditionACPower) {
           if (!EvalConditionACPower(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionNeedsUpdate.empty()) {
       for( auto ws: m_ConditionNeedsUpdate) {
           if (!EvalConditionNeedsUpdate(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionFirstBoot.empty()) {
       for( auto ws: m_ConditionFirstBoot) {
           if (!EvalConditionFirstBoot(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionPathExists.empty()) {
       for( auto ws: m_ConditionPathExists) {
           if (!EvalConditionPathExists(ws)) {
	       *logfile << L"Condition failed" << std::endl;
	       return false;
	   }
       }
    }
    if (!m_ConditionPathExistsGlob.empty()) {
       for( auto ws: m_ConditionPathExistsGlob) {
           if (!EvalConditionPathExistsGlob(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionPathIsDirectory.empty()) {
       for( auto ws: m_ConditionPathIsDirectory) {
           if (!EvalConditionPathIsDirectory(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionPathIsSymbolicLink.empty()) {
       for( auto ws: m_ConditionPathIsSymbolicLink) {
           if (!EvalConditionPathIsSymbolicLink(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionPathIsMountPoint.empty()) {
       for( auto ws: m_ConditionPathIsMountPoint) {
           if (!EvalConditionPathIsMountPoint(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionPathIsReadWrite.empty()) {
       for( auto ws: m_ConditionPathIsReadWrite) {
           if (!EvalConditionPathIsReadWrite(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionDirectoryNotEmpty.empty()) {
       for( auto ws: m_ConditionDirectoryNotEmpty) {
           if (!EvalConditionDirectoryNotEmpty(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionFileNotEmpty.empty()) {
       for( auto ws: m_ConditionFileNotEmpty) {
           if (!EvalConditionFileNotEmpty(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionFileIsExecutable.empty()) {
       for( auto ws: m_ConditionFileIsExecutable) {
           if (!EvalConditionFileIsExecutable(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionUser.empty()) {
       for( auto ws: m_ConditionUser) {
           if (!EvalConditionUser(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionGroup.empty()) {
       for( auto ws: m_ConditionGroup) {
           if (!EvalConditionGroup(ws)) {
	       return false;
	   }
       }
    }
    if (!m_ConditionControlGroupController.empty()) {
       for( auto ws: m_ConditionControlGroupController) {
           if (!EvalConditionControlGroupController(ws)) {
	       return false;
	   }
       }
    }

    *logfile << L"Condition passed" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionArchitecture(std::wstring arg)
{
    *logfile << L"condition ConditionArchitecture is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionVirtualization(std::wstring arg)
{
    *logfile << L"condition ConditionVirtualization is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionHost(std::wstring arg)
{
    *logfile << L"condition ConditionHost is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionKernelCommandLine(std::wstring arg)
{
    *logfile << L"condition ConditionKernelCommandLine is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionKernelVersion(std::wstring arg)
{
    *logfile << L"condition ConditionKernelVersion is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionSecurity(std::wstring arg)
{
    *logfile << L"condition ConditionSecurity is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionCapability(std::wstring arg)
{
    *logfile << L"condition ConditionCapability is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionACPower(std::wstring arg)
{
    *logfile << L"condition ConditionACPower is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionNeedsUpdate(std::wstring arg)
{
    *logfile << L"condition ConditionNeedsUpdate is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionFirstBoot(std::wstring arg)
{
    *logfile << L"condition ConditionFirstBoot is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionPathExists(std::wstring arg)
{
    wchar_t *path = (wchar_t*)arg.c_str();
    int rslt = 0;

    *logfile << L"condition ConditionPathExists " << arg << std::endl;

    if (path[0] == L'!') {
        rslt =  ::GetFileAttributes(++path);
        return rslt == INVALID_FILE_ATTRIBUTES;
    }
    else {
        rslt =  ::GetFileAttributes(path);
        return rslt != INVALID_FILE_ATTRIBUTES;
    }
}


boolean 
CWrapperService::EvalConditionPathExistsGlob(std::wstring arg)
{
    *logfile << L"condition ConditionPathExistsGlob is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionPathIsDirectory(std::wstring arg)
{
    *logfile << L"condition ConditionPathIsDirectory is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionPathIsSymbolicLink(std::wstring arg)
{
    *logfile << L"condition ConditionPathIsSymbolicLink is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionPathIsMountPoint(std::wstring arg)
{
    *logfile << L"condition ConditionPathIsMountPoint is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionPathIsReadWrite(std::wstring arg)
{
    *logfile << L"condition ConditionPathIsReadWrite is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionDirectoryNotEmpty(std::wstring arg)
{
    *logfile << L"condition ConditionDirectoryNotEmpty is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionFileNotEmpty(std::wstring arg)
{
    *logfile << L"condition ConditionFileNotEmpty is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionFileIsExecutable(std::wstring arg)
{
    *logfile << L"condition ConditionFileIsExecutable is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionUser(std::wstring arg)
{
    *logfile << L"condition ConditionUser is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionGroup(std::wstring arg)
{
    *logfile << L"condition ConditionGroup is not implemented" << std::endl;
    return true;
}


boolean 
CWrapperService::EvalConditionControlGroupController(std::wstring arg)
{
    *logfile << L"condition ConditionControlGroupController  is not implemented" << std::endl;
    return true;
}



boolean
CWrapperService::WaitForDependents() 

{
    DWORD bytes_needed = 0;
    DWORD num_services = 0;
    ENUM_SERVICE_STATUS *pServices;

    SC_HANDLE hsc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hsc) {
        int last_error = GetLastError();
        wcerr << L"WaitForDependents could not open service manager win err = " << last_error << std::endl;
        return false;
    }

    SC_HANDLE hsvc = OpenServiceW(hsc, m_ServiceName.c_str(), GENERIC_READ);
    if (hsvc == NULL)
    {
        wcerr << L"WaitForDependents OpeService failed " << GetLastError() << std::endl;
        CloseServiceHandle(hsc);
        return false;
    }

    // Figure out how much data I need to alloc
    (void)::EnumDependentServices(
                                    hsvc,           //  _In_      SC_HANDLE             hService,
                                    SERVICE_ACTIVE, //  _In_      DWORD                 dwServiceState,
                                    NULL,           //  _Out_opt_ LPENUM_SERVICE_STATUS lpServices,
                                    0,              //  _In_      DWORD                 cbBufSize,
                                    &bytes_needed,  //  _Out_     LPDWORD               pcbBytesNeeded,
                                    &num_services   //  _Out_     LPDWORD               lpServicesReturned
                                );

    pServices = (ENUM_SERVICE_STATUS *)new char[bytes_needed];
    do {
        if (!::EnumDependentServices(
                                    hsvc,           //  _In_      SC_HANDLE             hService,
                                    SERVICE_ACTIVE, //  _In_      DWORD                 dwServiceState,
                                    pServices,      //  _Out_opt_ LPENUM_SERVICE_STATUS lpServices,
                                    bytes_needed,   //  _In_      DWORD                 cbBufSize,
                                    &bytes_needed,  //  _Out_     LPDWORD               pcbBytesNeeded,
                                    &num_services   //  _Out_     LPDWORD               lpServicesReturned
                               ) ) {
            int last_error = GetLastError();
             // 2do: handle MORE_DATA
            wcerr << L"WaitForDependents could not enum dependent services win err = " << last_error << std::endl;
            CloseServiceHandle(hsvc);
            CloseServiceHandle(hsc);
            return false;
        }
        if (num_services > 0) {
             Sleep(100); // sleep for 0.1 sec as we check
        }
    } while(num_services > 0);

    CloseServiceHandle(hsvc);
    CloseServiceHandle(hsc);

    return true;
}


