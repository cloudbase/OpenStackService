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

#pragma once

#include <string>
#include <map>
#include <vector>
#include "ServiceBase.h"

typedef std::map<std::wstring, std::wstring> EnvMap;

class CWrapperService : public CServiceBase
{
public:
    enum ServiceType {
       SERVICE_TYPE_UNDEFINED,
       SERVICE_TYPE_SIMPLE,
       SERVICE_TYPE_FORKING,
       SERVICE_TYPE_ONESHOT,
       SERVICE_TYPE_DBUS,
       SERVICE_TYPE_NOTIFY,
       SERVICE_TYPE_IDLE
    };

   // StandardOut and StandardError are specified as type and maybe name
   // most of these will have significant differences in their semantics from unix/linux.
   enum OUTPUT_TYPE {
       OUTPUT_TYPE_INVALID,
       OUTPUT_TYPE_INHERIT,
       OUTPUT_TYPE_NULL,
       OUTPUT_TYPE_TTY,
       OUTPUT_TYPE_JOURNAL,
       OUTPUT_TYPE_SYSLOG,
       OUTPUT_TYPE_KMSG,
       OUTPUT_TYPE_JOURNAL_PLUS_CONSOLE,
       OUTPUT_TYPE_SYSLOG_PLUS_CONSOLE,
       OUTPUT_TYPE_KMSG_PLUS_CONSOLE,
       OUTPUT_TYPE_FILE,   // requires a path
       OUTPUT_TYPE_SOCKET,
       OUTPUT_TYPE_FD      // requires a name
    };

    // The parameter list has gotten very long. This way we have a packet of params
    // with defaults. Since C++ does not have named parameters this allows use to init some
    // and define others

    struct ServiceParams {
        LPCWSTR szServiceName;
        LPCWSTR szShellCmdPre;
        LPCWSTR szShellCmdPost;
        LPCWSTR szExecStartPre;
        LPCWSTR szExecStart;
        LPCWSTR szExecStartPost;
        LPCWSTR szExecStop;
        LPCWSTR szExecStopPost;
        enum ServiceType serviceType;
        BOOL   feOutputToEventLog;
        BOOL   fErrorToEventLog;
        BOOL   fOutputToFile;
        BOOL   fErrorToFile;
        HANDLE fStdOutHandle;
        HANDLE fStdErrHandle;
        BOOL fCanStop;
        BOOL fCanShutdown;
        BOOL fCanPauseContinue;
        std::vector<std::wstring> environmentFilesPS;
        std::vector<std::wstring> environmentFiles;
        std::vector<std::wstring> environmentVars;
        std::vector<std::wstring> files_before;
        std::vector<std::wstring> services_before;
        std::vector<std::wstring> files_after;
        std::vector<std::wstring> services_after;
        std::vector<std::wstring> files_requisite;
        std::vector<std::wstring> services_requisite;
        ServiceParams(): szServiceName(NULL), 
            szShellCmdPre(NULL),
            szShellCmdPost(NULL),
            szExecStartPre(NULL),
            szExecStart(NULL),
            szExecStartPost(NULL),
            szExecStop(NULL),
            szExecStopPost(NULL),
            serviceType(SERVICE_TYPE_SIMPLE),
            feOutputToEventLog(FALSE),
            fErrorToEventLog  (FALSE),
            fOutputToFile     (TRUE),
            fErrorToFile      (FALSE),
            fStdOutHandle     (INVALID_HANDLE_VALUE),
            fStdErrHandle     (INVALID_HANDLE_VALUE),
            fCanStop(TRUE),
            fCanShutdown(TRUE),
            fCanPauseContinue(FALSE) {  };
    };

    CWrapperService( struct CWrapperService::ServiceParams &params );
    virtual ~CWrapperService(void);

protected:

    virtual void OnStart(DWORD dwArgc, PWSTR *pszArgv);
    virtual void OnStop();

private:


    void GetCurrentEnv();
    void LoadEnvVarsFromFile(const std::wstring& path);
    void LoadPShellEnvVarsFromFile(const std::wstring& path);

    static DWORD WINAPI WaitForProcessThread(LPVOID lpParam);
    static void WINAPI KillProcessTree(DWORD dwProcId);
    PROCESS_INFORMATION StartProcess(LPCWSTR cmdLine, bool waitForProcess = false);

    std::wstring m_ServiceName;

    std::wstring m_ExecStartPreCmdLine;
    std::wstring m_ExecStartCmdLine;
    std::wstring m_ExecStartPostCmdLine;
    std::wstring m_ExecStopCmdLine;
    std::wstring m_ExecStopPostCmdLine;

    std::vector<std::wstring> m_FilesBefore;     // Service won't execute if these exist
    std::vector<std::wstring> m_ServicesBefore;  // Service won't execute if these are running
    std::vector<std::wstring> m_FilesAfter;      // Service won't execute if these exist
    std::vector<std::wstring> m_ServicesAfter;   // Service won't execute if these are running
    std::vector<std::wstring> m_Requisite_Files; // Service won't execute if these don't exist
    std::vector<std::wstring> m_Requisite_Services; //  Service won't execute if these are running

    std::vector<std::wstring> m_EnvironmentFiles;    // Evaluated each time the service is started.
    std::vector<std::wstring> m_EnvironmentFilesPS;  // Evaluated each time the service is started.
    std::vector<std::wstring> m_EnvironmentVars;
    std::wstring m_envBuf;
    EnvMap m_Env;

    DWORD m_dwProcessId;
    HANDLE m_hProcess;
    HANDLE m_WaitForProcessThread;
    enum ServiceType m_ServiceType;
    HANDLE m_StdOutHandle;
    HANDLE m_StdErrHandle;
    volatile BOOL m_IsStopping;
};
