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
#include <boost/program_options.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/join.hpp>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <regex>
#include <vector>
#include "ServiceBase.h"
#include "OpenStackService.h"
#pragma endregion

using namespace std;
using namespace boost::program_options;

struct CLIArgs
{
    vector<wstring> environmentFiles;
    vector<wstring> environmentFilesPShell;
    vector<wstring> environmentVars;
    wstring execStartPre;
    wstring execStart;
    wstring execStartPost;
    wstring execStop;
    wstring execStopPost;
    wstring serviceName;
    vector<wstring> additionalArgs;
    wstring logFile;
    wstring serviceUnit;
    wstring shellCmd_pre;
    wstring shellCmd_post;
    enum CWrapperService::ServiceType serviceType;
    vector<wstring> requisite_files;
    vector<wstring> requisite_services;
    vector<wstring> before_files;
    vector<wstring> before_services;
    vector<wstring> after_files;
    vector<wstring> after_services;
};

CLIArgs ParseArgs(int argc, wchar_t *argv[]);
EnvMap LoadEnvVarsFromFile(const wstring& path);
EnvMap GetCurrentEnv();

wofstream logfile("c:/tmp/some-log", std::ios_base::out | std::ios_base::app);


wstring DEFAULT_SHELL_PRE  =  L"powershell -command \"& {";
wstring DEFAULT_SHELL_POST =  L" } \" ";
wstring DEFAULT_START_ACTION = L"Write-Host \"No Start Action\" ";

CLIArgs ParseArgs(int argc, wchar_t *argv[])
{
    CLIArgs args;
    options_description desc{ "Options" };
    desc.add_options()
        ("service-unit", wvalue<wstring>(), "Service uses the service unit file in %SystemDrive%/SystemD/system" )
        ("log-file,l", wvalue<wstring>(), "Log file containing  the redirected STD OUT and ERR of the child process")
        ("environment-file,e", wvalue<vector<wstring>>(), "Environment file")
        ("environment-file-pshell", wvalue<vector<wstring>>(), "Powershell environment files")
        ("exec-start-pre", wvalue<wstring>(), "Command to be executed before starting the service")
        ("service-name", wvalue<wstring>(), "Service name");

    variables_map vm;
    auto parsed = wcommand_line_parser(argc, argv)
                .options(desc).allow_unregistered().run();
    store(parsed, vm);
    auto additionalArgs = collect_unrecognized(parsed.options, include_positional);
    notify(vm);

    variables_map service_unit_options;
    options_description config{ "service-unit_options" };
    config.add_options()
        ("Unit.Requisite", wvalue<vector<wstring>>(), "Prereuqisites. If not present, stop service") 
        ("Unit.Before",    wvalue<vector<wstring>>(), "Do not run service if these things exist") 
        ("Unit.After",     wvalue<vector<wstring>>(), "Do not run service until these things exist") 
        ("Service.Type", wvalue<wstring>(), "Systemd service type") 
        ("Service.Shell", wvalue<wstring>(), "Windows Extension. Shell to use for exec actions. Default is Powershell") 
        ("Service.EnvironmentFile", wvalue<vector<wstring>>(), "Environment files" )
        ("Service.EnvironmentFile-PS", wvalue<vector<wstring>>(), "Environment files in powershell format" )
        ("Service.Environment", wvalue<vector<wstring>>(), "Environment Variable settings" )
        ("Service.ExecStartPre", wvalue<vector<wstring>>(), "Execute before starting service")
        ("Service.ExecStart", wvalue<vector<wstring>>(), "Execute commands at when starting service")
        ("Service.ExecStartPost", wvalue<vector<wstring>>(), "Execute after starting service")
        ("Service.ExecStop", wvalue<vector<wstring>>(), "Execute commands at when stopping service")
        ("Service.ExecStopPost", wvalue<vector<wstring>>(), "Execute after stopping service")
        ("Service.BusName", wvalue<wstring>(), "Systemd dbus name. Used only for resolving service type") ;

logfile << L"check for service unit" << std::endl;
    if (vm.count("service-unit")) {
        args.serviceUnit = vm["service-unit"].as<wstring>();
logfile << L"has service unit " << args.serviceUnit.c_str() << std::endl;
        std::wifstream service_unit_file(args.serviceUnit.c_str());
logfile << L"opened service unit " << std::endl;
        auto config_parsed = parse_config_file(service_unit_file, config, true);
        store(config_parsed, service_unit_options);
        notify(service_unit_options);

for (auto elem : service_unit_options) {
    logfile << "elem_name ";
    logfile << std::wstring(elem.first.begin(), elem.first.end()) << std::endl;
}

    }

    if (vm.count("environment-file")) {
        args.environmentFiles = vm["environment-file"].as<vector<wstring>>();
    }

    if (vm.count("environment-file-pshell")) {
        args.environmentFilesPShell = vm["environment-file-pshell"].as<vector<wstring>>();
    }

logfile << "p1" << std::endl;
    if (vm.count("log-file")) {
        args.logFile = vm["log-file"].as<wstring>();
        args.logFile.erase(remove( args.logFile.begin(), args.logFile.end(), '\"' ), args.logFile.end());
        args.logFile.erase(remove( args.logFile.begin(), args.logFile.end(), '\'' ), args.logFile.end());
    }

logfile << "p2" << std::endl;
    if (vm.count("service-name")) {
        args.serviceName = vm["service-name"].as<wstring>();
        args.serviceName.erase(remove( args.serviceName.begin(), args.serviceName.end(), '\"' ), args.serviceName.end());
        args.serviceName.erase(remove( args.serviceName.begin(), args.serviceName.end(), '\'' ), args.serviceName.end());
    }

logfile << "p3" << std::endl;
    if (!additionalArgs.empty())
    {
        if (args.serviceName.empty()) {
            args.serviceName = additionalArgs[0];
        }
        additionalArgs = vector<wstring>(additionalArgs.begin(), additionalArgs.end());
    }

logfile << "p4" << std::endl;

    if (service_unit_options.count("Service.Type")) {

        // Convert string to enum
        if (service_unit_options["Service.Type"].as<std::wstring>().compare(L"simple") == 0) {
            args.serviceType = CWrapperService::SERVICE_TYPE_SIMPLE;
        }
        else if (service_unit_options["Service.Type"].as<std::wstring>().compare(L"forking") == 0) {
            args.serviceType = CWrapperService::SERVICE_TYPE_FORKING;
        }
        else if (service_unit_options["Service.Type"].as<std::wstring>().compare(L"oneshot") == 0) {
            args.serviceType = CWrapperService::SERVICE_TYPE_ONESHOT;
        }
        else if (service_unit_options["Service.Type"].as<std::wstring>().compare(L"dbus") == 0) {
            args.serviceType = CWrapperService::SERVICE_TYPE_DBUS;
        }
        else if (service_unit_options["Service.Type"].as<std::wstring>().compare(L"notify") == 0) {
            args.serviceType = CWrapperService::SERVICE_TYPE_NOTIFY;
        }
        else if (service_unit_options["Service.Type"].as<std::wstring>().compare(L"idle") == 0) {
            args.serviceType = CWrapperService::SERVICE_TYPE_IDLE;
        }
logfile << "p4.1 " << args.serviceType << std::endl;
    }
    else {

        // Unit type not defined. Figure out a default
        if (service_unit_options.count("Service.BusName")) {
            args.serviceType =CWrapperService:: SERVICE_TYPE_DBUS;
        }
        else if (service_unit_options.count("Service.ExecStart")) {
            args.serviceType = CWrapperService::SERVICE_TYPE_SIMPLE;
        }
        else {
            args.serviceType = CWrapperService::SERVICE_TYPE_ONESHOT;
        }
    }

    if (service_unit_options.count("Unit.Requisite")) {

        // Sort into service and non service members. They require different code to check
        std::vector<std::wstring> wsv = service_unit_options["Unit.Requisite"].as<std::vector<std::wstring>>();
        for (auto ws: wsv) {
            if (ws.rfind(L".service") != std::string::npos ) {
                args.requisite_services.push_back(ws);
            }
            else if (ws.rfind(L".target") != std::string::npos ) {
                args.requisite_files.push_back(ws);
            }
        }
    }

    if (service_unit_options.count("Unit.Before")) {
        
        // Sort into service and non service members. They require different code to check
        std::vector<std::wstring> wsv = service_unit_options["Unit.Before"].as<std::vector<std::wstring>>();
        for (auto ws: wsv) {
            if (ws.rfind(L".service") != std::string::npos ) {
                args.before_services.push_back(ws);
            }
            else if (ws.rfind(L".target") != std::string::npos ) {
                args.before_files.push_back(ws);
            }
        }
    }

    if (service_unit_options.count("Unit.After")) {
        
        // Sort into service and non service members. They require different code to check
        std::vector<std::wstring> wsv = service_unit_options["Unit.After"].as<std::vector<std::wstring>>();

logfile << "p4.4 after count = " << wsv.size() << std::endl;
for (auto ws:wsv) {
}
        for (auto ws: wsv) {
            if (ws.rfind(L".service") != std::string::npos ) {
                args.after_services.push_back(ws);
logfile << L"p4.5 after service  = " << ws << std::endl;
            }
            else if (ws.rfind(L".target") != std::string::npos ) {
                args.after_files.push_back(ws);
logfile << L"p4.6 after file  = " << ws << std::endl;
            }
        }
    }

    if (service_unit_options.count("Service.Shell")) {
        wstring shellname = service_unit_options["Service.Shell"].as<wstring>();
        transform(shellname.begin(), shellname.end(), shellname.begin(), tolower);
        if (shellname.compare(L"powershell") == 0) {
            args.shellCmd_pre = L"powershell -command \"& {";
            args.shellCmd_post = L" } \" ";
        }
        else if (shellname.compare(L"cmd") == 0) {
            args.shellCmd_pre = L"cmd /c \'";  // Untested. Fix if needed;
            args.shellCmd_post = L"\' ";
        }
        else if (shellname.compare(L"bash") == 0) {
            args.shellCmd_pre = L"bash -c \'";  // Untested. Fix if needed;
            args.shellCmd_post = L"\' ";
        }
        else {
            wostringstream ws;
            ws << "Unsupported shell type " << shellname << " specified in service unit " 
                                            << args.serviceName << std::endl;
            throw exception(std::string(ws.str().begin(), ws.str().end()).c_str());
        }
    }
    else {
        args.shellCmd_pre = DEFAULT_SHELL_PRE;
        args.shellCmd_post = DEFAULT_SHELL_POST;
    }

    if (service_unit_options.count("Service.Environment")) {
        args.environmentVars = service_unit_options["Service.Environment"].as<vector<wstring>>();
    }

    if (service_unit_options.count("Service.EnvironmentFile")) {
        args.environmentFiles = service_unit_options["Service.EnvironmentFile"].as<vector<wstring>>();
    }

    if (service_unit_options.count("Service.EnvironmentFile-PS")) {
        args.environmentFilesPShell = service_unit_options["Service.EnvironmentFilesPS"].as<vector<wstring>>();
    }

logfile << "p5" << std::endl;
    if (service_unit_options.count("Service.ExecStartPre")) {
        vector<wstring> ws_vector = service_unit_options["Service.ExecStartPre"].as<vector<wstring>>();
        wstring cmdline;
        for (auto ws : ws_vector) {
            cmdline.append(ws);
            cmdline.append(L" ; ");
        }
        args.execStartPre = cmdline;
    }

logfile << "p6" << std::endl;

    if (service_unit_options.count("Service.ExecStart")) {
        vector<wstring> ws_vector = service_unit_options["Service.ExecStart"].as<vector<wstring>>();
        wstring cmdline;
        for (auto ws : ws_vector) {
            cmdline.append(ws);
            cmdline.append(L" ; ");
        }
        args.execStart = cmdline;
logfile << "p6.1 execstart = " << cmdline << std::endl;
    }
    else {
        args.execStart = DEFAULT_START_ACTION;
    }

    if (service_unit_options.count("Service.ExecStartPost")) {
        vector<wstring> ws_vector = service_unit_options["Service.ExecStartPost"].as<vector<wstring>>();
        wstring cmdline;
        for (auto ws : ws_vector) {
            cmdline.append(ws);
            cmdline.append(L" ; ");
        }
        args.execStartPost = cmdline;
    }

    if (service_unit_options.count("Service.ExecStop")) {
        vector<wstring> ws_vector = service_unit_options["Service.ExecStop"].as<vector<wstring>>();
        wstring cmdline;
        for (auto ws : ws_vector) {
            cmdline.append(ws);
            cmdline.append(L" ; ");
        }
logfile << "p6.1 execstop = " << cmdline << std::endl;
        args.execStop = cmdline;
    }

    if (service_unit_options.count("Service.ExecStopPost")) {
        vector<wstring> ws_vector = service_unit_options["Service.ExecStopPost"].as<vector<wstring>>();
        wstring cmdline;
        for (auto ws : ws_vector) {
            cmdline.append(ws);
            cmdline.append(L" ; ");
        }
        args.execStopPost = cmdline;
    }

logfile << "p7" << std::endl;
logfile << L"service name " << args.serviceName << std::endl;
for (auto arg: additionalArgs ) {
logfile << L"additionalArgs " << arg << std::endl;
}

logfile << "p8" << std::endl;
    if(args.serviceName.empty())
        throw exception("Service name not provided");
    
    return args;
}



int wmain(int argc, wchar_t *argv[])
{
    HANDLE hLogFile = INVALID_HANDLE_VALUE;
    CWrapperService::ServiceParams params;
    try
    {
        EnvMap env;
        auto args = ParseArgs(argc, argv);

logfile << args.execStart << std::endl;
       
logfile << L"log file name " << args.logFile.c_str() << std::endl;

        if (!args.logFile.empty())
        {
            SECURITY_ATTRIBUTES sa;
            sa.nLength = sizeof(sa);
            sa.lpSecurityDescriptor = NULL;
            sa.bInheritHandle = TRUE;
            hLogFile = CreateFile(args.logFile.c_str(),
                                FILE_APPEND_DATA,
                                FILE_READ_DATA | FILE_WRITE_DATA,
                                &sa,
                                OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL);
            if (hLogFile == INVALID_HANDLE_VALUE)
            {
                char msg[100];
                sprintf_s(msg, "Failed to create log file w/err 0x%08lx", GetLastError());
                throw exception(msg);
            }
        }
 
        params.szServiceName  = args.serviceName.c_str();
        params.szShellCmdPre  = args.shellCmd_pre.c_str();
        params.szShellCmdPost = args.shellCmd_post.c_str();
        params.szExecStartPre = args.execStartPre.c_str();
        params.szExecStart     = args.execStart.c_str();
        params.szExecStartPost = args.execStartPost.c_str();
        params.szExecStop      = args.execStop.c_str();
        params.szExecStopPost  = args.execStopPost.c_str();
        params.environmentFilesPS = args.environmentFilesPShell;
        params.environmentFiles   = args.environmentFiles;
        params.environmentVars    = args.environmentVars;
        params.files_before       = args.before_files;
        params.services_before    = args.before_services;
        params.files_after        = args.after_files;
        params.services_after     = args.after_services;
        params.files_requisite    = args.requisite_files;
        params.services_requisite = args.requisite_services;
        params.feOutputToEventLog = FALSE;
        params.fErrorToEventLog   = FALSE;
        params.fOutputToFile  = TRUE;
        params.fErrorToFile   = TRUE;
        params.fStdOutHandle  = hLogFile;
        params.fStdErrHandle  = hLogFile;
        params.fCanStop       = TRUE;
        params.fCanShutdown   = TRUE;
        params.fCanPauseContinue = FALSE;
                                
        CWrapperService service(params);
        if (!CServiceBase::Run(service))
        {
            char msg[100];
            sprintf_s(msg, "Service failed to run w/err 0x%08lx", GetLastError());
logfile << msg << '\n';
            CloseHandle(hLogFile);
            throw exception(msg);
        }
        CloseHandle(hLogFile);
        return 0;
    }
    catch (exception &ex)
    {
logfile << ex.what() << '\n';
        CloseHandle(hLogFile);
        return -1;
    }
}
