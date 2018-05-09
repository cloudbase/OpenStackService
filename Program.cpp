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
#include <ostream>
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
    wstring unitPath;
    vector<wstring> environmentFiles;
    vector<wstring> environmentFilesPShell;
    vector<wstring> environmentVars;
    vector<wstring> execStartPre;
    wstring         execStart;
    vector<wstring> execStartPost;
    wstring execStop;
    vector<wstring> execStopPost;
    wstring serviceName;
    vector<wstring> additionalArgs;
    wstring logFilePath;    
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
    wstring stderrOutputType;
    wstring stderrFilePath;
    wstring stdoutOutputType;
    wstring stdoutFilePath;
};

CLIArgs ParseArgs(int argc, wchar_t *argv[]);
EnvMap LoadEnvVarsFromFile(const wstring& path);
EnvMap GetCurrentEnv();

std::wstring DEFAULT_LOG_DIRECTORY         = L"C:\\var\\log\\";
std::wstring DEFAULT_LOG_PATH      = L"c:\\var\\log\\system.log";

//wofstream g_logfile("c:\\var\\log\\openstackservice.log", std::ios_base::out | std::ios_base::app);

class wojournalstream unit_stderr;
class wojournalstream unit_stdout;
class wojournalstream unit_log;

class wojournalstream *logfile = &unit_log;

//wstring DEFAULT_SHELL_PRE  =  L"powershell -command \"& {";
wstring DEFAULT_SHELL_PRE  =  L"pwsh.exe -command \"& {";
wstring DEFAULT_SHELL_POST =  L" } \" ";
wstring DEFAULT_START_ACTION = L"Write-Host \"No Start Action\" ";

CWrapperService::ServiceParams params;


static void EscapeForPowershell(std::wstring &cmdline)

{
    for ( size_t start = 0; start != std::string::npos; ) {
        size_t end = cmdline.find(L'\"', start);
        if (end != std::string::npos) {
             cmdline.insert(end,  L"\\`");
             end += 3;
        }
        start = end;
    }

    for ( size_t start = 0; start != std::string::npos; ) {
        size_t end = cmdline.find(L'&', start);
        if (end != std::string::npos) {
             cmdline.insert(end,  L"\\`");
             end += 3;
        }
        start = end;
    }

}


CLIArgs ParseArgs(int argc, wchar_t *argv[])
{
    CLIArgs args;
    
    variables_map service_unit_options;
    options_description config{ "service-unit-options" };
    config.add_options()
        ("Unit.Description", value<string>(), "Description") 
        ("Unit.Requisite", wvalue<vector<wstring>>(), "Prereuqisites. If not present, stop service") 
        ("Unit.Before",    wvalue<vector<wstring>>(), "Do not run service if these things exist") 
        ("Unit.After",     wvalue<vector<wstring>>(), "Do not run service until these things exist") 
        ("Service.Type", wvalue<wstring>(), "Systemd service type") 
        ("Service.Shell", wvalue<wstring>(), "Windows Extension. Shell to use for exec actions. Default is Powershell") 
        ("Service.EnvironmentFile", wvalue<vector<wstring>>(), "Environment files" )
        ("Service.EnvironmentFile-PS", wvalue<vector<wstring>>(), "Environment files in powershell format" )
        ("Service.Environment", wvalue<vector<wstring>>(), "Environment Variable settings" )
        ("Service.ExecStartPre", wvalue<vector<wstring>>(), "Execute before starting service")
        ("Service.ExecStart", wvalue<wstring>(), "Execute commands at when starting service")
        ("Service.ExecStartPost", wvalue<vector<wstring>>(), "Execute after starting service")
        ("Service.ExecStop", wvalue<wstring>(), "Execute command when stopping service")
        ("Service.ExecStopPost", wvalue<vector<wstring>>(), "Execute multiple commands  after stopping service")
        ("Service.StandardOutput", wvalue<wstring>(), "standard out")
        ("Service.StandardError", wvalue<wstring>(), "standard error")
        ("Service.BusName", wvalue<wstring>(), "Systemd dbus name. Used only for resolving service type");


    options_description desc{ "Options" };
    desc.add_options()
        ("service-unit", wvalue<wstring>(), "Service uses the service unit file in %SystemDrive%/etc/SystemD/active" )
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
    
*logfile << L"check for service unit" << std::endl;
    if (vm.count("service-unit")) {
        args.unitPath = vm["service-unit"].as<wstring>();
        string unit_path( args.unitPath.begin(), args.unitPath.end());
		std::ifstream service_unit_file;
		std::string service_unit_contents;
		try {
			
			service_unit_file.open(unit_path.c_str(), ios::in);
			if (!service_unit_file.is_open()) {
				*logfile << L"counldnt open" << std::endl;
			}

			//service_unit_contents = std::string((std::istreambuf_iterator<char>()), std::istreambuf_iterator<char>());
			char buf[256];
			service_unit_file.getline(buf, 256);

			service_unit_file.clear();
			service_unit_file.seekg(0, std::ios::beg);
		}
		catch (...) {
			*logfile << L"Problems reading" << std::endl;
		}

*logfile << L"opened service unit " << service_unit_contents.c_str() << std::endl;
        auto config_parsed = parse_config_file<char>(service_unit_file, config, true);
        store(config_parsed, service_unit_options);
        notify(service_unit_options);

        for(unsigned i = 0; i < args.unitPath.length(); i++ ) {
            if (args.unitPath[i] == '\\') {
                args.unitPath[i] = '/';
            }
        }
        int start_index = args.unitPath.rfind('/');
*logfile << L"start index = " << start_index << std::endl;
        args.serviceUnit = args.unitPath.substr(start_index+1, args.unitPath.length() - start_index);
*logfile << L"has service unit " << args.serviceUnit.c_str() << std::endl;

    *logfile << L"unit path " << args.unitPath << std::endl ;
for (auto elem : service_unit_options) {
    *logfile << "elem_name ";
    *logfile << std::wstring(elem.first.begin(), elem.first.end()) << std::endl;
}

    }
    else {
        // 2do: Else derive the service name from the execStart executable
        // else give up
    }

    args.stderrOutputType = L"journal";
*logfile << L"service stdoutput = " << service_unit_options["Service.StandardOutput"].as<wstring>();
    if ( service_unit_options.count("Service.StandardOutput")) {
        args.stdoutOutputType = service_unit_options["Service.StandardOutput"].as<wstring>();
 
        if (args.stdoutOutputType.compare(0, 5, L"file:", 5)) {
            args.stdoutFilePath = args.stdoutOutputType.substr(0, args.stdoutOutputType.find_first_of(':')+1);
        }
    }
    if (args.stdoutFilePath.empty()) {
        args.stdoutFilePath = DEFAULT_LOG_DIRECTORY;
        args.stdoutFilePath.append(args.serviceUnit);
        args.stdoutFilePath.append(L".stdout.log");
    }
 
*logfile << L"open stdoutFile outputtype = " << args.stdoutOutputType << std::endl;
*logfile << L"open stdoutFile Path = " << args.stdoutFilePath << std::endl;

    unit_stdout.open(args.stdoutOutputType, args.stdoutFilePath);

    args.stderrOutputType = L"journal";
    if ( service_unit_options.count("Service.StandardError")) {
        args.stderrOutputType = service_unit_options["Service.StandardOutput"].as<wstring>();
 
        if (args.stderrOutputType.compare(0, 5, L"file:", 5)) {
            args.stderrFilePath = args.stderrOutputType.substr(0, args.stderrOutputType.find_first_of(':')+1);
        }
    }
    if (args.stderrFilePath.empty()) {
        args.stderrFilePath = DEFAULT_LOG_DIRECTORY;
        args.stderrFilePath.append(args.serviceUnit);
        args.stderrFilePath.append(L".stderr.log");
    }

*logfile << "open stderrFile Path = " << args.stderrFilePath.c_str() << std::endl;
    unit_stderr.open(args.stderrOutputType, args.stderrFilePath);

    if (vm.count("environment-file")) {
        args.environmentFiles = vm["environment-file"].as<vector<wstring>>();
    }

    if (vm.count("environment-file-pshell")) {
        args.environmentFilesPShell = vm["environment-file-pshell"].as<vector<wstring>>();
    }

*logfile << "p1" << std::endl;
    if (vm.count("log-file")) {
        args.logFilePath = vm["log-file"].as<wstring>();
        args.logFilePath.erase(remove( args.logFilePath.begin(), args.logFilePath.end(), '\"' ), args.logFilePath.end());
        args.logFilePath.erase(remove( args.logFilePath.begin(), args.logFilePath.end(), '\'' ), args.logFilePath.end());
*logfile << "p1.1 open log " << args.logFilePath << std::endl;
        unit_log.open(L"file:", args.logFilePath);
        logfile = &unit_log;
    }

*logfile << "p2" << std::endl;
    if (vm.count("service-name")) {
        args.serviceName = vm["service-name"].as<wstring>();
        args.serviceName.erase(remove( args.serviceName.begin(), args.serviceName.end(), '\"' ), args.serviceName.end());
        args.serviceName.erase(remove( args.serviceName.begin(), args.serviceName.end(), '\'' ), args.serviceName.end());
    }

*logfile << "p3" << std::endl;
    if (!additionalArgs.empty())
    {
        if (args.serviceName.empty()) {
            args.serviceName = additionalArgs[0];
        }
        additionalArgs = vector<wstring>(additionalArgs.begin(), additionalArgs.end());
    }

*logfile << "p4" << std::endl;

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
*logfile << "p4.1 " << args.serviceType << std::endl;
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

*logfile << "p4.4 after count = " << wsv.size() << std::endl;

        for (auto ws: wsv) {
            if (ws.rfind(L".service") != std::string::npos ) {
                args.after_services.push_back(ws);
*logfile << L"p4.5 after service  = " << ws << std::endl;
            }
            else if (ws.rfind(L".target") != std::string::npos ) {
                args.after_files.push_back(ws);
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

*logfile << "p5" << std::endl;
    if (service_unit_options.count("Service.ExecStartPre")) {
        vector<wstring> ws_vector = service_unit_options["Service.ExecStartPre"].as<vector<wstring>>();
        for (auto ws : ws_vector) {
           EscapeForPowershell(ws);
*logfile << "p5.1 exec start pre cmdline = " << ws << std::endl;
        }
        args.execStartPre = ws_vector;
    }

*logfile << "p6" << std::endl;

    if (service_unit_options.count("Service.ExecStart")) {
        args.execStart = service_unit_options["Service.ExecStart"].as<wstring>();
        EscapeForPowershell(args.execStart);
*logfile << "p6.1 execstart = " << args.execStart << std::endl;
    }

    if (service_unit_options.count("Service.ExecStartPost")) {
        vector<wstring> ws_vector = service_unit_options["Service.ExecStartPost"].as<vector<wstring>>();
        for (auto ws : ws_vector) {
            EscapeForPowershell(ws);
*logfile << "p6.2 execstartpost = " << ws << std::endl;
        }
        args.execStartPost = ws_vector;
    }

    if (service_unit_options.count("Service.ExecStop")) {
        args.execStop = service_unit_options["Service.ExecStop"].as<wstring>();
        EscapeForPowershell(args.execStop);
*logfile << "p6.1 execstop = " << args.execStop << std::endl;
    }


    if (service_unit_options.count("Service.ExecStopPost")) {
        vector<wstring> ws_vector = service_unit_options["Service.ExecStopPost"].as<vector<wstring>>();
        for (auto ws : ws_vector) {
            EscapeForPowershell(ws);
*logfile << "p6.2 execstoppost = " << ws << std::endl;
        }
        args.execStopPost = ws_vector;
    }

*logfile << "p7" << std::endl;
*logfile << L"service name " << args.serviceName << std::endl;
for (auto arg: additionalArgs ) {
*logfile << L"additionalArgs " << arg << std::endl;
}

*logfile << "p8" << std::endl;
    if(args.serviceName.empty())
        throw exception("Service name not provided");
    
    return args;
}



int wmain(int argc, wchar_t *argv[])
{
    try
    {
        EnvMap env;

        unit_log.open(L"file:", L"c:\\var\\log\\openstackservice.log");
        auto args = ParseArgs(argc, argv);


*logfile << L"log file name " << args.logFilePath.c_str() << std::endl;

        params.szServiceName  = args.serviceName.c_str();
        params.szShellCmdPre  = args.shellCmd_pre.c_str();
        params.szShellCmdPost = args.shellCmd_post.c_str();
        params.execStartPre = args.execStartPre;
        params.execStart      = args.execStart;
        params.execStartPost  = args.execStartPost;
        params.execStop       = args.execStop;
        params.execStopPost   = args.execStopPost;
        params.environmentFilesPS = args.environmentFilesPShell;
        params.environmentFiles   = args.environmentFiles;
        params.environmentVars    = args.environmentVars;
        params.files_before       = args.before_files;
        params.services_before    = args.before_services;
        params.files_after        = args.after_files;
        params.services_after     = args.after_services;
        params.files_requisite    = args.requisite_files;
        params.services_requisite = args.requisite_services;
        params.stdErr         = &unit_stderr;
        params.stdOut         = &unit_stdout;
        params.fCanStop       = TRUE;
        params.fCanShutdown   = TRUE;
        params.fCanPauseContinue = FALSE;
                                
        CWrapperService service(params);
        if (!CServiceBase::Run(service))
        {
            char msg[100];
            sprintf_s(msg, "Service failed to run w/err 0x%08lx", GetLastError());
*logfile << msg << '\n';
            throw exception(msg);
        }
        return 0;
    }
    catch (exception &ex)
    {
*logfile << ex.what() << '\n';
        return -1;
    }
}
