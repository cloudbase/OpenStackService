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
    wstring environmentFile;
    wstring execStartPre;
    wstring serviceName;
    vector<wstring> additionalArgs;
};

CLIArgs ParseArgs(int argc, wchar_t *argv[]);
EnvMap LoadEnvVarsFromFile(const wstring& path);
EnvMap GetCurrentEnv();


CLIArgs ParseArgs(int argc, wchar_t *argv[])
{
    CLIArgs args;
    options_description desc{ "Options" };
    desc.add_options()
        ("environment-file,e", wvalue<wstring>(), "Environment file")
        ("exec-start-pre", wvalue<wstring>(), "Command to be executed before starting the service")
        ("service-name,n", wvalue<wstring>(), "Service name");

    variables_map vm;
    auto parsed = wcommand_line_parser(argc, argv).
        options(desc).allow_unregistered().run();
    store(parsed, vm);
    auto additionalArgs = collect_unrecognized(parsed.options, include_positional);
    notify(vm);

    if (vm.count("environment-file"))
        args.environmentFile = vm["environment-file"].as<wstring>();

    if (vm.count("exec-start-pre"))
        args.execStartPre = vm["exec-start-pre"].as<wstring>();

    if (vm.count("service-name"))
        args.serviceName = vm["service-name"].as<wstring>();
    else if (!additionalArgs.empty())
    {
        args.serviceName = additionalArgs[0];
        additionalArgs = vector<wstring>(additionalArgs.begin() + 1, additionalArgs.end());
    }

    if(args.serviceName.empty())
        throw exception("Service name not provided");

    args.additionalArgs = additionalArgs;
    if (args.additionalArgs.empty())
        throw exception("Service executable not provided");

    return args;
}

EnvMap GetCurrentEnv()
{
    EnvMap currentEnv;

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
            currentEnv[name] = value;
        }

        envPair = envPair + envPairStr.length() + 1;
    }
    ::FreeEnvironmentStrings(tmpEnv);

    return currentEnv;
}

EnvMap LoadEnvVarsFromFile(const wstring& path)
{
    wifstream inputFile(path);
    wstring line;
    EnvMap env;

    while (getline(inputFile, line))
    {
        wregex rgx(L"^([^#][^=]*)=(.*)$");
        wsmatch matches;
        if (regex_search(line, matches, rgx))
        {
            auto name = boost::algorithm::trim_copy(matches[1].str());
            auto value = boost::algorithm::trim_copy(matches[2].str());
            env[name] = value;
        }
    }

    return env;
}

int wmain(int argc, wchar_t *argv[])
{
    try
    {
        EnvMap env;
        auto args = ParseArgs(argc, argv);
        if (!args.environmentFile.empty())
        {
            auto currentEnv = GetCurrentEnv();
            env = LoadEnvVarsFromFile(args.environmentFile);
            env.insert(currentEnv.begin(), currentEnv.end());
        }

        auto it = args.additionalArgs.begin();
        wstring cmdLine = *it++;
        for (; it != args.additionalArgs.end(); ++it)
            cmdLine += L" \"" + *it + L"\"";

        CWrapperService service(args.serviceName.c_str(), cmdLine.c_str(), env);
        if (!CServiceBase::Run(service))
        {
            char msg[100];
            sprintf_s(msg, "Service failed to run w/err 0x%08lx", GetLastError());
            throw exception(msg);
        }

        return 0;
    }
    catch (exception &ex)
    {
        std::cerr << ex.what() << '\n';
        return -1;
    }
}
