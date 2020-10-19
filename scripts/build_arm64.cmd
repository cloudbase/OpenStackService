nuget.exe install packages.config -OutputDirectory packages

set VCVARSALL="C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat"

call %VCVARSALL% amd64_x64 10.0.17763.0 & set
MSBuild.exe /nologo /maxcpucount OpenStackService.sln /target:Build /property:Configuration="SDK10Release" /p:Platform=x64

call %VCVARSALL% amd64_arm64 10.0.17763.0 & set
MSBuild.exe /nologo /maxcpucount OpenStackService.sln /target:Build /property:Configuration="SDK10Release" /p:Platform=arm64
