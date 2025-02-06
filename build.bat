dotnet publish -r win-x64 --self-contained true --property:PublishDir=bin/win-x64/,assemblyname=reecon,PublishSingleFile=true,EnableCompressionInSingleFile=true --configuration=Release
dotnet publish -r linux-x64 --self-contained true --property:PublishDir=bin/linux-x64/,assemblyname=reecon,PublishSingleFile=true,EnableCompressionInSingleFile=true --configuration=Release
dotnet publish -r linux-arm64 --self-contained true --property:PublishDir=bin/linux-arm64/,assemblyname=reecon,PublishSingleFile=true,EnableCompressionInSingleFile=true --configuration=Release
dotnet publish -r linux-musl-x64 --self-contained true --property:PublishDir=bin/linux-musl-x64/,assemblyname=reecon,PublishSingleFile=true,EnableCompressionInSingleFile=true --configuration=Release
pause