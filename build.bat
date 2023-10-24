dotnet publish -r win-x64 --self-contained false --property:PublishDir=bin/win-x64/
REM dotnet publish -r linux-x64 --self-contained false --property:PublishDir=bin/linux-x64/
dotnet publish -r linux-arm64 --self-contained false --property:PublishDir=bin/linux-arm64/
REM dotnet publish -r linux-musl-x64 --self-contained false --property:PublishDir=bin/alpine-musl-x64/
pause