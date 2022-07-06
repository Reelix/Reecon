dotnet publish -r win-x64 --no-self-contained false -o bin/win-x64/
dotnet publish -r linux-x64 --no-self-contained -o bin/linux-x64/
REM dotnet publish -r linux-musl-x64 --self-contained false -o bin/alpine-musl-x64/
pause