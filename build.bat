dotnet publish -r win-x64 --self-contained false -o bin/win-x64/
dotnet publish -r linux-x64 --self-contained false -o bin/linux-x64/
dotnet publish -r linux-musl-x64 --self-contained false -o bin/alpine-musl-x64/
pause