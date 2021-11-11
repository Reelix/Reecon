wget https://download.visualstudio.microsoft.com/download/pr/0ce1c34f-0d9e-4d9b-964e-da676c8e605a/7a6c353b36477fa84f85b2821f2350c2/dotnet-runtime-6.0.0-linux-x64.tar.gz -O dotnet-setup.tar.gz
DOTNET_SETUP_FILE=dotnet-setup.tar.gz
export DOTNET_ROOT=~/dotnet
mkdir -p "$DOTNET_ROOT" && tar zxf "$DOTNET_SETUP_FILE" -C "$DOTNET_ROOT"
export PATH=$PATH:$DOTNET_ROOT
rm "$DOTNET_SETUP_FILE"
export PATH=~/dotnet/:$PATH
