#!/bin/bash
#
# Pull everything and build it.
#
# The ISO 15118 schemas are not in any of these repositories and are not
# fetched here either - that is a licence you accept yourself, once:
#
#   bash libs/WWCP_ISO15118/tools/download-schemas.sh

set -e

cd "$(dirname "$0")"

git submodule foreach git pull
git pull
#dotnet build LocalControllerCLI.slnx --configuration Release
dotnet build LocalControllerCLI.slnx
