#!/bin/bash
#
# Pull everything and build it.
#
# Nothing has to be fetched by hand first. The ISO 15118 repository is a
# submodule here, but nothing in this solution builds any of it, so ISO's
# schemas are not needed; the TypeScript and SASS compilers the libraries pin
# are installed by "npm ci" on the first build, and the OCPP stylesheets are
# compiled by the build rather than by hand.

set -e

cd "$(dirname "$0")"

git pull --ff-only
git submodule update --init --recursive
git submodule foreach git checkout master
git submodule foreach git pull
#dotnet build LocalControllerCLI.slnx --configuration Release
dotnet build LocalControllerCLI.slnx
