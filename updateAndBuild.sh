#!/bin/bash

git submodule foreach git pull
git pull
#dotnet build LocalControllerCLI.slnx --configuration Release
dotnet build LocalControllerCLI.slnx
