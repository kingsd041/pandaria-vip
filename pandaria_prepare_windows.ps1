$ErrorActionPreference = 'Stop'

rm -r -Force vendor\github.com\rancher\types\*
cp -r .vendor_pandaria\github.com\rancher\types\* vendor\github.com\rancher\types\
rm -r -Force vendor\github.com\rancher\kontainer-engine\*
cp -r .vendor_pandaria\github.com\rancher\kontainer-engine\* vendor\github.com\rancher\kontainer-engine\
rm -r -Force vendor\github.com\Azure\azure-sdk-for-go\*
cp -r .vendor_pandaria\github.com\Azure\azure-sdk-for-go\* vendor\github.com\Azure\azure-sdk-for-go\
cp package\windows\Dockerfile_pandaria.agent package\windows\Dockerfile.agent
