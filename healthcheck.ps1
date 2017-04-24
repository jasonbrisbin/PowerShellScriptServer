<#
    .Synopsis
    Testing script provided to verify if the web server is listening.

    .Description
    Provides a testing facility for the local web server to determine health

    .Parameter Config
    Specify an alternate configuration file to use.


#>
[CmdletBinding()]
Param(
    [parameter(Mandatory=$false)]
    [string]$config
)

#This library creates the class and method required to dynamically select
#the authentication type in the HttpListener per request.
if([string]::IsNullOrEmpty($config)){$config="$PSScriptRoot\config.xml"}
$app=[xml](get-content $config)
$port=$app.config.server.port
Try
{
    Invoke-WebRequest -Uri "http://localhost:$port/default.htm?puppet=healthcheck" -UseBasicParsing
    Exit 1
}
Catch
{
    Exit 0
}