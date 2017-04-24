[CmdletBinding()]
Param(
[parameter(Mandatory=$false)]
[int]$port,

[parameter(Mandatory=$false)]
[string]$title,

[parameter(Mandatory=$false)]
[string]$config
)

#This library creates the class and method required to dynamically select
#the authentication type in the HttpListener per request.
if([string]::IsNullOrEmpty($config)){$config="$PSScriptRoot\config.xml"}
Add-Type -Path "$PSScriptRoot\HttpDelegate.dll"
Add-Type -AssemblyName System.Web
Add-Type -AssemblyName System.Net
[CustomAuth]::SetDocumentPath("$config")

Function ConvertTo-HashTable
    {
        <#
            .Synopsis
            Convert an object to a HashTable test
            .Description
            Convert an object to a HashTable excluding certain types.  For example, ListDictionaryInternal doesn't support serialization therefore
            can't be converted to JSON.
            .Parameter InputObject
            Object to convert
            .Parameter ExcludeTypeName
            Array of types to skip adding to resulting HashTable.  Default is to skip ListDictionaryInternal and Object arrays.
            .Parameter MaxDepth
            Maximum depth of embedded objects to convert.  Default is 4.
            .Example
            $bios = get-ciminstance win32_bios
            $bios | ConvertTo-HashTable
        #>
        
        Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [Object]$InputObject,
        [string[]]$ExcludeTypeName = @("ListDictionaryInternal","Object[]"),
        [ValidateRange(1,10)][Int]$MaxDepth = 4
        )
        
        Process
            {
                
                Write-Verbose "Converting to hashtable $($InputObject.GetType())"
                #$propNames = Get-Member -MemberType Properties -InputObject $InputObject | Select-Object -ExpandProperty Name
                $propNames = $InputObject.psobject.Properties | Select-Object -ExpandProperty Name
                $hash = @{}
                    $propNames | % {
                        if ($InputObject.$_ -ne $null)
                            {
                                if ($InputObject.$_ -is [string] -or (Get-Member -MemberType Properties -InputObject ($InputObject.$_) ).Count -eq 0)
                                    {
                                        $hash.Add($_,$InputObject.$_)
                                    }
                                else
                                    {
                                        if ($InputObject.$_.GetType().Name -in $ExcludeTypeName)
                                            {
                                                Write-Verbose "Skipped $_"
                                            }
                                        elseif ($MaxDepth -gt 1)
                                            {
                                                $hash.Add($_,(ConvertTo-HashTable -InputObject $InputObject.$_ -MaxDepth ($MaxDepth - 1)))
                                            }
                                    }
                            }
                    }
                $hash
            }
    }

Function New-Log
{
    $path = $app.config.server.logpath
    if([string]::IsNullOrEmpty($path)){$path=$PSScriptRoot}
    if(-Not(Test-Path $path)){New-Item -Path $path -ItemType Directory | Out-Null}
    $logname = "$(Get-Date -Format "yyyyMMdd").txt"
    $path = Join-Path $path $logname
    if(-Not(Test-Path $path)){New-Item -Path $path -ItemType File | Out-Null}
    $global:ps3log=$path
}

Function Write-Log
{
    Param([string]$message,[switch]$noconsole)
    if(-not($noconsole)){Write-Information $message -InformationAction Continue} #aren't double negatives fun
    if([string]::IsNullOrEmpty($global:ps3log)){new-log}
    out-file -InputObject $message -Append -FilePath $global:ps3log -NoClobber -Encoding ascii
}

Function Write-Response
    {
        <#
            .Synopsis
            Return the response stream
            .Description
            Return the reponse stream
            .Parameter
            Object to convert
            .Parameter ExcludeTypeName
            Array of types to skip adding to resulting HashTable.  Default is to skip ListDictionaryInternal and Object arrays.
            .Parameter MaxDepth
            Maximum depth of embedded objects to convert.  Default is 4.
            .Example
            $bios = get-ciminstance win32_bios
            $bios | ConvertTo-HashTable
        #>
        
        [cmdletbinding(DefaultParameterSetName="Success")]
        Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,ParameterSetName="Success")]
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,ParameterSetName="Error")]
        [object]$transaction,

        [Parameter(Mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Success")]        
        [switch]$success=$true,

        [Parameter(Mandatory=$true,ValueFromPipeline=$false,ParameterSetName="Error")]
        [validateset("FileNotFound","ServiceUnavailable","InternalError","AccessDenied","BadRequest","Unauthorized","UnexpectedError","Teapot","UnsupportedMediaType","MovedPermanently","Found","TemporaryRedirect","PermanentRedirect","Forbidden")]
        [string]$error
        )


        Process
            {
                

                if($PSCmdlet.ParameterSetName -eq "Error")
                {                    
                    $error_code=@{
                        FileNotFound=@(404,"File not found")
                        ServiceUnavailable=@(503,"Service unavailable")
                        InternalError=@(500,"Internal error")
                        BadRequest=@(400,"Bad request")
                        Unauthorized=@(401,"Unauthorized")
                        Forbidden=@(403,"Forbidden")
                        UnsupportedMediaType=@(415,"Unsupported media type")
                        Teapot=@(418,"I'm a teapot")
                        UnexpectedError=@(420,"Unexpected error")
                        MovedPermanently=@(301,"Moved permanantly")
                        Found=@(302,"Found")
                        TemporaryRedirect=@(307,"Temporary redirect")
                        PermanentRedirect=@(308,"Permanent redirect")
                    }                    
                    $transaction.statusCode = ($error_code[$error])[0] #Error_code[FileNotFound] returns an array with 404 and "File not found" as elements.
                    $transaction.commandOutput = ($error_code[$error])[1]                                
                    
                }
                else
                {
                    $transaction.statusCode = 200                    
                }
                                
                $line_num=$MyInvocation.ScriptLineNumber
                Write-Debug "Response $($transaction.statusCode) called via line number: $line_num"
                
                #Calculate total time for transaction server side
                $transaction.totaltime=New-TimeSpan -Start $transaction.starttime -End (get-date) | select -ExpandProperty milliseconds
                $response = $context.Response
                $response.StatusCode = $transaction.statusCode
                               
                if(($transaction.Content_Type -like "image*") -and ($transaction.statusCode -eq 200))
                    {
                        $buffer = $transaction.commandOutput
                    }
                else
                    {
                        $buffer = [System.Text.Encoding]::UTF8.GetBytes($transaction.commandOutput)
                    }
                $response.AddHeader("Server","$($app.config.server.title)`n`n")

                if(-not([string]::IsNullOrEmpty($transaction.location)))
                {
                    $response.AddHeader("Location","$($transaction.location)")
                }

                $response.ContentType = $transaction.Content_Type
                $response.ContentLength64 = $buffer.Length
                $transaction.sc_bytes = $response.ContentLength64
                
                $fields=@("starttime","sitename","s_ip","method","cs_uri_stem","cs_uri_query","s_port","cs_username","c_ip","cs_useragent","referrer","s_host","statusCode","sc_bytes","cs_bytes","totaltime")
                $logmessage=($fields | %{$transaction.$_}) -join ","
                write-log $logmessage
                                                
                $output = $response.OutputStream
                $output.Write($buffer,0,$buffer.Length)
                $output.Close()                                
            }
    }

Function Invoke-ConsoleCommand {
                    [CmdletBinding(SupportsShouldProcess)]
                    param(
                        [Parameter(Mandatory)]
                        [string]$Target,

                        [Parameter(Mandatory)]
                        [string]$Action,

                        [Parameter(Mandatory)]
                        [scriptblock]$ScriptBlock
                    )

                    Set-StrictMode -Version 'Latest'

                    if(-not $PSCmdlet.ShouldProcess($Target, $Action)){
                        return
                    }

                    $output = Invoke-Command -NoNewScope -ScriptBlock $ScriptBlock
                    if ($LASTEXITCODE) {
                        $output = $output -join [Environment]::NewLine
                        Write-Error ('Failed action ''{0}'' on target ''{1}'' (exit code {2}): {3}' -f $Action,$Target,$LASTEXITCODE,$output)
                    } else {
                        $output | Where-Object { $_ -ne $null } | Write-Verbose
                    }
                }

Function Start-HTTPListener
    {
        <#
            .Synopsis
            Creates a new HTTP Listener accepting PowerShell command line to execute
            .Description
            Creates a new HTTP Listener enabling a remote client to execute PowerShell command lines using a simple REST API.
            This function requires running from an elevated administrator prompt to open a port.
            
            Use Ctrl-C to stop the listener.  You'll need to send another web request to allow the listener to stop since
            it will be blocked waiting for a request.
            .Parameter Port
            Port to listen, default is 8888
            .Parameter URL
            URL to listen, default is /
            .Parameter Auth
            Authentication Schemes to use, default is IntegratedWindowsAuthentication
            .Example
            Start-HTTPListener -Port 8080 -Url PowerShell
            Invoke-WebRequest -Uri "http://localhost:8888/PowerShell?command=get-service winmgmt&format=text" -UseDefaultCredentials | Format-List *
            
            .Notes
            Original HTTPListener code is from Steve Lee at https://blogs.msdn.microsoft.com/powershell/2014/09/29/simple-http-api-for-executing-powershell-scripts/
            
        #>
        [cmdletbinding()]
        Param (
        [Int] $Port = 7000,
        [string[]] $HostAddress = "127.0.0.1",
        [String] $Url = ""
        )
        
        Process
            {
                If ($PSBoundParameters['Debug']){$DebugPreference = 'Continue'}                       
                $host.UI.RawUI.BufferSize.Width=250

                #In order to bind a web listener to a TCP port you must be a local administrator.
                <#$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
                if ( -not ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )))
                    {
                        write-log "This script must be executed from an elevated PowerShell session" -noconsole
                        Write-Error "This script must be executed from an elevated PowerShell session" -ErrorAction Stop
                    }
                #>
                #Normalize URL address
                if ($Url.Length -gt 0 -and -not $Url.EndsWith('/'))
                    {
                        $Url += "/"
                    }
                                
                
                #Setup Logging
                New-Log
                $requestcounter=0

                #Avoid line wrapping in console output.
                If(-not($psise)){[console]::BufferWidth=1000}
                
                #region Configure HTTP Listener
                $app=[xml](get-content $config)

                #Integrity check hashes all files located in virtualdirectories and then valids that has for each call.
                #Requestlog creates a text file which contains the .Net Request object which is useful for debugging
                If ([string]::IsNullOrEmpty($app.config.server.integritycheck)){$integritycheck = $true}
                else{$integritycheck=[boolean]::Parse($app.config.server.integritycheck)}
                If ([string]::IsNullOrEmpty($app.config.server.requestlog)){$requestlog = $false}
                else{$requestlog=[boolean]::Parse($app.config.server.requestlog)}

                if($app.config.virtualdirectory.path.trim("\") -contains $PSScriptRoot.trim("\"))
                {
                    #To avoid exposing the server script and libraries the ScriptRoot cannot be shared.
                    Write-Log "The physical path of the server script cannot be shared as a virtual directory"
                    Throw "The physical path of the server script cannot be shared as a virtual directory"
                    exit
                }


                #Hash the config files and script files for change detection.
                if($integritycheck)
                {
                    write-debug "Generating hashtable for all endpoints."
                    #$current_config_hash=(Get-FileHash -Path $config -Algorithm SHA256 -debug:$false -verbose:$false).Hash
                    $current_config_hash=(Get-FileHash -Path $config -Algorithm SHA256).Hash
                    $current_endpoint_hash=@{}
                    foreach($endpoint in $app.config.virtualdirectory)
                        {
                        
                            if(test-path $endpoint.path)
                                {
                                    $file_list=get-childitem $endpoint.path -Recurse
                                    foreach($file in $file_list)
                                        {
                                            #$current_endpoint_hash[$file.fullname] = (Get-FileHash -path $file.fullname -Algorithm SHA256 -debug:$false -verbose:$false).Hash
                                            $current_endpoint_hash[$file.fullname] = (Get-FileHash -path $file.fullname -Algorithm SHA256).Hash
                                        }
                                }
                        }
                }
                
                
                $prefix="http"
                $usessl=$false
                if($app.config.server.cert)
                {
                    $instanceid=new-guid
                    $cert=$app.config.server.cert
                    if((gci cert:\localmachine\my).Thumbprint -notcontains $cert)
                    {
                        Write-Log "Certificate $cert is not found in the LocalMachine Certificate Store."
                        Throw "Certificate $cert is not found in the LocalMachine Certificate Store."
                    }
                    $UseSSL=$true
                    $prefix="https"
                    Write-Log -Message "Binding certificate [$Cert] to [$ipPort]" -noconsole              
                }
                
                $listener = New-Object System.Net.HttpListener
                foreach($hostentry in $HostAddress)
                    {
                        $ipPort="$Hostentry`:$($Port.tostring())"
                        $entry = "$prefix`://$ipPort/$Url"
                        $listener.Prefixes.Add($entry)                        
                        if($usessl){Invoke-ConsoleCommand -Target $ipPort -Action 'creating SSL certificate binding' -ScriptBlock {netsh http add sslcert ipport="$ipPort" certhash="$cert" appid="{$InstanceId}"}}
                        write-log $logmessage
                    }

                
                $ipPort="127.0.0.1:$($Port.tostring())"
                $entry = "$prefix`://$ipPort/$Url"                
                if($usessl){Invoke-ConsoleCommand -Target $ipPort -Action 'creating SSL certificate binding' -ScriptBlock {netsh http add sslcert ipport="$ipPort" certhash="$cert" appid="{$InstanceId}"}}
                 
                
                $listener.Prefixes.Add($entry)
                $currentime=get-date -f "yyyy-MM-dd HH:mm:ss"  
                Write-Log "$currentime,Web server starting at $prefix on $($env:computername)"
                
                $method   = [customauth].getmethod("ClientAuth")
                $delegate = [System.Net.AuthenticationSchemeSelector]::CreateDelegate([System.Net.AuthenticationSchemeSelector], $method)
                $listener.AuthenticationSchemeSelectorDelegate = [System.Net.AuthenticationSchemeSelector]($delegate)
                #endregion
                
                Try
                    {
                        #region initialize server environment
                        $listener.Start()
                        
                        #Write-Warning "Note that thread is blocked waiting for a request."
                        #Write-Warning "After using Ctrl-C to stop listening, you need to send a valid HTTP request to stop the listener cleanly."
                        
                        
                        $logheader='starttime,sitename,s_ip,method,cs_uri_stem,cs_uri_query,s_port,cs_username,c_ip,cs_useragent,referrer,s_host,statusCode,sc_bytes,cs_bytes,total_time'
                        Write-log $logheader
                        #endregion
                        
                        #Infinite request loop
                        while ($true)
                            {
                                
                                #region Load Configuration
                                #Routes from configuration document.  This config file gets read on every request
                                #so that the server instance does not require a reboot for changes.                                                               
                                $app=[xml](get-content $config)
                                #$new_config_hash=(Get-FileHash -path $config -Algorithm SHA256 -debug:$false -verbose:$false).Hash
                                if($integritycheck)
                                {
                                    $new_config_hash=(Get-FileHash -path $config -Algorithm SHA256).Hash
                                    if($current_config_hash -ne $new_config_hash)
                                        {
                                            $message="Configuration file has been changed. $config"
                                            Write-Log $message -noconsole
                                            Write-Warning $message
                                            if($PSBoundParameters['Verbose']){Write-Verbose $message}
                                            elseif($PSBoundParameters['Debug']){Write-Debug $message}
                                        }
                                    $current_config_hash = $new_config_hash
                                }
                            #>
                            #endregion
                            
                            #region Recieve Request
                            #Receive submitted requests
                            $context = $listener.GetContext()
                            $username = $context.User.Identity.Name
                            if([string]::IsNullOrEmpty($username)){$username="Anonymous"}
                            $request = $context.Request                           
                            $access=$false
                            #endregion
                            
                            if([string]::IsNullOrEmpty($request.ContentLength64)){$request.ContentLength64=0}
                            #region Request Parsing
                            #$logmessage=$sitename,$s_ip,$method,$cs_uri_stem,$cs_uri_query,$s_port,$cs_username,$c_ip,$cs_useragent
                            #$referrer,$s_host,$statusCode,0,0,$sc_bytes,$cs_bytes -join ","
                            $uri=[System.Uri]::new($request.url)
                            $currentime=get-date -f "yyyy-MM-dd HH:mm:ss"                            
                            $transaction=new-object System.Management.Automation.PSObject -Property @{
                                starttime = $currentime
                                sitename = $host.ui.RawUI.WindowTitle
                                s_ip = $request.LocalEndPoint
                                method = $request.HttpMethod
                                cs_uri_stem = $request.RawUrl
                                cs_uri_query = $uri.Query.trim("?")
                                s_port = $Port
                                cs_username = $username
                                c_ip = $request.RemoteEndPoint.address.IPAddressToString
                                cs_useragent = $request.UserAgent
                                referrer=$request.UrlReferrer
                                s_host=($request.userhostname).split(":")[0]
                                statusCode = 500
                                sc_bytes=0
                                cs_bytes=0
                                lb_c_ip=[string]($request.Headers.GetValues("Client-IP"))
                                uri=$uri
                                toplevel=""                                                          
                                commandOutput = ""                                
                                content_Type= "text/html"
                                totaltime=$currentime
                                location=""
                                apikey=""
                                async=""
                            }

                            #If the conversation comes from the Netscaler the Client IP it stored in an different header
                            #So we need to swap the c_ip with the HTTP header Client-IP
                            if($transaction.lb_c_ip -ne ""){$transaction.c_ip = $transaction.lb_c_ip}
                            
                            #If the URI stem contains a query string we need to strip before checking Routes.
                            if($transaction.cs_uri_stem -match "\?"){$transaction.cs_uri_stem=$transaction.cs_uri_stem.split("?")[0]}

                            #region RequestLog                            
                            #Optional logging of received HTTP requests.  Very useful for debugging.   
                            Write-debug "Generating requestlog. $requestlog = $($url.localpath)"                         
                            if(($requestlog) -and ($uri.LocalPath -notlike "/admin/*"))
                                {
                                if([string]::IsNullOrEmpty($app.config.server.requestlogpath))
                                        {
                                            $requestindex="$env:temp\ps3index.csv"
                                        }
                                    else
                                        {
                                            $requestindex= join-path $app.config.server.requestlogpath "ps3index.csv"
                                        }

                                    
                                    if(-not(test-path $requestindex))
                                    {
                                        $null=new-item $requestindex -ItemType file
                                        $header="Filename","RequestTime","URL","User" -join ","
                                        set-content -Path $requestindex -Value $header
                                    }
                                    Write-debug "Generating requestlog."
                                    $requestcounter++
                                    $tempfile = New-TemporaryFile
                                    if([string]::IsNullOrEmpty($app.config.server.requestlogpath))
                                        {
                                            $destpath=split-path $tempfile.fullname -parent
                                        }
                                    else
                                        {
                                            $destpath=$app.config.server.requestlogpath
                                        }
                                    $reqcount="{0:D6}" -f [int]$requestcounter
                                    $destfile= $app.config.server.title,$reqcount,$tempfile.name -join ""
                                    $destpath=join-path $destpath $destfile
                                    if(test-path $destpath){remove-item $destpath -force -ErrorAction SilentlyContinue}
                                    $tempfile.moveto($destpath)
                                    $request | Export-Clixml -Path $destpath
                                    $indexentry=$destfile,$transaction.starttime,$uri.localpath,$transaction.cs_username -join ","
                                    $indexentry | out-file -FilePath $requestindex -Append
                                }
                            #endregion                       
                                 
                            #APIKey Capture to be used for authentication later
                            #API Key can be passed to the server in 2 different ways.
                            #1.  Using a standard HTTP Header X-ApiKey
                            #2.  http://server.domain.com:port/scriptname.ps1?api-key
                            if($request.querystring["api-key"]){$transaction.apikey=$request.querystring["api-key"]}
                            elseif($request.querystring["apikey"]){$transaction.apikey=$request.querystring["apikey"]}
                            elseif($request.Headers.keys -contains "ApiKey"){$transaction.apikey=$request.headers.GetValues('ApiKey')}
                            else{$transaction.apikey=""}
                            
                            #Async processing
                            #Directs the web server to respond to the client that the request has been recieved before calling a script
                            if($request.querystring["async"]){$transaction.async=$request.querystring["async"]}
                            elseif($request.Headers.keys -contains "Async"){$transaction.Async=$request.headers.GetValues('Async')}
                            else{$transaction.async=""}                            
                            #endregion
                                                       
                            
                            #region Route Validation
                            #Validate Request against configured routes

                            #Root directory http://127.0.0.1:7000/ or http://127.0.0.1:7000/default.htm
                            #Localpath = /default.htm
                            #^ = beginning of string
                            #\/ = Literal character '/'
                            #\w+ = any number of word characters 'default'
                            #\. = Literal character '.'
                            #\w+ = any number of word characters 'htm'
                            #$ = end of string
                            if(($uri.LocalPath -eq "/") -or ($uri.LocalPath -match "^\/\w+\.\w+$"))
                            {
                                $route=$app.config.virtualdirectory | where{$_.uri -eq "/"}
                            }
                            else
                            {
                                # url = /includes/css/bootstrap.css
                                #$_.uri.trim handles all cases in the config file where the virtual directory has no slashes or preceeding slash
                                # includes/css/bootstrap.css or  /includes/css/bootstrap.css
                                # /includes, includes, includes/, or /includes/
                                $route=$app.config.virtualdirectory |  where{"/$($uri.localpath.trim("/"))/" -match "^/$($_.uri.trim("/"))/"}
                            }
                            
                            #Throw an error if no Route exists
                            if($route.count -eq 0)
                            {
                                $logmessage="Virtual directory $($uri.Segments[1]) was not found in config.xml"
                                write-debug $logmessage
                                write-log $logmessage -noconsole
                                Write-Response -transaction $transaction -error FileNotFound
                                continue
                            }
                            elseif($route.count -ge 2)
                            {
                                Write-Debug "Multiple virtual directories found in config.xml for $($uri.LocalPath)"
                                Write-Log "Multiple virtual directories found in config.xml for $($uri.LocalPath)" -noconsole
                                Write-Response -transaction $transaction -error InternalError
                                continue
                            }                                                            
                            
                                If(-not([System.IO.Path]::HasExtension($uri.LocalPath)))
                                {
                                    $default_documents=$app.config.defaultdocument.value
                                    $isDefaultDoc=$false
                                
                                    foreach($doc in $default_documents)
                                    {
                                        $temppath=Join-Path $route.path $doc
                                        if(Test-Path $temppath)
                                        {
                                            $isDefaultDoc=$True
                                            #redirect URL to default page
                                            $transaction.location=(join-path $uri.localpath "$doc").replace('\','/')
                                            break
                                        }

                                    }

                                    if($isDefaultDoc -eq $false)
                                        {
                                            Write-Debug "Default document not found at $($route.path)"
                                            Write-Response -transaction $transaction -error FileNotFound
                                            continue
                                        }
                                    else
                                        {
                                            #$transaction.location=$location
                                            Write-Response -transaction $transaction -error MovedPermanently
                                            continue
                                        }
                                    }
                                else
                                {

                                    #/scripts/scriptname.ps1 gets replaced with
                                    #d:\directory\and\path\from\configfile\scriptname.ps1
                                    if($route.uri -ne "/"){$localfile=$uri.LocalPath.replace("/$($route.uri.trim("/"))/","$($route.path)").replace("/","\")}
                                    else{$localfile=$uri.LocalPath.replace("/","$($route.path)").replace("/","\")}
                                    if(test-path $localfile)
                                        {
                                            if($integritycheck)
                                            {
                                                #$new_endpoint_hash=(Get-FileHash -path $localfile -Algorithm SHA256 -debug:$false -verbose:$false).Hash                                            
                                                $new_endpoint_hash=(Get-FileHash -path $localfile -Algorithm SHA256).Hash
                                                if($current_endpoint_hash[$localfile] -ne $new_endpoint_hash)
                                                    {
                                                        $message="File has been changed. $localfile"
                                                        Write-Log $message -noconsole
                                                        Write-Warning $message
                                                        if($PSBoundParameters['Verbose']){Write-Verbose $message}
                                                        elseif($PSBoundParameters['Debug']){Write-Debug $message}
                                                    }
                                                $current_endpoint_hash[$route.name]=$new_endpoint_hash
                                            }

                                            #MIME Type Mapping
                                            $fileextension=[System.IO.Path]::GetExtension($localfile)
                                            if($app.config.mime.override.name -ieq $fileextension.trim("."))
                                                {
                                                    $mime_override=$app.config.mime.override | where{$_.name -ieq $fileextension.trim(".")}
                                                    if([string]::IsNullOrEmpty($mime_override.content)){$mime_override.content="text/html"}
                                                    if([string]::IsNullOrEmpty($mime_override.type)){$mime_override.type="text"}
                                                    $transaction.content_type=$mime_override.content
                                                    $content_operation=$mime_override.type
                                                }
                                            else
                                                {
                                                    $transaction.content_type=[System.Web.MimeMapping]::GetMimeMapping($localfile)
                                                    $content_operation="text"
                                                    if($transaction.content_type -like "image*")
                                                        {
                                                            $content_operation="image"
                                                        }
                                                }
                                            
                                            
                                        }
                                    
                                    #Throw an error if the file was not found and skip to the next request.
                                    else
                                        {
                                            Write-Warning "File not found $($localpath)"
                                            write-debug "Request: $($uri.localpath)"
                                            write-debug "Local path: $($localfile)"                                            
                                            Write-Response -transaction $transaction -error FileNotFound
                                            continue
                                        }
                                }
                            #endregion
                            
                            #region Access Control
                            #Deny by default, this flag only changes if the user is found to satisfy an access rule from the config file
                            #Note this check is done for every request.
                            $access=$false
                            $IsAuthenticated=$false
                            $IsAuthorized=$false

                            #region Authenticate
                            #Authenticated
                            If($context.user.Identity)
                                {
                                    $IsAuthenticated=$context.user.Identity.IsAuthenticated  
                                    $identity = $context.User.Identity            
                                    $AuthType = $context.user.Identity.AuthenticationType
                                    $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($identity)                        
                                    #$transaction.cs_username = $identity.Name
                                    Write-debug "Authorization requested from $($identity.Name) for route $($route.uri)"
                                }                                 
                                                               
                            #Anonymous access
                            elseif($route.auth -ieq "anonymous")
                                {
                                    $IsAuthenticated=$true
                                    Write-debug "Anonymous access requested for route $($route.uri)"
                                    $transaction.cs_username = "Anonymous"
                                    $AuthType = "Anonymous"
                                }

                            #If the user was not authenticated respond with unauthorized
                            Else
                                {
                                    Write-debug "Access denied. User was not authenticated"
                                    Write-Response -transaction $transaction -error Unauthorized
                                    continue
                                }                                
                            #endregion

                            #region Authorize
                            $Group_List=@()
                            $Api_list=@()
                            $Address_list=@{}
                            $auth_list=@()
                            foreach($item in $route.authorize)
                            {
                                if($item.group){$Group_List+=$item.group;$auth_list+="group"}
                                elseif($item.api){$Api_list+=$item.api;$auth_list+="api"}
                                elseif(-not([string]::IsNullOrEmpty($item.address))){$Address_list[$item.address]=$item.mask;$auth_list+="network"}
                            }
                            foreach($item in $app.config.authorize)
                            {
                                if($item.group){$Group_List+=$item.group;$auth_list+="group"}
                                elseif($item.api){$Api_list+=$item;$auth_list+="api"}
                                elseif(-not([string]::IsNullOrEmpty($item.address))){$Address_list[$item.address]=$item.mask;$auth_list+="network"}
                            }
                            $auth_list=$auth_list | select -Unique

                            #If the request was authenticated anonymous and there are no additional access rules for that
                            #virtual directory then the request is acceptable.  Such as requests for graphics, stylesheets, etc.
                            if(($auth_list.count -eq 0) -and ($authtype -eq "Anonymous")){$auth_list+="anonymous"}

                            Foreach($auth in $auth_list)
                            {
                                #Doing the check inside the this loop allows us to have multiple authorization schemes
                                #if any fail the foreach loop is exited at the end and the request is rejected.
                                Switch($auth)
                                {
                                    "group"
                                        {
                                            #Group Access
                                            $IsAuthorized=Check-AccessGroup -transaction $transaction -groups $Group_List -principal $WindowsPrincipal
                                            break
                                        }
                                    "api"
                                        {
                                            #API Access
                                            $IsAuthorized=Check-AccessAPI -transaction $transaction -apikeys $Api_list
                                            break
                                        }
                                    "network"
                                        {
                                            #Network Access Check
                                            $IsAuthorized=Check-AccessNetwork -transaction $transaction -networks $Address_list
                                            break
                                        }
                                    "anonymous"
                                        {
                                            Write-Debug "Anon Access Evaluation"
                                            $IsAuthorized = $true
                                            break
                                        }
                                    default
                                        {
                                            #This should only occur if the config file has invalide ACCESS elements in it for the route specified.
                                            Write-Debug "Access evaluation failure"
                                            $IsAuthorized = $false
                                            break
                                        }
                                }

                                #Exit loop if ANY auth check registers false
                                if($IsAuthorized -eq $false){break}
                            }
                                                                                                                                                                                                                                                                                
                            #Return a message that the user is unauthorized
                            If($IsAuthorized -eq $false)
                                {
                                    Write-debug "Access Denied. User/request was not authorized"
                                    Write-Response -transaction $transaction -error Forbidden
                                    continue
                                }
                            #endregion
                            
                            #region Request Execution
                            
                            if(($IsAuthenticated) -and ($IsAuthorized))
                                {                                                                                                            
                                    [System.Text.Encoding]$encoding = $request.ContentEncoding
                                    [System.IO.StreamReader]$reader=$request.InputStream
                                    
                                    #Read in body content
                                    $body=$reader.ReadToEnd()
                                    $commandOptions=@{}
                                    $commandOptions.Request = $transaction

                                    #Convert from JSON
                                    Try
                                        {
                                            #Check to see if the request has a message body (METHOD = POST)
                                            if($request.HasEntityBody)
                                            {
                                                $body = $body | convertfrom-json
                                                $commandOptions.InputObject=$body
                                            }
                                        }
                                    Catch
                                        {
                                            Write-Warning "Message was not a valid JSON"
                                            write-Debug "Request:`n$body"
                                            Write-Debug "Bad request:  Message was not a valid JSON"                                            
                                            Write-Response -transaction $transaction -error BadRequest
                                            continue
                                        }
                                    #endregion
                                    
                                    #region Execute receiver script
                                    #MAGIC HAPPENS HERE ;-)
                                    Try
                                        {
                                            switch($content_operation)
                                                {                                            
                                                    "script"                                         
                                                        {
                                                            #The querystring will be passed to the called script via splatting
                                                            if($request.QueryString)
                                                                {
                                                                    foreach($item in $request.querystring.keys)
                                                                        {
                                                                            if(($item -eq "api-key") -or ($item -eq "async")){continue}
                                                                            $commandOptions.($item)=$request.querystring[$item]
                                                                        }
                                                                }
                                                                                                                        
                                                            #The difference here is subtle DotSource vs Call
                                                            #For the Admin URI ONLY, we will DotSource the script so we have access to
                                                            #the main scripts memory scope.  This allows access to variables and objects
                                                            #to manipulate the runtime.
                                                            #The external Call is used for everything else to provide memory isolation.
                                                            if($route.name -ine "admin")
                                                            {
                                                                Write-debug "Executing: & $($localfile) @commandOptions"
                                                                                    
                                                                #If Async is not specified call the script and return the response                              
                                                                if([string]::IsNullOrEmpty($transaction.async))
                                                                {             
                                                                                              
                                                                    $result={& $localfile @commandOptions}.Invoke()
                                                                    $transaction.commandOutput=$result.output
                                                                    $transaction.content_type=$result.content_type
                                                                    if($result.status -eq "Success"){Write-Response -transaction $transaction -success}
                                                                    else{Write-Response -transaction $transaction -error $result.status}
                                                                }

                                                               #If Async is specified submit the job                            
                                                               else
                                                                { 
                                                                    $asynccount="{0:D6}" -f [int]$requestcounter
                                                                    #Script authors will need to handle output
                                                                    get-job -name "PS3Async_*" | Where{$_.state -eq "Completed"} | remove-job
                                                                    #$job=start-job -Name "PS3Async_$asynccount" -ScriptBlock {Param($localfile);& $localfile} -ArgumentList $localfile
                                                                    $job=start-job -name "PS3Async_$asynccount" -ScriptBlock {param($localfile,$commandoptions);& $localfile @commandoptions} -ArgumentList $localfile,$commandoptions                                                                    
                                                                    $transaction.commandOutput="Request received."
                                                                    Write-Response -transaction $transaction -success
                                                                }
                                                            }
                                                            else
                                                            {
                                                                Write-debug "Executing: . $($localfile) @commandOptions"
                                                                {. $localfile @commandOptions}.Invoke()                                                                
                                                            }                                                  
                                                            
                                                            break
                                                        }
                                                    "image"
                                                        {
                                                            Write-debug "Getting image data for $localfile"
                                                            $transaction.commandOutput=get-content $localfile -Encoding Byte
                                                            Write-Response -transaction $transaction -success
                                                            break
                                                        }
                                                    Default
                                                        {
                                                            Write-debug "Getting content for $localfile"
                                                            $transaction.commandOutput=get-content $localfile
                                                            Write-Response -transaction $transaction -success
                                                            break
                                                        }
                                                }
                                            
                                            
                                        }
                                    Catch
                                        {
                                            Write-Log "Error thrown by script $($localfile)"
                                            Write-Log $_
                                            
                                            if($requestlog)
                                                {
                                                    $tempfile = New-TemporaryFile
                                                    if([string]::IsNullOrEmpty($app.config.server.requestlogpath))
                                                        {
                                                            $destpath=split-path $tempfile.fullname -parent
                                                        }
                                                    else
                                                        {
                                                            $destpath=$app.config.server.requestlogpath
                                                        }
                                                    $reqcount="{0:D6}" -f [int]$requestcounter
                                                    $destfile= $app.config.server.title,$reqcount,"error",$tempfile.name -join ""
                                                    $destpath=join-path $app.config.server.requestlog $destfile
                                                    if(test-path $destpath){remove-item $destpath -force -ErrorAction SilentlyContinue}
                                                    $tempfile.moveto($destpath)
                                                    set-content -Path $destpath -value $_
                                                    
                                                }
                                                                                        
                                            Write-Response -transaction $transaction -error UnexpectedError
                                            continue
                                        }
                                    #endregion
                                    
                                }
                            #endregion
                            
                            
                        }
                }
            Catch
                {
                    Write-Log $_
                    Write-Response -transaction $transaction -error UnexpectedError
                }
            finally
                {
                    $listener.Stop()                                       
                    if($usessl)
                    {
                        foreach($hostentry in $HostAddress)
                        {
                            $ipPort="$Hostentry`:$($Port.tostring())"                     
                            Invoke-ConsoleCommand -Target $ipPort -Action 'creating SSL certificate binding' -ScriptBlock {netsh http delete sslcert ipport="$ipPort"}
                            write-log $logmessage
                        }                
                        $ipPort="127.0.0.1:$($Port.tostring())"                    
                        Invoke-ConsoleCommand -Target $ipPort -Action 'creating SSL certificate binding' -ScriptBlock {netsh http delete sslcert ipport="$ipPort"}
                    }
                }
        }
}

Function Compare-Subnets
{
        param (
        [parameter(Mandatory=$true)]
        [Net.IPAddress]
        [alias("IP1")]
        $SourceAddress,
        
        [parameter(Mandatory=$true)]
        [alias("IP2")]
        [Net.IPAddress]
        $TargetAddress,
        
        [parameter()]
        [alias("SubnetMask","Subnet")]
        [Net.IPAddress]
        $TargetMask ="255.255.255.0"
        )
        
        $bin_source=[string]::Join("",($SourceAddress.GetAddressBytes() | %{[Convert]::ToString($_, 2).PadLeft(8, '0') }))
        $bin_target=[string]::Join("",($TargetAddress.GetAddressBytes() | %{[Convert]::ToString($_, 2).PadLeft(8, '0') }))
        $bin_subnet=[string]::Join("",($TargetMask.GetAddressBytes() | %{[Convert]::ToString($_, 2).PadLeft(8, '0') }))
        $mask_bits=([regex]::matches($bin_subnet,"1").count)
        #Write-Debug "$($bin_source.Insert($mask_bits,"/")) - Network Address/Source Address - $($SourceAddress)"
        #Write-Debug "$($bin_target.Insert($mask_bits,"/")) - Network Address/Target Address - $($TargetAddress)"
        if (($SourceAddress.address -band $TargetMask.address) -eq ($TargetAddress.address -band $TargetMask.address)) {return $true}
        else {return $false}
    }

Function Check-AccessAPI
{
    Param(

    [object]$transaction,
    [string[]]$apikeys
    )

    #If the route accepts API keys check for the key.  If none found then continue to next authorization check (group membership)
    if($transaction.apikey -eq "")
    {
        return $false        
    }
    Write-debug "API Authorization requested with key '$($transaction.apikey)' for route $($route.uri)"
    foreach($key in $apikeys)
        {
            if($key -eq $transaction.apikey)
                {
                    Write-debug "Authorized Key for route $($route.uri)"
                    $transaction.cs_username = "API"  
                    return $true                                      
                }
        }                                          
        return $false
}

Function Check-AccessGroup
{
    Param(

    [object]$transaction,
    [string[]]$groups,
    [System.Security.Principal.WindowsPrincipal]$principal

    )

    Write-Debug "Group Membership authorization requested for $($principal.Identities.name) for route $($transaction.uri.localpath)"
    foreach($entry in $groups)
        {            
            if($principal.IsInRole($entry))
                {
                    Write-debug "Authorized via '$entry' for '$($transaction.uri.localpath)'"
                    return $true
                }
            else
                {
                    #Write-Debug "User is not a member of '$entry'"
                }
        }
    return $false
}

Function Check-AccessNetwork
{
Param(

[object]$transaction,
[hashtable]$networks

)
    Write-debug "Network authorization requested from $($transaction.c_ip) for route $($transaction.uri.localpath)"                                                                        
    $addresses=$networks.keys
    foreach($entry in $addresses)
        {
            if(Compare-Subnets -SourceAddress $transaction.c_ip -TargetAddress $entry -TargetMask $networks[$entry])
                {
                    Write-debug "Authorized via $($entry)`/$($networks[$entry])"
                    return $true
                }
            else
                {
                    #Write-Debug "Address $($transaction.c_ip) is not in the same network as '$entry'"
                }
        }      
    return $false                              
}

If ($PSBoundParameters['Debug']){$DebugPreference = 'Continue'}
$SaveVerbosePreference=$VerbosePreference
$SaveDebugPreference=$DebugPreference
$VerbosePreference="SilentlyContinue"
$DebugPreference="SilentlyContinue"
import-module \\pdnas01\Scripts\Modules\RCIS-Command.psm1 -force | out-null
import-module ActiveDirectory -force | out-null
$VerbosePreference=$SaveVerbosePreference
$DebugPreference=$SaveDebugPreference
$app=[xml](get-content $config)
$ServerStart={Start-HTTPListener -port $port -HostAddress $IP}

#Temp file cleanup.
get-childitem $app.config.server.requestlogpath -Filter "ps3*" | remove-item -Force -ErrorAction SilentlyContinue


if([string]::IsNullOrEmpty($app.config.server.ip))
    {
        $IP=([System.Net.DNS]::GetHostAddresses($env:computername) |where{$_.addressfamily -eq "InterNetwork"}).ipaddresstostring
        $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    }
else
    {
        $ip=$app.config.server.ip -split ","
    }
$Connections = $TCPProperties.GetActiveTcpListeners() | where{$_.port -eq $port.tostring()}
if(-not($title)){$title="$($app.config.server.title)@$IP`:$($app.config.server.port)"}
if(-not($port)){$port=$app.config.server.port}
$host.ui.RawUI.WindowTitle=$title

if(-not($Connections))
    {
        #$ServerStart.Invoke()
        Start-HTTPListener -port $port -HostAddress $IP
    }
else
    {
        Write-Log "Port is already in use."
        Write-Warning "Port is already in use."
    }

# SIG # Begin signature block
# MIIRYQYJKoZIhvcNAQcCoIIRUjCCEU4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUAGF/+crq1rRVSmgx7J2rZr7L
# l22ggg7FMIIGxDCCBKygAwIBAgIKahrk7wABAAAFJTANBgkqhkiG9w0BAQsFADBX
# MRMwEQYKCZImiZPyLGQBGRYDY29tMRQwEgYKCZImiZPyLGQBGRYEcmNpczEUMBIG
# CgmSJomT8ixkARkWBGNvcnAxFDASBgNVBAMTCy1QRFBLSTAxLUNBMB4XDTE2MDUw
# OTE0MjU1MFoXDTIwMDExMTIyNTg0M1owEjEQMA4GA1UEAxMHQnJpc2owMTCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJgxR03ETSORWLIsRug2jgkAV5Ke
# NunQt6apgVcqY3HlJKsaeDb3wWvZuuYz6RVh8BYf79NhdYfTSVJdEleBsz8nPzrU
# GOt+znSrGaQy2d2YCy6Ij2nlrDA2maEIL91CHB4dshVJx5YZVKfJso0NpM/PxXDr
# tKWAvc5blILEtqLjO+P6HmYNH7qu+15Uk6w+Aw9AvL1cMf1cTFqa0HiB3gFkZp04
# HnnbxlhDI3z5we/A4/v7WHUz0SW+P5B57EGaj5SWyCLkvBHE9c3jIVTDqG4UrfZL
# o56LUbtLeun3hJ8bLD21CEFxArtcP32bY1Niy5x1B6L1UEhOO90q+MJDooECAwEA
# AaOCAtUwggLRMD0GCSsGAQQBgjcVBwQwMC4GJisGAQQBgjcVCIKRyHiJsCSB1Ycw
# gee+T4H4l0GBFIaH02SG8YscAgFkAgEHMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4G
# A1UdDwEB/wQEAwIHgDAbBgkrBgEEAYI3FQoEDjAMMAoGCCsGAQUFBwMDMB0GA1Ud
# DgQWBBQKECZbyedawTl+egstb+C+CxrpTDAfBgNVHSMEGDAWgBQThvdzAfxci63W
# Sx/dkZQoBYzQ7jCCARUGA1UdHwSCAQwwggEIMIIBBKCCAQCggf2GgbdsZGFwOi8v
# L0NOPS1QRFBLSTAxLUNBLENOPVBEUEtJMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtl
# eSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y29y
# cCxEQz1yY2lzLERDPWNvbT9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/
# b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnSGQWZpbGU6Ly9cXHBkbmFz
# MDEuY29ycC5yY2lzLmNvbVxpbmZyYXN0cnVjdHVyZVxjcmxcLVBEUEtJMDEtQ0Eu
# Y3JsMIHCBggrBgEFBQcBAQSBtTCBsjCBrwYIKwYBBQUHMAKGgaJsZGFwOi8vL0NO
# PS1QRFBLSTAxLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxD
# Tj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNvcnAsREM9cmNpcyxEQz1j
# b20/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25B
# dXRob3JpdHkwMAYDVR0RBCkwJ6AlBgorBgEEAYI3FAIDoBcMFWJyaXNqMDFAY29y
# cC5yY2lzLmNvbTANBgkqhkiG9w0BAQsFAAOCAgEAkEid8cHreH6SmIryFK5Rk9vE
# CYcJoavgkTg0VIWP87KU9iWk0E7nw6GJoZmFSR3kbbzeYSU+ytyW+e2E0G4QeEaV
# qWKV3YXm96oj689B5sKa0k904n3hueY3/BXBIztVBzcoeZ2E8ni9AwIqnZKQq9LP
# t/nBrY7Si5q/Uw5ULjJ7wtTS37tOkMeNStl3PUygzUq/qACkmtduPt1fXbRsUY2c
# 9Li/uaelUm9UAtN77GrNF01bzkaPnyDk8m5qzw4EM7gvVy+H3+oc4scDBHsuIrFD
# Yk4qFvnR17wgBooKs9c4qMfntWcv3Ke4IWIzrT3I/J2toPOeh2QClSeMAUR8smnm
# 1yHUpC5m3X0vCdtusHf1p0bw1xKoL8hfQthR/noDAYQUEpUtSsqnN4EfpvNpmfMf
# 2MqPXC90zxKRNmt8Kp5BjPp9TXKa2EEghwsSkTlm2QV0I9rsrbBP2TT6bmyzssp9
# /Gi8ZZ4paXgpnu3CdVDeyL/SNQXj8b0/MrKCXMwrY8vb8xX93GQl+vAm5JoCcUzn
# jjKQLExzZ9h1x+SUVj/qMpEsB+gvKWvYN0RFpspJcHHLKAhwt+VTwmRO0AmRlpTn
# tCDd6Zh+Fb0nSy7PprBGVUuVDEUSMHFWrRP1zKr949SWcn81YfelljPjSiazdcRD
# z2Pbju+EyMCF8ga3wAAwggf5MIIF4aADAgECAgphQoomAAAAAAAHMA0GCSqGSIb3
# DQEBBQUAMBgxFjAUBgNVBAMTDVBLSVJPT1RMT1ctQ0EwHhcNMTAwMTExMjI0ODQz
# WhcNMjAwMTExMjI1ODQzWjBXMRMwEQYKCZImiZPyLGQBGRYDY29tMRQwEgYKCZIm
# iZPyLGQBGRYEcmNpczEUMBIGCgmSJomT8ixkARkWBGNvcnAxFDASBgNVBAMTCy1Q
# RFBLSTAxLUNBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArj9MgjKI
# 1Wjr9uPmW0irGI0eQC8ems7m8xUIurXLr16r1TglB9jU+/Tyfupl5q0scDr38lis
# zWNA4vYkK2yE4BAL1KCO2TZn7uVyJgTvhDaNDURSBAxYM83z8ItWT35fb2y341C8
# IM1ureMpXCYcSiJGl50lQ968Lm+1/1BoYe/zjftjrgo8JdHOstSDxOyl+VHUuwMm
# pEF3OFkKhpiaklGYDq36A8TvtpDGMur4wKJ2kheA35khaVNsJm6bXWCL1Sf6GFh2
# HyDD7tKMLHUXU+NHs48aFKmY7Ml2eRFoKr0vMfdbzCjD5++xklyraJ6WHtL+pDR0
# Zin0Rr5ZuufqgJLiDV0uV7UNU10YdQN/X+vampBg42/9aIzWd7+8+d8jEmepzzCu
# 7iyx6qwgqYu8w70dwZ7BQGjEdQZMqewtMub3dXGWQ+wQuKA+gqAZC4lLhiSqmROO
# en919EWfA33Kb+bFyxIumclWmH0TSxbnEI5IFGIvbUsv8WeRlo1rHyE21gIRZ8XI
# jEv9wBaxh+CyEuY2wDC96AEJ2RgB7lQ+sgubqyWzt8nRIFkk7Jskik4EMpotmdBH
# /u1pgtPaDI5UcJhqmSR6E+5J7y5sxfi0IEOdKVADzjxFvtQ0cWLCoCFvY75jDTLs
# RSKyjQiUEs8I+6oHcxUTHacgzlsOPPtUHUECAwEAAaOCAwQwggMAMBAGCSsGAQQB
# gjcVAQQDAgEBMCMGCSsGAQQBgjcVAgQWBBSZv8qSEebWEZxVeSW6U55LjLDsyDAd
# BgNVHQ4EFgQUE4b3cwH8XIut1ksf3ZGUKAWM0O4wGQYJKwYBBAGCNxQCBAweCgBT
# AHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgw
# FoAUoi9qUhAav5r6bc8T3vpDWIlvIK8wggEdBgNVHR8EggEUMIIBEDCCAQygggEI
# oIIBBIaBvGxkYXA6Ly8vQ049UEtJUk9PVExPVy1DQSxDTj1QS0lSb290TG93LENO
# PUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1D
# b25maWd1cmF0aW9uLERDPWNvcnAsREM9UkNJUyxEQz1jb20/Y2VydGlmaWNhdGVS
# ZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBv
# aW50hkNmaWxlOi8vXFxwZG5hczAxLmNvcnAucmNpcy5jb21caW5mcmFzdHJ1Y3R1
# cmVcY3JsXFBLSVJPT1RMT1ctQ0EuY3JsMIIBKwYIKwYBBQUHAQEEggEdMIIBGTCB
# sQYIKwYBBQUHMAKGgaRsZGFwOi8vL0NOPVBLSVJPT1RMT1ctQ0EsQ049QUlBLENO
# PVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3Vy
# YXRpb24sREM9Y29ycCxEQz1SQ0lTLERDPWNvbT9jQUNlcnRpZmljYXRlP2Jhc2U/
# b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTBjBggrBgEFBQcwAoZX
# ZmlsZS8vJTVDJTVDcGRuYXMwMS5jb3JwLnJjaXMuY29tJTVDaW5mcmFzdHJ1Y3R1
# cmUlNUNjcmwlNUNQS0lSb290TG93X1BLSVJPT1RMT1ctQ0EuY3J0MA0GCSqGSIb3
# DQEBBQUAA4ICAQBOggaeM2VhunXHncfFzqT0TBDMap7W4Djvjz0CWmhbkyP+3IO3
# /LoDzNQVD8H8IePSPOGMdeZbqwX4auCX5Q0dD6pG1/kifehPijf8sAUNlvvMV0Xj
# xVN1xe5/j+7ZbhFGmdWZriQnEHa/XS4aQn6/pYf8O/B4ATrUL1f6muFdtWq+pb5J
# 47+tb4zLVgHcB8TyjFfqX6hBqyA6AfhrdfUQw1wSCo85GdV5fxsYCIUoZV8M8p36
# GLPWkmKUA0M7vtMbsXIUMdCGgGVVHjEs81DyxqTL/lu797kHpx0s8em6lNUansmL
# b/J73V7i7Fga7k5+tPi8423rAfTmfvhyT9lx/CJSMSbkn/wI6/Ejf8Ty5MKk8q8n
# tDvefurFg1bJ50IDf35Ee3DOW8JuypwBnaUagg80RZb3zmpytDUPjujL7cEMKEqu
# bCYqE/h+7B3Xe5+1luWG6QJbG3Py9ZUzThiKDPHkQlidPSh39vKZvI5VLJePK2QG
# IU/UWD3Gb9RtlTh1N+es56E2Mhlvo/IMqCGsbDJAPV5O2XhH7MSYADXZ/sTOlRnL
# EaeXvaLJ7axt9G5IJlKKuvKyf8/ZpIV+FxLlFKjurTeIJlkhhQyEiXNQ1pya5gve
# vPzD+vB53iwEo4iZs8lnTbOHu6/k+cdNJejtwAy9n2SjWUwm5TXzADT6yjGCAgYw
# ggICAgEBMGUwVzETMBEGCgmSJomT8ixkARkWA2NvbTEUMBIGCgmSJomT8ixkARkW
# BHJjaXMxFDASBgoJkiaJk/IsZAEZFgRjb3JwMRQwEgYDVQQDEwstUERQS0kwMS1D
# QQIKahrk7wABAAAFJTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUyisyJL3Cp43FYHDw6s0/Kcg6
# +z8wDQYJKoZIhvcNAQEBBQAEggEAhyJu856cRon2focQ68Nt7U0NX3v+7R+wQ/ay
# 9uqPJjn8oSe6jETaR59UMD4y6zLJPrqV179/C13PqrMKBCNFTCZ1LnQd60xjGZgd
# TX9Offbr56v+U1IbVTOTRGDL4HQJMQ4lx75c0mkBAFbd3QEZVENz5ILHgMygDFEB
# rI/pMvi25iC6Nx+j//IFmoZSr/AkE9pHc462OF9LSq873hL97Be+NXD9K12Wrgh+
# Ke4N8Qfwb6mdDeXeos2FmPmC0dxSe0qsAfqRzfZXVOA4gxV1bRcAzKPEvS6+uNEM
# V6xvEu0biR9IenOIjn57HHScG+rxy8LlbE/4MAxMdrdKBwLdMw==
# SIG # End signature block



