param(
[string]$command
)

    $AdminFunctionsList=[ordered]@{
        "Debug"="Debug"
        "Verbose"="Verbose"
        "Information"="Information"
        "View Request Logs"="RequestLog"
        "Enable Request Log"="RequestLog&enable=true"
        "Disabled Request Log"="RequestLog&enable=false"
        "Log"="Log"
        "Config"="Config"
        "Shutdown"="Shutdown"
        "Restart"="Restart"
        "Page Index" = "Index"
    }

if([string]::IsNullOrEmpty($command))
    {
        
        $AdminFunctionLinks=ForEach($function in $AdminFunctionsList.Keys)
            {
                $option=new-object psobject -Property @{Functions = "<a href=/admin/default.ps1?command=$($AdminFunctionsList[$function])>$($function)</a>"}
                $option
            }
        $Title="Server Administration $($env:computername)"
        $transaction.commandOutput = $AdminFunctionLinks | ConvertTo-Html -Head $title  -Title $title -Property Functions -CssUri "/includes/css/bootstrap.css"
        $transaction.commandOutput = [System.Web.HttpUtility]::HtmlDecode($transaction.commandOutput)
        Write-Response -transaction $transaction -success
        return
    }


switch($command)
    {
        
        "Index"
            {
                if($request.querystring["browse"])
                    {
                        $browse_uri=$request.querystring["browse"]
                        if(($browse_uri -eq "/") -or ($browse_uri -match "^\/\w+\.\w+$"))
                            {
                                $transaction.location="/admin/default.ps1?command=Index"
                                Write-Response -transaction $transaction -error MovedPermanently
                            }
                        else
                            {
                                $virtualdirectory=$app.config.virtualdirectory |  where{"/$($browse_uri.trim("/"))/" -match "^/$($_.uri.trim("/"))/"}
                                $Parent=(Split-path $browse_uri -Parent).replace("\","/")
                                $parentlink="<table><tr><td><a href=/admin/default.ps1?command=Index&browse=$parent>Up</a></td></tr></table>"
                                
                                if($virtualdirectory.name)
                                    {
                                        $browsepath=join-path $virtualdirectory.path $browse_uri.trim("/").replace($virtualdirectory.uri.trim("/"),"")
                                        $browse_uri=$browse_uri.trim("/")
                                        $directorylist = @(get-childitem $browsepath -directory | Select @{label="Name";expression={"<a href=/admin/default.ps1?command=Index&browse=/$browse_uri/$_/>$_</a>"}},length,LastWriteTime)
                                        $directorylist += get-childitem $browsepath -File |  Select @{label="Name";expression={"<a href=/$browse_uri/$_>$_</a>"}},length,LastWriteTime
                                        $transaction.commandOutput = $directorylist | ConvertTo-Html -Title "Index of $browsepath" -Property Name,Length,LastWriteTime -CssUri "/includes/css/bootstrap.css" -PostContent $parentlink
                                    }
                                
                                $transaction.commandOutput = [System.Web.HttpUtility]::HtmlDecode($transaction.commandOutput)                                
                                Write-Response -transaction $transaction -success
                            }
                    }
                Else
                    {
                        $IndexLinks=ForEach($function in $app.config.virtualdirectory.uri.trim("/"))
                            {
                                $option=new-object psobject -Property @{"Virtual Directories" = "<a href=/admin/default.ps1?command=Index&Browse=/$($function)>$($function)</a>"}
                                $option
                            }
                        $parentlink="<table><tr><td><a href=/admin/default.ps1>Up</a></td></tr></table>"
                        $transaction.commandOutput = $IndexLinks | ConvertTo-Html -Title "Web Site Index" -Property "Virtual Directories" -CssUri "/includes/css/bootstrap.css" -PostContent $parentlink
                        $transaction.commandOutput = [System.Web.HttpUtility]::HtmlDecode($transaction.commandOutput)
                        Write-Response -transaction $transaction -success
                    }
                break
            }
        "Shutdown"
            {
                write-log "Shutting down." -console $false
                Write-Information "Shutting down." -InformationAction continue
                $transaction.commandOutput = "Shutdown"
                Write-Response -transaction $transaction -success
                Throw "Server shutdown requested."                
                stop-process -Id $PID
                #break
            }
        "Restart"
            {
                write-zlog "Restarting server." -console $false
                Write-Response -transaction $transaction -success                
                Write-Information "`n`nRestarting server." -InformationAction continue
                $listener.stop()
                $ServerStart.Invoke()
                #break
            }
        "Debug"
            {
                $message="Debug logging enabled"
                $script:DebugPreference = "Continue"
                $script:VerbosePreference = "SilentlyContinue"
                Write-Debug $message
                $transaction.commandOutput = ConvertTo-Html -Body "$message<script type=""text/JavaScript"">setTimeout(""location.href = '/admin/default.ps1';"",1500);</script>"
                Write-Response -transaction $transaction -success
                break
            }
        "Verbose"
            {
                $script:DebugPreference = "SilentlyContinue"
                $script:VerbosePreference = "Continue"
                $message="Verbose logging enabled"
                Write-Verbose $message
                $transaction.commandOutput = ConvertTo-Html -Body "$message<script type=""text/JavaScript"">setTimeout(""location.href = '/admin/default.ps1';"",1500);</script>"
                Write-Response -transaction $transaction -success
                break
            }
        "Information"
            {
                $script:DebugPreference = "SilentlyContinue"
                $script:VerbosePreference = "SilentlyContinue"
                $message="Default logging enabled."
                Write-Information $message
                $transaction.commandOutput = ConvertTo-Html -Body "$message<script type=""text/JavaScript"">setTimeout(""location.href = '/admin/default.ps1';"",1500);</script>"
                Write-Response -transaction $transaction -success
                break
            }
        "Log"
            {
                $message= Get-Content $global:ps3log
                if($request.querystring["format"] -ieq "raw"){$transaction.commandOutput = $message}
                else{foreach($line in $message){$transaction.commandOutput += "$line<br>"}}
                Write-Response -transaction $transaction -success
                break
            }
        "Config"
            {
                if($request.querystring["format"] -ieq "raw")
                    {
                        $transaction.commandOutput = $app.OuterXml | out-string
                        $transaction.content_type="text/plain"
                    }
                else
                    {
                        $transaction.commandOutput = $app.OuterXml
                        $transaction.content_type="text/xml"
                    }
                Write-Response -transaction $transaction -success
                break
            }
        "RequestLog"
            {
                $response_parameters=@{}
                
                if($request.querystring["enable"])
                    {
                        Switch($request.querystring["enable"])
                            {
                                "True"
                                    {
                                        #Sets the value of a variable in the Parent Scope to a new value
                                        Set-Variable -scope 1 -Name "requestlog" -value $true
                                        $message="Request logging enabled."
                                        Write-Debug $message
                                        $transaction.commandOutput = ConvertTo-Html -Body "$message<script type=""text/JavaScript"">setTimeout(""location.href = '/admin/default.ps1';"",1500);</script>"
                                        Write-Response -transaction $transaction -success
                                        break
                                    }
                                "False"
                                    {
                                        Set-Variable -scope 1 -Name "requestlog" -value $false
                                        $message="Request logging disabled."
                                        Write-Debug $message
                                        $transaction.commandOutput = ConvertTo-Html -Body "$message<script type=""text/JavaScript"">setTimeout(""location.href = '/admin/default.ps1';"",1500);</script>"
                                        Write-Response -transaction $transaction -success
                                        break
                                    }
                                default {break}
                            }
                        
                    }
                elseif($request.querystring["view"])
                    {
                        $filepath=join-path $env:tmp $request.querystring["view"]
                        if([string]::IsNullOrEmpty($request.querystring["view"]))
                            {
                                Write-Response -transaction $transaction -error FileNotFound
                            }
                        elseif(-not(Test-Path $filepath))
                            {
                                Write-Response -transaction $transaction -error FileNotFound
                            }
                        else
                            {
                                
                                Try
                                    {
                                        $transaction.commandOutput=Get-Content $filepath
                                        $transaction.content_type=[System.Web.MimeMapping]::GetMimeMapping($filepath.replace(".tmp",".xml"))
                                        Write-Response -transaction $transaction -success
                                    }
                                Catch
                                    {
                                        Write-Response -transaction $transaction -error InternalError
                                    }
                                
                            }
                    }
                else
                    {
                        $transaction.commandOutput=""
                        #$file_filter= $app.config.server.title,"??????tmp*.tmp" -join ""
                        $requestindex=join-path $app.config.server.logpath "ps3index.csv"
                        if(test-path $requestindex){$file_list=Import-Csv $requestindex}
                        else{$file_list=$null}

                        #$file_list=get-childitem $env:temp -filter $file_filter | select Name,LastWriteTime,Length | Sort-Object -Descending -Property LastWriteTime
                        
                        if($file_list.count -gt 0)
                            {
                                foreach($file in $file_list)
                                    {
                                        $file.filename="<a href=/admin/default.ps1?command=requestlog&view=$($file.filename)>$($file.filename)</a>"
                                    }
                                $transaction.commandOutput = $file_list | ConvertTo-Html -CssUri "/includes/css/bootstrap.css"
                                $transaction.commandOutput = $transaction.commandOutput.replace("<table>",'<table width="80%">')
                                $transaction.commandOutput = [System.Web.HttpUtility]::HtmlDecode($transaction.commandOutput)
                                Write-Response -transaction $transaction -success
                            }
                        else
                            {
                                $message="No request logs found."
                                Write-Debug $message
                                $transaction.commandOutput = ConvertTo-Html -Body "$message<script type=""text/JavaScript"">setTimeout(""location.href = '/admin/default.ps1';"",1500);</script>"
                                Write-Response -transaction $transaction -success
                            }
                    }
                break
            }
        
        #If an admin page/query is requested but does not match any above critetia, return an error.
        Default
            {
                $Global:DebugPreference = "SilentlyContinue"
                $Global:VerbosePreference = "SilentlyContinue"
                Write-Response -transaction $transaction -error BadRequest
                break
            }
    }

