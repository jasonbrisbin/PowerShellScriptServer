<#   
	.SYNOPSIS
        [IN DEVELOPMENT] Cleans up datastores and volumes created by the Self-Serve Restore process.
    
    .DESCRIPTION
        Searches all vCenter servers for datastore names beginning with "SSR-" and containing a datetime older than a specified number of hours.
        If it finds any, it deletes those datastores and their associated volumes.
    
    .EXAMPLE
    	PS>SSR_Cleanup.ps1

    .NOTES
        Author: Jake Gates
        Version: 0.1
        Date: 20170201
	
    .LINK
#>

#region Parameters
#Create well structured parameters to be supplied to the script
param(
    #region Standard Parameters
        #This object contains the message body object converted from JSON if any was passed
        [parameter(Mandatory=$false)]
        [object]$InputObject,

        #This object contains the actual HTTP request that was received
        [parameter(Mandatory=$false)]
        [object]$Request,

        #Default status code
        [parameter(Mandatory=$false)]
        [validateset("Success","FileNotFound","ServiceUnavailable","InternalError","AccessDenied","BadRequest","Unauthorized","UnexpectedError","Teapot","UnsupportedMediaType","MovedPermanently","Found","TemporaryRedirect","PermanentRedirect","Forbidden")]
        [string]$status_code = "Success",

        #Default content type
        [parameter(Mandatory=$false)]
        [validateset("text/html","application/json","text/xml","text/csv")]
        [string]$content_type="text/html",

         #Default content type  Example might be @{"Location" = "/some/other/page.htm"}
        [parameter(Mandatory=$false)]
        [hashtable]$additional_headers
    #endregion

)
#endregion

#region Begin
#Processes that run once and only at the begining of the script.

	#region Modules
		#Import all modules required by script here

        Try
        {
		$module_path = "\\pdnas01\infrastructure\scripts\modules"
		Import-Module (Join-Path $module_path RCIS-Command.psm1) -force
		Import-Module (Join-Path $module_path Uncommon\PureStorage\PureStoragePowerShellSDK) -force
        import-module VMware.VimAutomation.Core

		# set vSphere module default settings
		Set-PowerCliConfiguration -DefaultVIServerMode Single -InvalidCertificateAction Ignore `
			-DisplayDeprecationWarnings $false -Scope Session -Confirm:$false | Out-Null
        }
        Catch
        {
            $Output="Unable to load modules. $($Error[0])"
            $status_code="InternalError"
        }


	#endregion
	
	#region Initialize
	#Specify varaibles used throughout the script and verify any prerequisites.
		$ErrorActionPreference="Stop"

		$logfile = New-zLog -console $false
		
		# name of secret containing credentials to actually do the restore cleanup work
		$secret = "SvcPD_SSR_App"
		
		$cleanupageinhours = 25

	#endregion

	#region Functions
		#Define all local script functions.

	#endregion

#endregion

#region Process
#Main script which performs all desired activities and calls functions as needed.  This section should be run once per each object passed to the script.

	Try
	{
		$creds = Get-rSecret $secret -Credential
	
		# get vcenters
		write-zlog "Getting vCenter servers from variable store"
		$vcenters = Get-rVar technologies.vmware.vcenter.name
		write-zlog "$($vcenters.count) vCenter servers gotten"
		
		# get pure arrays
		write-zlog "Getting Pure arrays"
		$purearrays = Get-rVar technologies.storage.pure.array.name
		write-zlog "Got $($purearrays.count) Pure arrays"
	
		foreach($vcenter in $vcenters)
		{
			# connect to vcenter
			write-zlog "Connecting to $vcenter"
			Connect-VIServer -Server $vcenter -Credential $creds | Out-Null
			write-zlog "Connected to $vcenter"
	
			# get SSR datastores
			write-zlog "Getting SSR datastores to be unmounted (those more than $cleanupageinhours hours old)"
			$datastores = Get-Datastore | ? {($_.Name -like "SSR-*") -and (([datetime]::ParseExact((($_.Name).substring(4,12)),"yyyyMMddHHmm",$null)).AddHours($cleanupageinhours) -lt (get-date))}
			write-zlog "$($datastores.count) SSR datastore(s) found"
	
			# if there are SSR datastores to be discarded..."
			if($datastores.count -gt 0)
			{
				foreach($datastore in $datastores)
				{
					# remove hard disk from vms
					$dsvms = Get-Vm -id (Get-View $datastore).Vm
					foreach($dsvm in $dsvms)
					{
						$dsvmview = Get-VM $dsvm | Get-View
						foreach ($VirtualSCSIController in ($dsvmview.Config.Hardware.Device | where {$_.DeviceInfo.Label -match "SCSI Controller"}))
						{
							foreach ($VirtualDiskDevice in ($dsvmview.Config.Hardware.Device | where {($_.ControllerKey -eq $VirtualSCSIController.Key) -and ($_.Backing.Datastore -eq $datastore.Id)}))
							{
								# remove the hard disk
								write-zlog "Removing $($VirtualDiskDevice.DeviceInfo.Label) from $dsvm"
								Get-HardDisk $dsvm | where {$_.Filename -eq $VirtualDiskDevice.Backing.Filename} | Remove-HardDisk -Confirm:$false
								write-zlog "$($VirtualDiskDevice.DeviceInfo.Label) removed from $dsvm"
							}
						}
					}
	
					# get hosts to which datastore is mounted
					write-zlog "Getting hosts connected to $datastore"
					$vmhosts = Get-VmHost -id $datastore.extensiondata.host.key
					write-zlog "$($vmhosts.count) hosts connected to $datastore"
	
					# unmount datastore
					foreach($vmhost in $vmhosts)
					{
						$esxcli = Get-EsxCli -VMHost $vmhost
						write-zlog "Unmounting $datastore from $vmhost"
						$esxcli.storage.filesystem.unmount($null,$datastore,$null,$null) | Out-Null
						write-zlog "$datastore unmounted from $vmhost"
					}
	
					# destroy volume
					foreach($purearray In $purearrays)
					{
						$purefa = New-PfaArray -EndPoint $purearray -Credentials $creds
						if(Get-PfaVolumes -Array $purefa | where {$_.Name -eq $datastore})
						{
							foreach($hostgroup in (Get-PfaHostGroups -array $purefa))
							{
								if(Get-PfaHostGroupVolumeConnections -array $purefa -hostgroupname $hostgroup.name | where {$_.vol -eq $datastore})
								{
									write-zlog "Removing host group connection $($hostgroup.name) from $datastore on $purearray"
									Remove-PfaHostGroupVolumeConnection -Array $purefa -VolumeName $datastore -HostGroupName $hostgroup.name | Out-Null
									write-zlog "Host group connection $($hostgroup.name) removed from $datastore on $purearray"
								}
							}
							write-zlog "Destroying Pure Storage volume $datastore on $purearray"
							Remove-PfaVolumeorSnapshot -Array $purefa -Name $datastore | Out-Null
							write-zlog "Pure Storage volume $datastore on $purearray destroyed"
						}
					}
					# rescan hosts
					foreach($vmhost in $vmhosts)
					{
						write-zlog "Rescanning host $vmhost"
						Get-VMHost $vmhost | Get-VMHostStorage -RescanAllHba -RescanVmfs| Out-Null
						write-zlog "$vmhost rescan complete"
					}
				}
			}
		}
        $Output = "Cleanup process has completed."
        $status_code="Success"
	}
	Catch
	{
		Write-zlog -message $Error[0] -eventlevel "Error"
		Send-zMail -torecips "storageadmins@rcis.com" -subject "Error" -body "Error in Self-Serve Restore cleanup script." -attachments $logfile -priority "High"
        $output = "Error processing.  Please review the logs."
        $status_code = "InternalError"
	}

#endregion

#region End
#Processes that run once and only at the end of the script.  This is for cleanup activities, reporting, and to return data to the caller.
$return=@{
status=$status_code
output=$output
content_type=$content_type
header=$additional_headers
}
return $return
#endregion
