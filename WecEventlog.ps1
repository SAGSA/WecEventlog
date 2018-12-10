<#
.EXAMPLE
    New-EventLogProvider -ProviderName WEC-Workstations-Sysmon,WEC-DomainControllers-Sysmon,WEC-Servers-Sysmon
.EXAMPLE
    New-EventLogProvider -ProviderName WEC-DomainControllers-Test -ChannelName Test,Test1,Test2 -LogSize 32mb
.EXAMPLE
    New-EventLogProvider -ManFile c:\ManFile.man
.NOTES
    Author: SAGSA
    https://github.com/SAGSA/WecEventlog
    Requires: Powershell 2.0
#>
function New-EventLogProvider
{
[cmdletbinding()]
param(
[ValidateNotNullOrEmpty()]
[string[]]$ProviderName,
[string[]]$ChannelName,
[ValidateSet("Admin","Operational")]
$ChannelType="Operational",
[string[]]$ImportChannel=@("Application","System"),
[int64]$LogSize=10485760,
[ValidateNotNullOrEmpty()]
[ValidateScript({test-path $_})]
[string]$ManFile


)
    $NameSpaceName="CustomChannelsNamespace"
    [String]$RootFolder="$env:SystemRoot\CustomProviders"
    $BaseName="CustomProvider"
    #$CheckFileSignature=$True
    
    if (!((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)))
    {
        Write-Error "Run powershell as administrator" -ErrorAction Stop
    }
    
    
    if ($PSBoundParameters["ProviderName"] -and $PSBoundParameters["ManFile"])
    {
        Write-Error "Only one parameter is possible from ProviderName,Manfile" -ErrorAction Stop
    }
 
    $TmpRes=Join-Path -Path $RootFolder -ChildPath Tmp    
    if (!(Test-Path $TmpRes))
    {
        Write-Verbose "Create Folder $TmpRes"
        New-Item -ItemType Directory -Path $TmpRes -ErrorAction Stop | Out-Null   
    }
    if ($PSBoundParameters["ManFile"])
    {
        Write-Verbose "Copy-item $ManFile $TmpRes\$BaseName.man" 
        [xml]$ManConfigXml=Get-Content $ManFile -ErrorAction Stop
        [array]$ProviderName=$ManConfigXml.instrumentationManifest.instrumentation.events.provider | foreach {
            $_.name
        }
        if ($ProviderName.count -eq 0)
        {
            Write-Error "Incorrect man file $ManFile" -ErrorAction Stop
        }
        Copy-Item $ManFile -Destination "$TmpRes\$BaseName.man"
          
    }

    $ProviderName | foreach {
        if (Get-WinEvent -ListProvider $_ -ErrorAction SilentlyContinue)
        {
            Write-Error "Provider $_ already exists" -ErrorAction Stop
        }  
    } 
    
    $FolderName=[guid]::NewGuid()
    
    $CustomEventsDLLFullPath = $RootFolder + "\"+$FolderName+"\"+ $BaseName + ".dll"
    $TmpManFileFullPath=$TmpRes+"\$BaseName"+".man"

    if (!(Test-Path $RootFolder))
    {
        Write-Verbose "Create Folder $RootFolder"
        New-Item -ItemType Directory -Path $RootFolder -ErrorAction Stop | Out-Null   
    }
    

    #Write-Verbose $CustomEventsDLLFullPath
    function CreateManFile
    {
        [cmdletbinding()]
        param(
        [string[]]$ProviderName,
        [ValidateSet("Admin","Operational","Analytic","Debug")]
        $ChannelType="Operational",
        [string[]]$ImportChannel,
        [xml]$ManConfigXml,
        [string[]]$Channel,
        [parameter(Mandatory=$true)]
        [ValidateScript({$_ -match ":\\.+\\.+\.dll$"})]
        [string]$DllPath,
        [parameter(Mandatory=$true)]
        [ValidateScript({$_ -match ":\\.+\\.+\.man$"})]
        [string]$OutManFilePath
        )
        
        if ($PSBoundParameters["ManConfigXml"])
        {
            $ManConfigXml.instrumentationManifest.instrumentation.events.provider | foreach {
                Write-Verbose "$($_.name) Set Attribute resourceFileName $DllPath"
                $_.SetAttribute("resourceFileName",$DllPath)
                Write-Verbose "$($_.name) Set Attribute messageFileName $DllPath"
                $_.SetAttribute("messageFileName",$DllPath)
                Write-Verbose "$($_.name) Set Attribute parameterFileName $DllPath"
                $_.SetAttribute("parameterFileName",$DllPath)
            }       
            $ManConfigXml.Save($OutManFilePath)
        }
        elseif($PSBoundParameters["ProviderName"])
        {
            $ProviderName=$ProviderName | Select-Object -Unique    
            #$CustomEvents = Import-CSV $ConfigFile
            #$Providers = $CustomEvents | Select-Object -Property ProviderSymbol,ProviderName,ProviderGuid -Unique
            $XmlWriter = New-Object System.XMl.XmlTextWriter($OutManFilePath,$null)
            $xmlWriter.Formatting = "Indented"
            $xmlWriter.Indentation = "4"
            $xmlWriter.WriteStartDocument() 
            $xmlWriter.WriteStartElement("instrumentationManifest")
            $xmlWriter.WriteAttributeString("xsi:schemaLocation","http://schemas.microsoft.com/win/2004/08/events eventman.xsd")
            $xmlWriter.WriteAttributeString("xmlns","http://schemas.microsoft.com/win/2004/08/events")
            $xmlWriter.WriteAttributeString("xmlns:win","http://manifests.microsoft.com/win/2004/08/windows/events")
            $xmlWriter.WriteAttributeString("xmlns:xsi","http://www.w3.org/2001/XMLSchema-instance")
            $xmlWriter.WriteAttributeString("xmlns:xs","http://www.w3.org/2001/XMLSchema")
            $xmlWriter.WriteAttributeString("xmlns:trace","http://schemas.microsoft.com/win/2004/08/events/trace")
            $xmlWriter.WriteStartElement("instrumentation")
	        $xmlWriter.WriteStartElement("events")
    
            foreach ($Pname in $ProviderName)
            {
                $ProviderSymbol=$Pname -replace "-","_"
                if (!($PSBoundParameters['Channel']))
                {
                    $Channel=$ChannelType
                }
                $ProviderGuid="{$([guid]::NewGuid())}"
                $xmlWriter.WriteStartElement("provider")
		            $xmlWriter.WriteAttributeString("name",$PName)
		            $xmlWriter.WriteAttributeString("guid", $ProviderGuid)
		            $xmlWriter.WriteAttributeString("symbol",$ProviderSymbol)
		            $xmlWriter.WriteAttributeString("resourceFileName",$DllPath)
		            $xmlWriter.WriteAttributeString("messageFileName",$DllPath)
		            $xmlWriter.WriteAttributeString("parameterFileName",$DllPath)
		            $xmlWriter.WriteStartElement("channels")  
			        if ($PSBoundParameters["ImportChannel"])
                    {
                        $Count=0
                        $ImportChannel | foreach {
                            $Count++
                            $xmlWriter.WriteStartElement("importChannel") 
                            $xmlWriter.WriteAttributeString("name",$_)
                            $xmlWriter.WriteAttributeString("chid","C$Count")
                            $xmlWriter.WriteEndElement()     
                        }
                             
                    }
                    $Channel | foreach {
                        $xmlWriter.WriteStartElement("channel")	
                        $ChannelName=$Pname+"/$_"
                        $ChannelSymbol=($ChannelName -replace "-","_") -replace "/","_"
                        $xmlWriter.WriteAttributeString("name",$ChannelName)
			            $xmlWriter.WriteAttributeString("chid",($ChannelName).Replace(' ',''))
			            $xmlWriter.WriteAttributeString("symbol",$ChannelSymbol)
			            $xmlWriter.WriteAttributeString("type",$ChannelType)
			            $xmlWriter.WriteAttributeString("enabled","true")
                        $xmlWriter.WriteEndElement()
                    }    
                    $xmlWriter.WriteEndElement()
		        $xmlWriter.WriteEndElement()
        
            }
            $xmlWriter.WriteEndElement()
            $xmlWriter.WriteEndElement()
            $xmlWriter.WriteEndElement()

            $xmlWriter.WriteEndDocument()

            $xmlWriter.Finalize
            $xmlWriter.Flush()
            $xmlWriter.Close()
        }
        else
        {
            Write-Error "Parameter ProviderName or ManConfigXml is empty" -ErrorAction Stop
        }
        
    Write-Verbose "Man file created successfully $OutManFilePath"
    return 0
    }
    
    if ($PSBoundParameters["ProviderName"])
    {
        Write-Verbose "Create ManFile $ProviderName"
        $res=CreateManFile -ProviderName $ProviderName -ChannelType $ChannelType -DllPath $CustomEventsDLLFullPath -OutManFilePath $TmpManFileFullPath -Channel $ChannelName -ImportChannel $ImportChannel
        if ($res -ne 0)
        {
            Write-Error "Man file not created" -ErrorAction Stop
        }  
    }
    elseif($PSBoundParameters["ManFile"])
    {
        Write-Verbose "Create Provider Use ManFile $ManFile"
        $res=CreateManFile -ManConfigXml $ManConfigXml -DllPath $CustomEventsDLLFullPath -OutManFilePath $TmpManFileFullPath
        if ($res -ne 0)
        {
            Write-Error "Man file not created" -ErrorAction Stop
        }  
    }
    else
    {
        Write-Error "Parameter ProviderName or ManFile is empty" -ErrorAction Stop
    } 
    
    $Osarch="x32"
    $FrameworkFolderName="Framework"
    if (${env:ProgramFiles(x86)})
    {
        $Osarch="x64"
        $FrameworkFolderName="Framework64"
    }
    $UtilPath=$PSScriptRoot+"\util\$Osarch"
    $McFullPath=join-path $UtilPath "mc.exe" -Resolve -ErrorAction Stop
    $RcFullfPath=join-path $UtilPath "rc.exe" -Resolve -ErrorAction Stop
    $RcDllfullPath=join-path $UtilPath "rcdll.dll" -Resolve -ErrorAction Stop
    $CscFullPath= join-path $env:SystemRoot "Microsoft.NET\$FrameworkFolderName\v4.0.30319\csc.exe" -Resolve -ErrorAction Stop

    $Res=InvokeExe -ExeFile $McFullPath -Args $TmpManFileFullPath,"-h",$TmpRes,"-r",$TmpRes -CheckSignature $CheckFileSignature -ErrorAction Stop
    $Res=InvokeExe -ExeFile $McFullPath -Args "-css",$NameSpaceName,$TmpManFileFullPath,"-h",$TmpRes,"-r",$TmpRes -ErrorAction Stop
    $RcFileFullPath=Join-Path $TmpRes $($BaseName+".rc") -Resolve -ErrorAction Stop
    $Res=InvokeExe -ExeFile $RcFullfPath -Args $RcFileFullPath -CheckSignature $CheckFileSignature -ErrorAction Stop
    $Res=InvokeExe -ExeFile $CscFullPath "/win32res:$TmpRes\$BaseName.res","/unsafe","/target:library","/out:$TmpRes\$BaseName.dll","$TmpRes\$BaseName.cs" -ErrorAction Stop


    if (Test-Path "$RootFolder\$BaseName.dll")
    {
        Write-Error "file $RootFolder\$BaseName.dll already exists" -ErrorAction Stop
    }
    if (Test-Path "$RootFolder\$BaseName.man")
    {
        Write-Error "file $RootFolder\$BaseName.man already exists" -ErrorAction Stop    
    }

    Write-Verbose "New-Item -Path $RootFolder\$FolderName"
    New-Item -ItemType Directory -Path $RootFolder\$FolderName -ErrorAction Stop | Out-Null
    Write-Verbose "Copy-Item $TmpRes\$BaseName.dll $RootFolder\$FolderName"
    Copy-Item -Path "$TmpRes\$BaseName.dll" -Destination $RootFolder\$FolderName -ErrorAction Stop
    Write-Verbose "Copy-Item $TmpRes\$BaseName.man $RootFolder\$FolderName"
    Copy-Item -Path "$TmpRes\$BaseName.man" -Destination $RootFolder\$FolderName -ErrorAction Stop

    $WevtUtilFullPath=Join-Path $env:SystemRoot "system32\wevtutil.exe" -Resolve -ErrorAction Stop
    $res=InvokeExe -ExeFile $WevtUtilFullPath -Args "im","$TmpRes\$BaseName.man" -ErrorAction Stop
    Write-Verbose "Remove $TmpRes"
    Remove-Item $TmpRes -Recurse -Force
    Get-WinEvent -ListProvider $ProviderName | Select-Object -Property Name,LogLinks,MessageFilePath | foreach {
        $Provider=$_
        $Provider.Loglinks | foreach {
            $LogName=$_.Logname
            if (!($_.IsImported))
            {
                InvokeExe -ExeFile $WevtUtilFullPath -Args "sl",$LogName,"/ms:$LogSize" | Out-Null
                Get-WinEvent -ListLog $LogName | Select-Object -Property OwningProviderName,LogName,LogType,MaximumSizeInBytes,LogMode
            }
            
        }
    }
}
<#
.EXAMPLE
    Remove-EventLogProvider -ProviderName WEC-Workstations-Sysmon,WEC-DomainControllers-Sysmon,WEC-Servers-Sysmon
.EXAMPLE
    Get-WinEvent -ListProvider WEC* | Remove-EventLogProvider
.NOTES
    Author: SAGSA
    https://github.com/SAGSA/WecEventlog
    Requires: Powershell 2.0
#>
function Remove-EventLogProvider
{
[cmdletbinding()]
param(
[parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
[string[]]$ProviderName,
[switch]$Force
)

begin
{
    if (!((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)))
    {
        Write-Error "Run powershell as administrator" -ErrorAction Stop
    }
    Function RemoveProvider
    {
    param(
    [parameter(Mandatory=$true)]
    [string]$ManFile,
    [parameter(Mandatory=$true)]
    [string]$FolderPath
    )
        if (!(Test-Path $Manfile))
        {
            Write-Error "File $Manfile not found" -ErrorAction Stop
        }
        $WevtUtilFullPath=Join-Path $env:SystemRoot "system32\wevtutil.exe" -Resolve -ErrorAction Stop
        $res=InvokeExe -ExeFile $WevtUtilFullPath -Args "um",$Manfile -ErrorAction Stop
        Write-Verbose "Remove-Item -Path $FolderPath"
        Remove-Item -Path $FolderPath -Recurse -Force     
    }
    
$AllProviderInfo=Get-WinEvent -ListProvider * -ErrorAction SilentlyContinue
$RemovedProvider=@()
$ProviderNames=@()
}
Process
{   
    if ($ProviderName -ne $null)
    {
        $ProviderNames+=$ProviderName                
    }
}
End
{
    foreach($ProviderName in $ProviderNames)
    {
        if ($RemovedProvider -eq $ProviderName)
        {
            Write-Verbose "$ProviderName has been removed"
        }
        else
        {
            $ProviderInfo=$AllProviderInfo | Where-Object {$_.providername -eq $ProviderName} 
            if (!$ProviderInfo)
            {
                Write-Error "$ProviderName provider does not exist"
            }
            else
            {
                if ($ProviderInfo.MessageFilePath -ne $null)
                {
                    if ($ProviderInfo.MessageFilePath -match ".+\\(.+-.+-.+-.+-.+)\\")
                    {
                        $ManFilePath=$ProviderInfo.MessageFilePath -replace "\.dll$",".man" 
                        $FolderGuid=$matches[1]
                        $FolderFullPath=Split-Path $ProviderInfo.MessageFilePath -Parent
                        [array]$ProviderList=$AllProviderInfo | Where-Object {$_.MessageFilePath -match $FolderGuid}
                        if ($ProviderList.count -eq 1)
                        {
                            RemoveProvider -ManFile $ManFilePath -FolderPath $FolderFullPath
                            Write-Host "$ProviderName removed succesfully" -ForegroundColor Green
                        }
                        elseif($ProviderList.count -gt 1)
                        {
                            if($PSBoundParameters["Force"].ispresent)
                            {
                                RemoveProvider -ManFile $ManFilePath -FolderPath $FolderFullPath
                                Write-Host "$($ProviderList.ProviderName) removed successfully" -ForegroundColor Green
                                $RemovedProvider+=$ProviderList.ProviderName
                            } 
                            else
                            {
                                Write-Error "Multiple providers refer to a file $($ProviderInfo[0].MessageFilePath) Use parameter Force to remove $($ProviderList.ProviderName)" -ErrorAction Stop
                            }   
                        }
                        else
                        {
                            Write-Error "Impossible to delete $ProviderName"  
                        }
               
        
                    }
                    else
                    {
                        Write-Verbose "Unknown provider $ProviderName" -Verbose
                    }
                }
                else
                {
                    Write-Error "$ProviderName MessageFilePath is Null"
                }
            }
        }    
    }
    
    if ($FolderFullPath)
    {
        $RootFolder=Split-Path $FolderFullPath -Parent
        if (Test-Path $RootFolder)
        {
            if(!(Get-ChildItem $RootFolder -Force))
            {
                Write-Verbose "Remove-Item $RootFolder"
                Remove-Item $RootFolder -ErrorAction SilentlyContinue
            }
        }
    }    
}
    
}

Function New-EventlogManifest
{
    [CmdletBinding()]
    param()
    if(!(Test-Path -Path "$PSScriptRoot\util\ecmangen.exe"))
    {
        Write-Error "$PSScriptRoot\util\ecmangen.exe Not Found" -ErrorAction Stop
    }
    Copy-Item "$PSScriptRoot\util\ecmangen.exe" $env:TEMP -Force | Out-Null
    if ($CheckFileSignature)
    {
        if((Get-AuthenticodeSignature -FilePath "$env:TEMP\ecmangen.exe").Status -ne "Valid")
        {
            Write-Error "CheckSignature failed" -ErrorAction Stop
        }
    } 
    Write-Verbose "Start-Process $env:TEMP\ecmangen.exe"
    Start-Process -FilePath "$env:TEMP\ecmangen.exe"
}

function InvokeExe 
{
[cmdletbinding()]
param(
[Parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[String]$ExeFile,
[Parameter(Mandatory=$false)]
[String[]]$Args,
[Parameter(Mandatory=$false)]
[String]$Verb,
[bool]$CheckSignature=$false
)    
    $oPsi = New-Object -TypeName System.Diagnostics.ProcessStartInfo
    $oPsi.CreateNoWindow = $true
    $oPsi.UseShellExecute = $false
    $oPsi.RedirectStandardOutput = $true
    $oPsi.RedirectStandardError = $true
    $oPsi.FileName = $ExeFile
    if (! [String]::IsNullOrEmpty($Args)) 
    {
        $oPsi.Arguments = $Args
    }
    if (! [String]::IsNullOrEmpty($Verb)) 
    {
        $oPsi.Verb = $Verb
    }
    
    $oProcess = New-Object -TypeName System.Diagnostics.Process
    $oProcess.StartInfo = $oPsi

    
    $oStdOutBuilder = New-Object -TypeName System.Text.StringBuilder
    $oStdErrBuilder = New-Object -TypeName System.Text.StringBuilder

    $sScripBlock = {
        if (! [String]::IsNullOrEmpty($EventArgs.Data)) 
        {
            $Event.MessageData.AppendLine($EventArgs.Data)
        }
    }
    $oStdOutEvent = Register-ObjectEvent -InputObject $oProcess -Action $sScripBlock -EventName 'OutputDataReceived' -MessageData $oStdOutBuilder
    $oStdErrEvent = Register-ObjectEvent -InputObject $oProcess -Action $sScripBlock -EventName 'ErrorDataReceived' -MessageData $oStdErrBuilder

    Write-Verbose "$ExeFile $Args"
    if ($CheckSignature)
    {
        Write-Verbose "CheckSignature $ExeFile"
        if((Get-AuthenticodeSignature -FilePath $ExeFile).Status -ne "Valid")
        {
            Write-Error "CheckSignature failed" -ErrorAction Stop
        }
    }
    [Void]$oProcess.Start()
    $oProcess.BeginOutputReadLine()
    $oProcess.BeginErrorReadLine()
    [Void]$oProcess.WaitForExit()

    Unregister-Event -SourceIdentifier $oStdOutEvent.Name
    Unregister-Event -SourceIdentifier $oStdErrEvent.Name
    $oResult = New-Object -TypeName PSObject -Property (@{
        "ExeFile"  = $ExeFile;
        "Args"     = $Args -join " ";
        "ExitCode" = $oProcess.ExitCode;
        "StdOut"   = $oStdOutBuilder.ToString().Trim();
        "StdErr"   = $oStdErrBuilder.ToString().Trim()
    })
    if ($oResult.ExitCode -ne 0)
    {
        if (($oResult.StdErr).length -ne 0)
        {
            Write-Error "$($oResult.StdErr)"
        }
        elseif ($Res.StdOut -match "(error.+)")
        {
            Write-Error $Matches[1]
        }
        else
        {
            Write-Error "Unknown error"
        }
    
    }

return $oResult

}
