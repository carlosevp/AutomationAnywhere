#region v1 Authentication
function Get-AAToken {
    <#
        .Synopsis
            Returns a JWT token from AA Control Room in a Header format.

        .DESCRIPTION
            Returns a JWT token from AA Control Room in a Header format.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Credential
            Credential object saved with Get-Credential. If domain user, must use DOMAIN\\username with \\ to escape special characters.

         .PARAMETER ApyKey
            API key to be used instead of a password. 
        

        .EXAMPLE
           $header=Get-AAToken -CR https://mycr.domain.tld -Credential MyCredentialAsset
    #>
    [CmdletBinding()]
    param (
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [pscredential]$Credential=$MyCred,

           [Parameter(Mandatory=$false)]
           [string]$UserOverride=$UserOverride,

           [Parameter(Mandatory=$false)]
           [string]$APIKey=$APIKey
    )

    [uri]$uri="$($CR)/v1/authentication"

    if ($APIKey){$body = @{"username"="$($Credential.username)";"apiKey"="$APIKey"}} 
    else {
    $pwd=[PSCredential]::new(0, $Credential.password).GetNetworkCredential().Password
    #We have to add an additional backslash to the domain user as an escape character as required by AA
    $username=$Credential.username.Split("\")[0]+"\\"+$Credential.username.Split("\")[1]
    $body = @{"username"="$username";"password"="$pwd"}
        }
    if ($UserOverride){$body = @{"username"="$($UserOverride)";"password"="$pwd"}} 
    Try{
        $token=Invoke-RestMethod -Method Post -Uri $uri -Body ($body|ConvertTo-Json)  -ContentType "application/json"
        $header=@{"X-Authorization"=$token.token}
        $pwd=$null
        $body=$null
        return $header
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }

}

function Remove-AAToken {
    <#
        .Synopsis
            Logout from AA Control Room.

        .DESCRIPTION
            Logout from AA Control Room.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
         .PARAMETER HeaderToken
            JWT token acquired with Get-AAToken to perform the logout. 
        

        .EXAMPLE
           $header=Remove-AAToken -CR https://mycr.domain.tld -Token $HeaderToken
    #>
    [CmdletBinding()]
    param (
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$HeaderToken=$HeaderToken
    )

    [uri]$uri="$($CR)/v1/authentication/logout"

    Try{
        $logout=Invoke-RestMethod -Method Post -Uri $uri -Header $HeaderToken -ContentType "application/json" -Body "{}"
        return $true
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }

}

#endregion

#region v1 Audit

function Get-AAAuditMessages {
    <#
        .Synopsis
            Returns AA License details.

        .DESCRIPTION
           Returns AA License details.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Header
            Header retrieved with Get-AAToken with proper token.
        
        .EXAMPLE
           Get-AAAuditMessages -CR https://mycr.domain.tld -Header (Get-AAToken)
    #>
    [CmdletBinding()]
    param (
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$Header=$Header,

           [Parameter(Mandatory=$False)]
           [ValidateSet('Yesterday','Today','SinceYesterday','ThisWeek','Last30Days','OneYear')] 
           [String]$Shortcut
    )

# Shortcut logic . . . .
Switch ($Shortcut) {
    "Yesterday"      {
       $Begindate = $(Get-Date).AddDays(-1).ToString('yyyy-MM-dd') + 'T' + ([datetime]"00:00:00").ToUniversalTime().ToString("HH:mm:ss.fffK")
       $EndDate   = $((Get-Date).ToString('yyyy-MM-dd')) + 'T' + ([datetime]"23:59:59").ToUniversalTime().ToString('HH:mm:ss.fffK')
    }
    "Today"          {
       $Begindate = $(Get-Date).ToString('yyyy-MM-dd') + 'T' + ([datetime]"00:00:00").ToUniversalTime().ToString('HH:mm:ss.fffK')
       $EndDate   = $((Get-Date).ToString('yyyy-MM-dd')) + 'T' + $((Get-Date).ToUniversalTime().ToString('HH:mm:ss.fffK'))
    }
    "SinceYesterday" {
       $Begindate = $(Get-Date).AddDays(-1).ToString('yyyy-MM-dd') + 'T' + ([datetime]"00:00:00").ToUniversalTime().ToString('HH:mm:ss.fffK')
       $EndDate   = $((Get-Date).ToString('yyyy-MM-dd')) + 'T' + $((Get-Date).ToUniversalTime().ToString('HH:mm:ss.fffK'))
    }
    "ThisWeek" {
       $BeginDate = "$((Get-date).AddDays(-[int](Get-Date).dayofweek+1).ToString('yyyy-MM-dd'))"  + 'T' + ([datetime]"00:00:00").ToUniversalTime().ToString('HH:mm:ss.fffK')
       $EndDate   = $((Get-Date).ToString('yyyy-MM-dd')) + 'T' + $((Get-Date).ToUniversalTime().ToString('HH:mm:ss.fffK'))
    }
    "Last30Days" {
       $BeginDate = "$((Get-date).AddDays(-30).ToString('yyyy-MM-dd'))" + 'T' + ([datetime]"00:00:00").ToUniversalTime().ToString('HH:mm:ss.fffK')
       $EndDate   = $((Get-Date).ToString('yyyy-MM-dd')) + 'T' + $((Get-Date).ToUniversalTime().ToString('HH:mm:ss.fffK'))
    }
    "OneYear" {
       $BeginDate = "$((Get-date).AddDays(-365).ToString('yyyy-MM-dd'))" + 'T' + ([datetime]"00:00:00").ToUniversalTime().ToString('HH:mm:ss.fffK')
       $EndDate   = $((Get-Date).ToString('yyyy-MM-dd')) + 'T' + $((Get-Date).ToUniversalTime().ToString('HH:mm:ss.fffK'))
    }
    DEFAULT {
             If (!$BeginDate -and !$EndDate) {
               $tmpstr = "$((get-date).AddDays(-365).ToShortDateString())"
               $Daterange = Get-DateRange -Title "<ESCAPE> To Abort, Hold <SHIFT> to select multiple days" -Displaymode 2 -SQLFormat -MinDate $tmpstr -MaxDate $((Get-Date).ToShortDateString())
               If (!$Daterange) {write-warning 'Search aborted by [ESCAPE] key'; Return}
               $BeginDate = ([DateTime]$Global:StartDate).ToString('yyyy-MM-dd') + 'T' + ([datetime]"00:00:00").ToUniversalTime().ToString('HH:mm:ss.fffK')
               $EndDate   = ([DateTime]$Global:EndDate).ToString('yyyy-MM-dd 23:59:59')
               $EndDate   = ([DateTime]$EndDate).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffK')
             } Else {
               if (!$BeginDate -or !$EndDate) {write-warning 'If you specify dates, you have to specify both -StartDate and -EndDate';Return}
               $BeginDate = ([DateTime]$BeginDate).ToString('yyyy-MM-dd 00:00:00')
               $BeginDate = ([DateTime]$BeginDate).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffK')
               $EndDate   = ([DateTime]$EndDate).ToString('yyyy-MM-dd 23:59:59')
               $EndDate   = ([DateTime]$EndDate).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffK')
             }
            }
  }


    $jsonBase = @{}
    $filter = @{}
    $page= @{"length"="1000";"Offset"="0";}
    #$sort=@{"field"="createdOn";"direction"="desc"}
    $sort=@(
    @{
        field="createdOn"
        direction="desc"
    }
    )
    $filter=@{}
    $Operands = @(
        @{
            operator="gt"
            field="createdOn"
            value="$($BeginDate)"
        })
    $Operands+=@{operator='lt';field='createdOn';value="$($EndDate)"}
   # $operands1=@{"operator"="gt";"field"="createdOn";"value"="$($BeginDate)"} 
    #$filter.Add("operands",$operands1)
    #$operands2=$operands1+=@{"operator"="lt";"field"="createdOn";"value"="$($EndDate)"}
    $filter.Add("operands",$($operands))
    $filter.Add("operator","and")
    $jsonBase.Add("sort",$sort)
    $jsonBase.Add("filter",$filter)
    $jsonBase.Add("page",$page)
    $jsonbase=$jsonBase | ConvertTo-Json -Depth 10


    #Get-Date -UFormat '+%Y-%m-%dT%H:%M:%S.000Z' to get to AAs Unix-style formatting
    #(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffK")

    Try{
        [uri]$uri="$($CR)/v1/audit/messages/list"
        $AuditMessages=Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Headers $header  -Body ($jsonBase) #"{}"
        return $AuditMessages.list
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }
}

#endregion

#region v2 License
function Get-AALicense {
    <#
        .Synopsis
            Returns AA License details.

        .DESCRIPTION
           Returns AA License details.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Header
            Header retrieved with Get-AAToken with proper token.
        
        .EXAMPLE
           Get-AALicense -CR https://mycr.domain.tld -Header (Get-AAToken)
    #>
    [CmdletBinding()]
    param (
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$Header=$Header
    )
    Try{
        [uri]$uri="$($CR)/v2/license/details"
        $Licenses=Invoke-RestMethod -Method Get -Uri $uri -ContentType "application/json" -Headers $header
        return $Licenses
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }
}
function Get-AALicenseDetails {
    <#
        .Synopsis
            Returns AA License details.

        .DESCRIPTION
           Returns AA License details.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Header
            Header retrieved with Get-AAToken with proper token.
        
        .EXAMPLE
           Get-AALicenseDetails -CR https://mycr.domain.tld -Header (Get-AAToken)
    #>
    [CmdletBinding()]
    param (
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$Header=$Header
    )
    Try{
        [uri]$uri="$($CR)/v2/license/product/list"
        $LicenseDetails=Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Headers $header  -Body "{}"
        return $LicenseDetails
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }
}
#endregion
#region v2 BotInsight
function Get-AABotInsightRunData {
    <#
        .Synopsis
            Returns AA BotInsight Run Data.

        .DESCRIPTION
            Returns AA BotInsight Run Data.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Header
            Header retrieved with Get-AAToken with proper token.
        
        .PARAMETER fromDate
            From Date to search - as a string in (yyyy-mm-ddThh:mm:ss) format.

        .PARAMETER toDate
            To Date to search - as a string in (yyyy-mm-ddThh:mm:ss) format.

        .PARAMETER Limit
            Limit how many records to return.

        .PARAMETER PageNo
            page Numbers to return.

        .EXAMPLE
           Get-AABotInsightRunData -CR https://mycr.domain.tld -Header (Get-AAToken)
    #>
    [CmdletBinding()]
    param (
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$Header=$Header,

           [Parameter(Mandatory=$false)]
           [String]$fromDate,

           [Parameter(Mandatory=$false)]
           [String]$toDate,

           [Parameter(Mandatory=$false)]
           [String]$Limit,

           [Parameter(Mandatory=$false)]
           [String]$pageNo,

           [Parameter(Mandatory=$False)]
           [ValidateSet('Yesterday','Today','SinceYesterday','ThisWeek','Last30Days','OneYear')] 
           [String]$Shortcut
    )

# Shortcut logic . . . .
Switch ($Shortcut) {
    "Yesterday"      {
       $fromDate = $(Get-Date).AddDays(-1).ToString('yyyy-MM-dd') + 'T' + ([datetime]"00:00:00").ToUniversalTime().ToString("HH:mm:ss")
       $toDate   = $((Get-Date).AddDays(-1).ToString('yyyy-MM-dd')) + 'T' + ([datetime]"23:59:59").ToUniversalTime().ToString('HH:mm:ss')
    }
    "Today"          {
       $fromDate = $(Get-Date).ToString('yyyy-MM-dd') + 'T' + ([datetime]"00:00:00").ToUniversalTime().ToString('HH:mm:ss')
       $toDate   = $((Get-Date).ToString('yyyy-MM-dd')) + 'T' + $((Get-Date).ToUniversalTime().ToString('HH:mm:ss'))
    }
    "SinceYesterday" {
       $fromDate = $(Get-Date).AddDays(-1).ToString('yyyy-MM-dd') + 'T' + ([datetime]"00:00:00").ToUniversalTime().ToString('HH:mm:ss')
       $toDate   = $((Get-Date).ToString('yyyy-MM-dd')) + 'T' + $((Get-Date).ToUniversalTime().ToString('HH:mm:ss'))
    }
    "ThisWeek" {
       $fromDate = "$((Get-date).AddDays(-[int](Get-Date).dayofweek+1).ToString('yyyy-MM-dd'))"  + 'T' + ([datetime]"00:00:00").ToUniversalTime().ToString('HH:mm:ss')
       $toDate   = $((Get-Date).ToString('yyyy-MM-dd')) + 'T' + $((Get-Date).ToUniversalTime().ToString('HH:mm:ss'))
    }
    "Last30Days" {
       $fromDate = "$((Get-date).AddDays(-30).ToString('yyyy-MM-dd'))" + 'T' + ([datetime]"00:00:00").ToUniversalTime().ToString('HH:mm:ss')
       $toDate   = $((Get-Date).ToString('yyyy-MM-dd')) + 'T' + $((Get-Date).ToUniversalTime().ToString('HH:mm:ss'))
    }
    "OneYear" {
       $fromDate = "$((Get-date).AddDays(-365).ToString('yyyy-MM-dd'))" + 'T' + ([datetime]"00:00:00").ToUniversalTime().ToString('HH:mm:ss')
       $toDate   = $((Get-Date).ToString('yyyy-MM-dd')) + 'T' + $((Get-Date).ToUniversalTime().ToString('HH:mm:ss'))
    }
    DEFAULT {
             If (!$BeginDate -and !$toDate) {
               $tmpstr = "$((get-date).AddDays(-365).ToShortDateString())"
               $Daterange = Get-DateRange -Title "<ESCAPE> To Abort, Hold <SHIFT> to select multiple days" -Displaymode 2 -SQLFormat -MinDate $tmpstr -MaxDate $((Get-Date).ToShortDateString())
               If (!$Daterange) {write-warning 'Search aborted by [ESCAPE] key'; Return}
               $fromDate = ([DateTime]$Global:fromDate).ToString('yyyy-MM-dd') + 'T' + ([datetime]"00:00:00").ToUniversalTime().ToString('HH:mm:ss')
               $toDate   = ([DateTime]$Global:toDate).ToString('yyyy-MM-dd 23:59:59')
               $toDate   = ([DateTime]$toDate).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
             } Else {
               if (!$BeginDate -or !$toDate) {write-warning 'If you specify dates, you have to specify both -fromDate and -toDate';Return}
               $fromDate = ([DateTime]$BeginDate).ToString('yyyy-MM-dd 00:00:00')
               $fromDate = ([DateTime]$BeginDate).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
               $toDate   = ([DateTime]$toDate).ToString('yyyy-MM-dd 23:59:59')
               $EndDate   = ([DateTime]$EndDate).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
             }
            }
  }

  #Write-Output "From: $($fromdate) and to: $($toDate)"
  #pause
    [uri]$uri="$($CR)/v2/botinsight/data/api/getbotrundata?"
    if ($fromDate) {$uri="$($uri)&fromdate=$($fromDate)"}
    if ($toDate) {$uri="$($uri)&todate=$($toDate)"}
    if ($Limit) {$uri="$($uri)&limit=$($Limit)"}
    if ($pageNo) {$uri="$($uri)&pageno=$($pageNo)"}
    #write-output  [uri]$uri
    #pause
    Try{    
        $Insights=Invoke-RestMethod -Method Get -Uri $uri -ContentType "application/json" -Headers $header
        return $Insights.botRunDataList
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }
}
function Get-AABusinessTaskLogData {
    <#
        .Synopsis
            Returns AA Business Task Log Data. MUST BE member of the "AAE_Bot Insight Admin" group.

        .DESCRIPTION
            Returns AA Business Task Log Data. MUST BE member of the "AAE_Bot Insight Admin" group.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Header
            Header retrieved with Get-AAToken with proper token.

        .PARAMETER botName
            Bot name to search.
                
        .PARAMETER fromDate
            From Date to search - as a string in (yyyy-mm-ddThh:mm:ss) format.

        .PARAMETER toDate
            To Date to search - as a string in (yyyy-mm-ddThh:mm:ss) format.

        .PARAMETER Limit
            Limit how many records to return.

        .PARAMETER PageNo
            page Numbers to return.
        
        .EXAMPLE
           Get-AABusinessTaskLogData  -CR https://mycr.domain.tld -Header (Get-AAToken) -botName 'MyBot' 
    #>
    [CmdletBinding()]
    param (
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$Header=$Header,

           [Parameter(Mandatory=$false)]
           [String]$botName,

           [Parameter(Mandatory=$false)]
           [String]$fromDate,

           [Parameter(Mandatory=$false)]
           [String]$toDate,

           [Parameter(Mandatory=$false)]
           [String]$Limit,

           [Parameter(Mandatory=$false)]
           [String]$pageNo
    )

    [uri]$uri="$($CR)/v2/botinsight/data/api/gettasklogdata"
    if ($botName) {$uri="$($uri)?botname=$($botname)"}
    if ($fromDate) {$uri="$($uri)&fromdate=$($fromDate)"}
    if ($toDate) {$uri="$($uri)&todate=$($toDate)"}
    if ($Limit) {$uri="$($uri)&limit=$($Limit)"}
    if ($pageNo) {$uri="$($uri)&pageno=$($pageNo)"}
    Try{
        $TaskLogData=Invoke-RestMethod -Method Get -Uri $uri -ContentType "application/json" -Headers $header  -Body "{}"
        return $TaskLogData
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }
}
#endregion

#region v1 Devices
function Get-AARunAsUsers {
    <#
        .Synopsis
            Returns AA RunAsUsers Data.

        .DESCRIPTION
            Returns AA RunAsUsers Data.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Header
            Header retrieved with Get-AAToken with proper token.
        
        .EXAMPLE
           Get-AARunAsUsers -CR https://mycr.domain.tld -Header (Get-AAToken)
    #>
    [CmdletBinding()]
    param (
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$Header=$Header
    )

    Try{
        [uri]$uri="$($CR)/v1/devices/runasusers/list"
        $RunList=Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Headers $header  -Body "{}"
        return $RunList.list
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }
}

#endregion

#region v3 Workload Management
function Get-AAWorkItemModels {
    <#
        .Synopsis
            Returns AA Work Item models.

        .DESCRIPTION
           Returns AA Work Item models.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Header
            Header retrieved with Get-AAToken with proper token.
        
        .EXAMPLE
           Get-AAWorkItemModels  -CR https://mycr.domain.tld -Header (Get-AAToken)
    #>
    [CmdletBinding()]
    param (
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$Header=$Header
    )
    Try{
        [uri]$uri="$($CR)/v3/wlm/workitemmodels/list"
        $WorkItemModels=Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Headers $header  -Body "{}" 
        return $WorkItemModels.list
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }
}

function Get-AAAutomations {
    <#
        .Synopsis
            Returns AA Work Item models.

        .DESCRIPTION
           Returns AA Work Item models.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Header
            Header retrieved with Get-AAToken with proper token.
        
        .EXAMPLE
           Get-AAAutomations  -CR https://mycr.domain.tld -Header (Get-AAToken)
    #>
    [CmdletBinding()]
    param (
        
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$Header=$Header
    )
    Try{
        [uri]$uri="$($CR)/v3/wlm/automations/list"
        $Automations=Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Headers $header  -Body "{}" 
        return $Automations.list
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }
}
#endregion

#region v3 Bot Deploy API

function Start-AAAutomation {
    <#
        .Synopsis
            Starts the execution of a AA Automation on a given bot Runner.

        .DESCRIPTION
           Starts the execution of a AA Automation on a given bot Runner.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Header
            Header retrieved with Get-AAToken with proper token.
        
        .EXAMPLE
           Start-AAAutomation -CR https://mycr.domain.tld -Header (Get-AAToken) -botID 123 -RunnerID 456
    #>
    [CmdletBinding()]
    param (
        
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$Header=$Header,

           [Parameter(Mandatory=$true)]
           [Hashtable]$AutomationFileID,

           [Parameter(Mandatory=$true)]
           [Hashtable]$RunnerID
    )

    $body = @{"fileId"="$($AutomationFileID)";"runAsUserIds"="$($RunnerID)"}

    Try{
        [uri]$uri="$($CR)/v3/automations/deploy"
        $DeploymentID=Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Headers $header  -Body ($body|ConvertTo-Json)  
        return $DeploymentID
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }
}


#endregion

#region v2 Repository
function Get-AAFileList {
    <#
        .Synopsis
            Returns AA Files.

        .DESCRIPTION
           Returns AA Files.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Header
            Header retrieved with Get-AAToken with proper token.
        
        .EXAMPLE
           Get-AAAutomations  -CR https://mycr.domain.tld -Header (Get-AAToken)
    #>
    [CmdletBinding()]
    param (
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$Header=$Header
    )
    Try{
        [uri]$uri="$($CR)/v2/repository/file/list"
        $FileList=Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Headers $header  -Body "{}" 
        return $FileList.list
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }
}

#endregion
#region v1 User Management
function Get-AAUser {
    <#
        .Synopsis
            Returns AA User details.

        .DESCRIPTION
           Returns AA User details.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Header
            Header retrieved with Get-AAToken with proper token.
        
        .EXAMPLE
           Get-User -CR https://mycr.domain.tld -Header (Get-AAToken)
    #>
    [CmdletBinding()]
    param (
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$Header=$Header
    )
    Try{
        [uri]$uri="$($CR)/v1/usermanagement/users/list"
        $Users=Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Headers $header -Body "{}" 
        return $Users.list
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }
}

function Get-AAUserRole {
    <#
        .Synopsis
            Returns AA User role details.

        .DESCRIPTION
           Returns AA User role details.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Header
            Header retrieved with Get-AAToken with proper token.
        
        .EXAMPLE
           Get-UserRole-CR https://mycr.domain.tld -Header (Get-AAToken)
    #>
    [CmdletBinding()]
    param (
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$Header=$Header
    )
    Try{
        [uri]$uri="$($CR)/v1/usermanagement/roles/list"
        $UserRoles=Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Headers $header -Body "{}" 
        return $UserRoles.list
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }
}

function New-AAUser {
    <#
        .Synopsis
            Creates a user in AA.

        .DESCRIPTION
           Creates a user in AA.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Header
            Header retrieved with Get-AAToken with proper token.

        .PARAMETER Roles
            Role ID to add the new user to.

        .PARAMETER Domain
            Active Directory Domain name.

        .PARAMETER Email
            Users e-mail address.

        .PARAMETER enableAutoLogin
            Enable auto login.

        .PARAMETER Username
            Username.

        .PARAMETER firstName
            First Name.

        .PARAMETER lastName
            Last Name.

        .PARAMETER Description
            Description.

        .PARAMETER Disabled
            User is disabled? True/False switch.

        .PARAMETER Password
            Initial Password (only for local users).

        .PARAMETER licenseFeatures
            License Features.
        
        .EXAMPLE
           New-AAUser -CR https://mycr.domain.tld -Header (Get-AAToken) 
    #>
    [CmdletBinding()]
    param (
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$Header=$Header,

           [Parameter(Mandatory=$true)]
           [Integer]$Roles,

           [Parameter(Mandatory=$false)]
           [String]$Domain,
        
           [Parameter(Mandatory=$true)]
           [String]$Email,

           [Parameter(Mandatory=$false)]
           [Switch]$enableAutoLogin=$false,

           [Parameter(Mandatory=$true)]
           [Hashtable]$username,

           [Parameter(Mandatory=$true)]
           [String]$firstName,

           [Parameter(Mandatory=$true)]
           [String]$lastName,

           [Parameter(Mandatory=$true)]
           [String]$description,

           [Parameter(Mandatory=$false)]
           [Switch]$disabled=$false,

           [Parameter(Mandatory=$false)]
           [SecureString]$password,

           [Parameter(Mandatory=$true)]
           [String]$licenseFeatures

           )

    $body = @{"roles"="$($roles)"
            "domain"="$($Domain)"
            "email"="$($Email)"
            "enableAutoLogin"="$($enableAutoLogin)"
            "username"="$($username)"
            "firstName"="$($firstName)"
            "lastName"="$($lastName)"
            "description"="$($description)"
            "disabled"="$($disabled)"
            "licenseFeatures"="$($licenseFeatures)"}
## Still need to add password to the hash above. ##

    Try{
        [uri]$uri="$($CR)/v1/usermanagement/users"
        $Users=Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Headers $header -Body  ($body|ConvertTo-Json) 
        return $true
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }
}

#endregion

#region v2 Bot Execution Orchestrator
function Get-AABotExectionList {
    <#
        .Synopsis
            Returns AA User role details.

        .DESCRIPTION
           Returns AA User role details.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Header
            Header retrieved with Get-AAToken with proper token.
        
        .EXAMPLE
           Get-BotExectionList -CR https://mycr.domain.tld -Header (Get-AAToken)
    #>
    [CmdletBinding()]
    param (
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$Header=$Header
    )
    Try{
        [uri]$uri="$($CR)/v2/activity/list"
        $BotExectionList=Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Headers $header -Body "{}" 
        return $BotExectionList.list
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }
}

function Get-AABotDeviceList {
    <#
        .Synopsis
            Returns AA User role details.

        .DESCRIPTION
           Returns AA User role details.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Header
            Header retrieved with Get-AAToken with proper token.
        
        .EXAMPLE
           Get-AABotDeviceList -CR https://mycr.domain.tld -Header (Get-AAToken)
    #>
    [CmdletBinding()]
    param (
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$Header=$Header
    )
    Try{
        [uri]$uri="$($CR)/v2/devices/list"
        $BotExectionList=Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Headers $header -Body "{}" 
        return $BotExectionList.list
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }
}

#endregion

#region v2 Devices
function Get-AADevicePoolList {
    <#
        .Synopsis
            Returns AA User role details.

        .DESCRIPTION
           Returns AA User role details.

        .PARAMETER CR
            URL for Control Room including http/https as needed. If https, valid cert chain must exist.
        
        .PARAMETER Header
            Header retrieved with Get-AAToken with proper token.
        
        .EXAMPLE
           Get-AADevicePoolList-CR https://mycr.domain.tld -Header (Get-AAToken)
    #>
    [CmdletBinding()]
    param (
           [Parameter(Mandatory=$false)]
           [string]$CR=$CR,

           [Parameter(Mandatory=$false)]
           [Hashtable]$Header=$Header
    )
    Try{
        [uri]$uri="$($CR)/v2/devices/pools/list"
        $DevicePoolList=Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Headers $header -Body "{}" 
        return $DevicePoolList.list
    } Catch{
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__) "
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Warning -Message "Details: $_"
    }
}

#endregion