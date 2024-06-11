Import-Module Microsoft.Graph.Devices.CorporateManagement

# App registration details
$tenantId = "tenant-id"
$clientId = "client-id"
$clientSecret = "client-secret"
$filePath = "C:\intune\ApiTest.intunewin"

# Authenticate with the Microsoft Graph API
$token = (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body @{
    client_id     = $clientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $clientSecret
    grant_type    = "client_credentials"
}).access_token

# Connect to Microsoft Graph with the token
Connect-MgGraph -AccessToken $token

# Define the parameters for the application stub to be created
$params = @{
	"@odata.type" = "#microsoft.graph.win32LobApp"
	displayName = "Test-APIApp"
	description = "Uploaded via Microsoft Graph"
	publisher = "Me"
	isFeatured = $false
	committedContentVersion = "1"
	fileName = $((Get-Item -Path $filePath).Name)
	installCommandLine = "powershell.exe -ExecutionPolicy Bypass -File install.ps1"
	uninstallCommandLine = "powershell.exe -ExecutionPolicy Bypass -File uninstall.ps1"
	applicableArchitectures = "x64"
    minimumSupportedWindowsRelease = "1607" # Windows 10 1607
	rules = @(
		@{
			"@odata.type" = "microsoft.graph.win32LobAppFileSystemRule"
			ruleType = "detection"
            path = "C:\temp"
            fileOrFolderName = "Done.txt"
			check32BitOn64System = $false
			operationType = "exists"
			operator = "notConfigured"
		}
	)
	installExperience = @{
		"@odata.type" = "microsoft.graph.win32LobAppInstallExperience"
		runAsAccount = "system"
		deviceRestartBehavior = "allow"
	}
	returnCodes = @(
		@{
			"@odata.type" = "microsoft.graph.win32LobAppReturnCode"
			returnCode = "0"
			type = "success"
		},
        @{
			"@odata.type" = "microsoft.graph.win32LobAppReturnCode"
			returnCode = "1707"
			type = "success"
		},
        @{
			"@odata.type" = "microsoft.graph.win32LobAppReturnCode"
			returnCode = "3010"
			type = "softReboot"
		},
        @{
			"@odata.type" = "microsoft.graph.win32LobAppReturnCode"
			returnCode = "1641"
			type = "hardReboot"
		},
        @{
			"@odata.type" = "microsoft.graph.win32LobAppReturnCode"
			returnCode = "1618"
			type = "retry"
		}
	)
	setupFilePath = "install.ps1"
}

# TEMP DISABLED FOR TESTING
# $createAppStub = New-MgDeviceAppManagementMobileApp -BodyParameter $params
# $appId = $createAppStub.Id

# TESTING VARIABLE - app stub creation works, for testing purposes just using a specific stub that has been created by previous step
$appId = "80eb3d7c-8180-457b-af99-df27eeab6009"

# Get the app content versions
$contentVersions = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions" -Headers @{Authorization = "Bearer $token"}

# Create a new content version if none exists, otherwise use the default content version number
if ($contentVersions.value.Count -eq 0) {
    $newContentVersion = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions" -Headers @{Authorization = "Bearer $token"} -Body (@{} | ConvertTo-Json) -ContentType "application/json"
    $mobileAppContentVersionId = $newContentVersion.id
} else {
    $mobileAppContentVersionId = $contentVersions.value[0].id
}

# Get application info from Intunewin file
$intuneWin32AppFile = [System.IO.Compression.ZipFile]::OpenRead($filePath)
$detectionXmlFile = $intuneWin32AppFile.Entries | Where-Object {$_.Name -like "Detection.xml"}
$fileStream = $detectionXmlFile.Open()
$streamReader = New-Object -TypeName "System.IO.StreamReader" -ArgumentList $fileStream -ErrorAction Stop
$detectionXmlContent = [xml]($streamReader.ReadToEnd())
$fileStream.Close()
$streamReader.Close()
$intuneWin32AppFile.Dispose()

# Create an upload session for the app content file
$uploadSessionRequest = [ordered]@{
    "@odata.type" = "#microsoft.graph.mobileAppContentFile"
	"name" = $detectionXmlContent.ApplicationInfo.FileName
    "size" = [int64]$detectionXmlContent.ApplicationInfo.UnencryptedContentSize
    "sizeEncrypted" = (Get-Item -Path $filePath).Length
    "manifest" = $null
    "isDependency" = $false
}

$uploadSession = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions/$mobileAppContentVersionId/files" -Headers @{Authorization = "Bearer $token"} -Body ($uploadSessionRequest | ConvertTo-Json) -ContentType "application/json"
$fileId = $uploadSession.id

# Get the upload URL
$uploadUrl = "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions/$mobileAppContentVersionId/files/$fileId"
$storageCheck = Invoke-RestMethod -Uri $uploadUrl -Method Get -Headers @{Authorization = "Bearer $token"}

# The Intunewin file needs to be extracted and decrypted in order to split it into chunks for uploading to Intune
# Extract the Base64-encoded encryption key and initialization vector (IV) from the XML content structure
$Base64Key = $detectionXMLContent.ApplicationInfo.EncryptionInfo.EncryptionKey
$Base64IV = $detectionXMLContent.ApplicationInfo.EncryptionInfo.InitializationVector

# Define path for extracted file, open file as a ZIP archive and retrieve the name of the Intunewin file
$ExtractedIntuneWinFile = $FilePath + ".extracted"
$ZipFile = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
$IntuneWinFileName = $DetectionXMLContent.ApplicationInfo.FileName

# Search within the archive for the Intunewin file and extract it
$ZipFile.Entries | Where-Object { $_.Name -like $IntuneWinFileName } | ForEach-Object {
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $ExtractedIntuneWinFile, $true)
}
$ZipFile.Dispose()

# Decoding the Base64-encoded encryption key and IV into byte arrays
$Key = [System.Convert]::FromBase64String($Base64Key)
$IV = [System.Convert]::FromBase64String($Base64IV)

# Define the path for the decrypted file and open a file stream to write to this
$TargetFilePath = $FilePath + ".decoded"
$TargetFilePathName = Split-Path -Path $TargetFilePath -Leaf
[System.IO.FileStream]$FileStreamTarget = [System.IO.File]::Open($TargetFilePath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

# Set up an AES decryption object using the decoded key and IV, open file stream for the extracted file, offset by 48 bytes within the file
$AES = [System.Security.Cryptography.Aes]::Create()
[System.Security.Cryptography.ICryptoTransform]$Decryptor = $AES.CreateDecryptor($Key, $IV)
[System.IO.FileStream]$FileStreamSource = [System.IO.File]::Open($ExtractedIntuneWinFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
$FileStreamSourceSeek = $FileStreamSource.Seek(48l, [System.IO.SeekOrigin]::Begin)

# Debug output
Write-Output "Encryption Key: $($Key -join ', ')"
Write-Output "IV: $($IV -join ', ')"
Write-Output "Extracted file size: $((Get-Item $ExtractedIntuneWinFile).Length)"
Write-Output "Target file path: $TargetFilePath"

# Create a cryptographic stream for decryption, read the encrypted file in chunks of 2 MB, write the decrypted data to the target file and flush the stream to ensure all data is written
[System.Security.Cryptography.CryptoStream]$CryptoStream = New-Object -TypeName System.Security.Cryptography.CryptoStream -ArgumentList @($FileStreamTarget, $Decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write) -ErrorAction Stop
$buffer = New-Object byte[](2097152)
while ($BytesRead = $FileStreamSource.Read($buffer, 0, 2097152)) {
    $CryptoStream.Write($buffer, 0, $BytesRead)
    $CryptoStream.Flush()
}

# Flush and close the streams
$CryptoStream.FlushFinalBlock()
$CryptoStream.Close()
$FileStreamTarget.Close()
$FileStreamSource.Close()

# Verify final file size
Write-Output "Decoded file size: $((Get-Item $TargetFilePath).Length)"

# Calculate and create the chunks, split up by 6 MB per chunk
$ChunkSizeInBytes = 1024l * 1024l * 6l;
$SASRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()
$FileSize = (Get-Item -Path $ExtractedIntuneWinFile).Length
$ChunkCount = [System.Math]::Ceiling($FileSize / $ChunkSizeInBytes)
$BinaryReader = New-Object -TypeName System.IO.BinaryReader([System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite))

$ChunkIDs = @()
for ($Chunk = 0; $Chunk -lt $ChunkCount; $Chunk++) {
    $ChunkID = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Chunk.ToString("0000")))
    $ChunkIDs += $ChunkID
    $Start = $Chunk * $ChunkSizeInBytes
    $Length = [System.Math]::Min($ChunkSizeInBytes, $FileSize - $Start)
    $Bytes = $BinaryReader.ReadBytes($Length)
    $CurrentChunk = $Chunk + 1

    $Uri = "{0}&comp=block&blockid={1}" -f $storageCheck.azureStorageUri, $ChunkID
    $ISOEncoding = [System.Text.Encoding]::GetEncoding("iso-8859-1")
    $EncodedBytes = $ISOEncoding.GetString($Bytes)
    $Headers = @{
        "x-ms-blob-type" = "BlockBlob"
    }
    $UploadResponse = Invoke-WebRequest $Uri -Method "Put" -Headers $Headers -Body $EncodedBytes -UseBasicParsing -ErrorAction Stop
}

# DEBUG - Show chunks
Write-Output "DEBUG - Chunk IDs below:"
Write-Output $ChunkIDs

# Finalise the chunk list and send an XML list to the storage location
$finalChunkUri = "{0}&comp=blocklist" -f $storageCheck.azureStorageUri
$XML = '<?xml version="1.0" encoding="utf-8"?><BlockList>'
foreach ($ChunkId in $ChunkIds) {
    $XML += "<Latest>$($ChunkId)</Latest>"
}
$XML += '</BlockList>'

Write-Output "DEBUG - XML List:"
Write-Output $XML

Invoke-RestMethod -Uri $finalChunkUri -Method "Put" -Body $XML -ErrorAction Stop
$BinaryReader.Close()
$BinaryReader.Dispose()

# Commit the chunks into the file at the storage URL
$Win32FileEncryptionInfo = @{
    "fileEncryptionInfo" = [ordered]@{
        "encryptionKey"        = $DetectionXMLContent.ApplicationInfo.EncryptionInfo.EncryptionKey
        "macKey"               = $DetectionXMLContent.ApplicationInfo.EncryptionInfo.macKey
        "initializationVector" = $DetectionXMLContent.ApplicationInfo.EncryptionInfo.initializationVector
        "mac"                  = $DetectionXMLContent.ApplicationInfo.EncryptionInfo.mac
        "profileIdentifier"    = "ProfileVersion1"
        "fileDigest"           = $DetectionXMLContent.ApplicationInfo.EncryptionInfo.fileDigest
        "fileDigestAlgorithm"  = $DetectionXMLContent.ApplicationInfo.EncryptionInfo.fileDigestAlgorithm
    }
} | ConvertTo-Json

Write-Output "DEBUG - Win32 File Encrpytion Info details:"
Write-Output $Win32FileEncryptionInfo

$CommitResourceUri = "{0}/commit" -f $uploadUrl, $fileId
Invoke-RestMethod -uri $CommitResourceUri -Method "POST" -Body $Win32FileEncryptionInfo -Headers @{Authorization = "Bearer $token"} -ContentType "application/json"

# Check the upload state
$CommitStatus = Invoke-RestMethod -uri $uploadUrl -Method GET -Headers @{Authorization = "Bearer $token"}
$CommitStatus

# Update the file version
$Win32AppCommitBody = [ordered]@{
    "@odata.type"             = "#microsoft.graph.win32LobApp"
    "committedContentVersion" = $fileId
} | ConvertTo-Json
$Win32AppUrl = "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/$appId"
Invoke-RestMethod -uri $Win32AppUrl -Method "PATCH" -Body $Win32AppCommitBody -Headers @{Authorization = "Bearer $token"} -ContentType "application/json"
