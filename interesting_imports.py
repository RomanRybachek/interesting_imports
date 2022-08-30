from PyQt5 import QtCore, QtGui, QtWidgets
import sys
import ida_nalt
import ida_xref
import idautils
import ida_funcs
import ida_name
import idaapi

config = {

"Processes": ['CreateToolhelp32Snapshot', 'Process32First', 'Process32FirstW', 'Process32Next', 'Process32NextW', 'WriteProcessMemory', 
            'ReadProcessMemory', 'Toolhelp32ReadProcessMemory', 'Module32First', 'Module32FirstW', 'Module32Next', 'Module32NextW', 'CreateProcessW'],

"Co": ['CoCreateInstance'],

"ftp": ['FtpCommandA', 'FtpCommandW', 'FtpCreateDirectoryA', 'FtpCreateDirectoryW', 'FtpDeleteFileA', 'FtpDeleteFileW', 'FtpFindFirstFileA', \
        'FtpFindFirstFileW', 'FtpGetCurrentDirectoryA', 'FtpGetCurrentDirectoryW', 'FtpGetFileA', 'FtpGetFileEx', 'FtpGetFileSize', 'FtpGetFileW', \
        'FtpOpenFileA', 'FtpOpenFileW', 'FtpPutFileA', 'FtpPutFileEx', 'FtpPutFileW', 'FtpRemoveDirectoryA', 'FtpRemoveDirectoryW', 'FtpRenameFileA', \
        'FtpRenameFileW', 'FtpSetCurrentDirectoryA', 'FtpSetCurrentDirectoryW'],

"Import": ['GetProcAddress', 'LoadLibraryExW', 'LoadLibraryA', 'LoadLibrary'],

"dir": ['CreateDirectoryA', 'CreateDirectoryExA', 'CreateDirectoryExW', 'CreateDirectoryW', 'GetCurrentDirectoryA', 'GetCurrentDirectoryW',\
       'GetDllDirectoryA', 'GetDllDirectoryW', 'GetSystemDirectoryA', 'GetSystemDirectoryW', 'GetSystemWindowsDirectoryA', 'GetSystemWindowsDirectoryW',\
       'GetSystemWow64DirectoryA', 'GetSystemWow64DirectoryW', 'GetVDMCurrentDirectories', 'GetWindowsDirectoryA', 'GetWindowsDirectoryW', \
       'ReadDirectoryChangesW', 'RemoveDirectoryA', 'RemoveDirectoryW', 'SetCurrentDirectoryA', 'SetCurrentDirectoryW', 'SetDllDirectoryA',\
       'SetDllDirectoryW', 'SetVDMCurrentDirectories', 'SHCreateDirectory', 'SHCreateDirectoryExA', 'SHCreateDirectoryExW'],

"service": ['ChangeServiceConfig2A', 'ChangeServiceConfig2W', 'ChangeServiceConfigA', 'ChangeServiceConfigW', 'CloseServiceHandle', \
           'ControlService', 'CreateServiceA', 'CreateServiceW', 'DeleteService', 'EnumDependentServicesA', 'EnumDependentServicesW', \
           'EnumServiceGroupW', 'EnumServicesStatusA', 'EnumServicesStatusExA', 'EnumServicesStatusExW', 'EnumServicesStatusW', \
           'GetServiceDisplayNameA', 'GetServiceDisplayNameW', 'GetServiceKeyNameA', 'GetServiceKeyNameW', 'I_ScPnPGetServiceName', \
           'I_ScSetServiceBitsA', 'I_ScSetServiceBitsW', 'LockServiceDatabase', 'OpenServiceA', 'OpenServiceW', 'PrivilegedServiceAuditAlarmA', \
           'PrivilegedServiceAuditAlarmW', 'QueryServiceConfig2A', 'QueryServiceConfig2W', 'QueryServiceConfigA', 'QueryServiceConfigW', \
           'QueryServiceLockStatusA', 'QueryServiceLockStatusW', 'QueryServiceObjectSecurity', 'QueryServiceStatus', 'QueryServiceStatusEx', \
           'RegisterServiceCtrlHandlerA', 'RegisterServiceCtrlHandlerExA', 'RegisterServiceCtrlHandlerExW', 'RegisterServiceCtrlHandlerW', \
           'SetServiceBits', 'SetServiceObjectSecurity', 'SetServiceStatus', 'StartServiceA', 'StartServiceCtrlDispatcherA', 'StartServiceCtrlDispatcherW', \
           'StartServiceW', 'UnlockServiceDatabase', 'WdmWmiServiceMain'],

"reg": ['RegCloseKey', 'RegConnectRegistryA', 'RegConnectRegistryW', 'RegCreateKeyA', 'RegCreateKeyExA', 'RegCreateKeyExW',\
        'RegCreateKeyW', 'RegDeleteKeyA', 'RegDeleteKeyW', 'RegDeleteValueA', 'RegDeleteValueW', 'RegDisablePredefinedCache', \
        'RegDisablePredefinedCacheEx', 'RegEnumKeyA', 'RegEnumKeyExA', 'RegEnumKeyExW', 'RegEnumKeyW', 'RegEnumValueA', \
        'RegEnumValueW', 'RegFlushKey', 'RegGetKeySecurity', 'RegLoadKeyA', 'RegLoadKeyW', 'RegNotifyChangeKeyValue', \
        'RegOpenCurrentUser', 'RegOpenKeyA', 'RegOpenKeyExA', 'RegOpenKeyExW', 'RegOpenKeyW', 'RegOpenUserClassesRoot', \
        'RegOverridePredefKey', 'RegQueryInfoKeyA', 'RegQueryInfoKeyW', 'RegQueryMultipleValuesA', 'RegQueryMultipleValuesW', \
        'RegQueryValueA', 'RegQueryValueExA', 'RegQueryValueExW', 'RegQueryValueW', 'RegReplaceKeyA', 'RegReplaceKeyW', \
        'RegRestoreKeyA', 'RegRestoreKeyW', 'RegSaveKeyA', 'RegSaveKeyExA', 'RegSaveKeyExW', 'RegSaveKeyW', 'RegSetKeySecurity', \
        'RegSetValueA', 'RegSetValueExA', 'RegSetValueExW', 'RegSetValueW', 'RegUnLoadKeyA', 'RegUnLoadKeyW', 'SHDeleteEmptyKeyA', \
        'SHDeleteEmptyKeyW', 'SHDeleteKeyA', 'SHDeleteKeyW', 'SHOpenRegStream2A', 'SHOpenRegStream2W', 'SHOpenRegStreamA', \
        'SHOpenRegStreamW', 'SHQueryInfoKeyA', 'SHQueryInfoKeyW', 'SHQueryValueExA', 'SHQueryValueExW', 'SHRegCloseUSKey', \
        'SHRegCreateUSKeyA', 'SHRegCreateUSKeyW', 'SHRegDeleteEmptyUSKeyA', 'SHRegDeleteEmptyUSKeyW', 'SHRegDeleteUSValueA', \
        'SHRegDeleteUSValueW', 'SHRegDuplicateHKey', 'SHRegEnumUSKeyA', 'SHRegEnumUSKeyW', 'SHRegEnumUSValueA', 'SHRegEnumUSValueW'\
       , 'SHRegGetBoolUSValueA', 'SHRegGetBoolUSValueW', 'SHRegGetPathA', 'SHRegGetPathW', 'SHRegGetUSValueA', 'SHRegGetUSValueW', \
        'SHRegGetValueA', 'SHRegGetValueW', 'SHRegOpenUSKeyA', 'SHRegOpenUSKeyW', 'SHRegQueryInfoUSKeyA', 'SHRegQueryInfoUSKeyW', \
        'SHRegQueryUSValueA', 'SHRegQueryUSValueW', 'SHRegSetPathA', 'SHRegSetPathW', 'SHRegSetUSValueA', 'SHRegSetUSValueW', \
        'SHRegWriteUSValueA', 'SHRegWriteUSValueW', 'SHDeleteOrphanKeyA', 'SHDeleteOrphanKeyW', 'SHDeleteValueA', 'SHDeleteValueW', \
        'SHEnumKeyExA', 'SHEnumKeyExW', 'SHEnumValueA', 'SHEnumValueW', 'SHGetValueA', 'SHGetValueW', 'SHOpenRegStream2A', \
        'SHOpenRegStream2W', 'SHOpenRegStreamA', 'SHOpenRegStreamW', 'SHQueryInfoKeyA', 'SHQueryInfoKeyW', 'SHQueryValueExA', \
        'SHQueryValueExW', 'SHRegCloseUSKey', 'SHRegCreateUSKeyA', 'SHRegCreateUSKeyW', 'SHRegDeleteEmptyUSKeyA', \
        'SHRegDeleteEmptyUSKeyW', 'SHRegDeleteUSValueA', 'SHRegDeleteUSValueW', 'SHRegDuplicateHKey', 'SHRegEnumUSKeyA', \
        'SHRegEnumUSKeyW', 'SHRegEnumUSValueA', 'SHRegEnumUSValueW', 'SHRegGetBoolUSValueA', 'SHRegGetBoolUSValueW', 'SHRegGetPathA', \
        'SHRegGetPathW', 'SHRegGetUSValueA', 'SHRegGetUSValueW', 'SHRegGetValueA', 'SHRegGetValueW', 'SHRegOpenUSKeyA', 'SHRegOpenUSKeyW', \
        'SHRegQueryInfoUSKeyA', 'SHRegQueryInfoUSKeyW', 'SHRegQueryUSValueA', 'SHRegQueryUSValueW', 'SHRegSetPathA', 'SHRegSetPathW', \
        'SHRegSetUSValueA', 'SHRegSetUSValueW', 'SHRegWriteUSValueA', 'SHRegWriteUSValueW'],

"Files": ['fwrite', 'FindFirstFileW', 'FindNextFileW', 'FindClose', 'CompareFileTime', 'CopyFileA', 'CopyFileExA', 'CopyFileExW', \
		'CopyFileW', 'CopyLZFile', \
        'CreateFileA', 'CreateFileMappingA', \
        'CreateFileMappingW', 'CreateFileW', 'DeleteFileA', 'DeleteFileW', 'DosDateTimeToFileTime', 'FileTimeToDosDateTime', \
        'FileTimeToLocalFileTime', 'FileTimeToLocalFileTime', 'FileTimeToSystemTime', 'FlushFileBuffers', 'FlushViewOfFile', \
        'GetCPFileNameFromRegistry', 'GetCompressedFileSizeA', 'GetCompressedFileSizeW', 'GetFileAttributesA', 'GetFileAttributesExA', \
        'GetFileAttributesExW', 'GetFileAttributesW', 'GetFileInformationByHandle', 'GetFileSize', 'GetFileSizeEx', 'GetFileTime', \
        'GetFileType', 'GetSystemTimeAsFileTime', 'GetTempFileNameA', 'GetTempFileNameW', 'LZCloseFile', 'LZCreateFileW', 'LZOpenFileA',\
        'LZOpenFileW', 'LocalFileTimeToFileTime', 'LocalFileTimeToFileTime', 'LockFile', 'LockFileEx', 'MapViewOfFile', 'MapViewOfFileEx', \
        'MoveFileA', 'MoveFileExA', 'MoveFileExW', 'MoveFileW', 'MoveFileWithProgressA', 'MoveFileWithProgressW', 'OpenDataFile', 'OpenFile', \
        'OpenFileMappingA', 'OpenFileMappingW', 'OpenProfileUserMapping', 'PrivCopyFileExW', 'PrivMoveFileIdentityW', 'ReadFile', 'ReadFileEx', \
        'ReplaceFile', 'ReplaceFileA', 'ReplaceFileW', 'SetEndOfFile', 'SetFileAttributesA', 'SetFileAttributesW', 'SetFilePointer', \
        'SetFilePointerEx', 'SetFileShortNameA', 'SetFileShortNameW', 'SetFileTime', 'SetFileValidData', 'SystemTimeToFileTime', \
        'UnlockFile', 'UnlockFileEx', 'UnmapViewOfFile', 'WriteFile', 'WriteFileEx', 'WriteFileGather', 'GetFileSecurityA', \
        'GetFileSecurityW', 'SetFileSecurityA', 'SetFileSecurityW', 'CreateFileU'],

# APIs related to Collecting information about the host OS 
"os_info": ['GetComputerNameA', 'GetComputerNameExA', 'GetComputerNameExW', 'GetComputerNameW', 'GetDiskFreeSpaceA', \
            'GetDiskFreeSpaceExA', 'GetDiskFreeSpaceExW', 'GetDiskFreeSpaceW', 'GetDriveTypeA', 'GetDriveTypeW', 'GetVersion', \
            'GetVersionExA', 'GetVersionExW', 'GetSystemInfo', 'GetSystemMetrics', 'CheckTokenMembership'],

# List of APIs related to socket
"winsock": ['FreeAddrInfoW', 'GetAddrInfoW', 'GetNameInfoW', 'WEP', 'WPUCompleteOverlappedRequest', 'WSAAccept', \
            'WSAAddressToStringA', 'WSAAddressToStringW', 'WSAAsyncGetHostByAddr', 'WSAAsyncGetHostByName', 'WSAAsyncGetProtoByName',\
            'WSAAsyncGetProtoByNumber', 'WSAAsyncGetServByName', 'WSAAsyncGetServByPort', 'WSAAsyncSelect', 'WSACancelAsyncRequest',\
            'WSACancelBlockingCall', 'WSACleanup', 'WSACloseEvent', 'WSAConnect', 'WSACreateEvent', 'WSADuplicateSocketA',\
            'WSADuplicateSocketW', 'WSAEnumNameSpaceProvidersA', 'WSAEnumNameSpaceProvidersW', 'WSAEnumNetworkEvents', 'WSAEnumProtocolsA',\
            'WSAEnumProtocolsW', 'WSAEventSelect', 'WSAGetLastError', 'WSAGetOverlappedResult', 'WSAGetQOSByName', \
            'WSAGetServiceClassInfoA', 'WSAGetServiceClassInfoW', 'WSAGetServiceClassNameByClassIdA', 'WSAGetServiceClassNameByClassIdW',\
            'WSAHtonl', 'WSAHtons', 'WSAInstallServiceClassA', 'WSAInstallServiceClassW', 'WSAIoctl', 'WSAIsBlocking', 'WSAJoinLeaf', \
            'WSALookupServiceBeginA', 'WSALookupServiceBeginW', 'WSALookupServiceEnd', 'WSALookupServiceNextA', 'WSALookupServiceNextW', \
            'WSANSPIoctl', 'WSANtohl', 'WSANtohs', 'WSAProviderConfigChange', 'WSARecv', 'WSARecvDisconnect', 'WSARecvFrom', \
            'WSARemoveServiceClass', 'WSAResetEvent', 'WSASend', 'WSASendDisconnect', 'WSASendTo', 'WSASetBlockingHook', 'WSASetEvent',\
            'WSASetLastError', 'WSASetServiceA', 'WSASetServiceW', 'WSASocketA', 'WSASocketW', 'WSAStartup', 'WSAStringToAddressA', \
            'WSAStringToAddressW', 'WSAUnhookBlockingHook', 'WSAWaitForMultipleEvents', 'WSApSetPostRoutine', 'WSCDeinstallProvider', \
            'WSCEnableNSProvider', 'WSCEnumProtocols', 'WSCGetProviderPath', 'WSCInstallNameSpace', 'WSCInstallProvider', 'WSCUnInstallNameSpace',\
            'WSCUpdateProvider', 'WSCWriteNameSpaceOrder', 'WSCWriteProviderOrder', '__WSAFDIsSet', 'accept', 'bind', 'closesocket', 'connect', \
            'freeaddrinfo', 'getaddrinfo', 'gethostbyaddr', 'gethostbyname', 'gethostname', 'getnameinfo', 'getpeername', 'getprotobyname', \
            'getprotobynumber', 'getservbyname', 'getservbyport', 'getsockname', 'getsockopt', 'htonl', 'htons', 'inet_addr', 'inet_ntoa', \
            'ioctlsocket', 'listen', 'ntohl', 'ntohs', 'recv', 'recvfrom', 'select', 'send', 'sendto', 'setsockopt', 'shutdown', 'socket'],

"WinINet": ['CreateMD5SSOHash', 'DetectAutoProxyUrl', 'DllInstall', 'ForceNexusLookup', 'ForceNexusLookupExW', 'InternetAlgIdToStringA',\
            'InternetAlgIdToStringW', 'InternetAttemptConnect', 'InternetAutodial', 'InternetAutodialCallback', 'InternetAutodialHangup',\
            'InternetCanonicalizeUrlA', 'InternetCanonicalizeUrlW', 'InternetCheckConnectionA', 'InternetCheckConnectionW', \
            'InternetClearAllPerSiteCookieDecisions', 'InternetCloseHandle', 'InternetCombineUrlA', 'InternetCombineUrlW', \
            'InternetConfirmZoneCrossing', 'InternetConfirmZoneCrossingA', 'InternetConfirmZoneCrossingW', 'InternetConnectA',\
            'InternetConnectW', 'InternetCrackUrlA', 'InternetCrackUrlW', 'InternetCreateUrlA', 'InternetCreateUrlW', 'InternetDial',\
            'InternetDialA', 'InternetDialW', 'InternetEnumPerSiteCookieDecisionA', 'InternetEnumPerSiteCookieDecisionW', 'InternetErrorDlg',\
            'InternetFindNextFileA', 'InternetFindNextFileW', 'InternetFortezzaCommand', 'InternetGetCertByURL', 'InternetGetCertByURLA',\
            'InternetGetConnectedState', 'InternetGetConnectedStateEx', 'InternetGetConnectedStateExA', 'InternetGetConnectedStateExW',\
            'InternetGetCookieA', 'InternetGetCookieExA', 'InternetGetCookieExW', 'InternetGetCookieW', 'InternetGetLastResponseInfoA', \
            'InternetGetLastResponseInfoW', 'InternetGetPerSiteCookieDecisionA', 'InternetGetPerSiteCookieDecisionW', 'InternetGoOnline',\
            'InternetGoOnlineA', 'InternetGoOnlineW', 'InternetHangUp', 'InternetInitializeAutoProxyDll', 'InternetLockRequestFile',\
            'InternetOpenA', 'InternetOpenUrlA', 'InternetOpenUrlW', 'InternetOpenW', 'InternetQueryDataAvailable', 'InternetQueryFortezzaStatus',\
            'InternetQueryOptionA', 'InternetQueryOptionW', 'InternetReadFile', 'InternetReadFileExA', 'InternetReadFileExW', \
            'InternetSecurityProtocolToStringA', 'InternetSecurityProtocolToStringW', 'InternetSetCookieA', 'InternetSetCookieExA', \
            'InternetSetCookieExW', 'InternetSetCookieW', 'InternetSetDialState', 'InternetSetDialStateA', 'InternetSetDialStateW',\
            'InternetSetFilePointer', 'InternetSetOptionA', 'InternetSetOptionExA', 'InternetSetOptionExW', 'InternetSetOptionW', \
            'InternetSetPerSiteCookieDecisionA', 'InternetSetPerSiteCookieDecisionW', 'InternetSetStatusCallback', 'InternetSetStatusCallbackA',\
            'InternetSetStatusCallbackW', 'InternetShowSecurityInfoByURL', 'InternetShowSecurityInfoByURLA', 'InternetShowSecurityInfoByURLW', \
            'InternetTimeFromSystemTime', 'InternetTimeFromSystemTimeA', 'InternetTimeFromSystemTimeW', 'InternetTimeToSystemTime',\
            'InternetTimeToSystemTimeA', 'InternetTimeToSystemTimeW', 'InternetUnlockRequestFile', 'InternetWriteFile', 'InternetWriteFileExA',\
            'InternetWriteFileExW', 'IsHostInProxyBypassList', 'ParseX509EncodedCertificateForListBoxEntry', 'PrivacyGetZonePreferenceW', \
            'PrivacySetZonePreferenceW', 'ResumeSuspendedDownload', 'ShowCertificate', 'ShowClientAuthCerts', 'ShowSecurityInfo', \
            'ShowX509EncodedCertificate','UrlZonesDetach', '_GetFileExtensionFromUrl'], 

"url": ['UrlApplySchemeA', 'UrlApplySchemeW', 'UrlCanonicalizeA', 'UrlCanonicalizeW', 'UrlCombineA', 'UrlCombineW', 'UrlCompareA', \
       'UrlCompareW', 'UrlCreateFromPathA', 'UrlCreateFromPathW', 'UrlEscapeA', 'UrlEscapeW', 'UrlGetLocationA', 'UrlGetLocationW', 'UrlGetPartA'\
      , 'UrlGetPartW', 'UrlHashA', 'UrlHashW', 'UrlIsA', 'UrlIsNoHistoryA', 'UrlIsNoHistoryW', 'UrlIsOpaqueA', 'UrlIsOpaqueW', 'UrlIsW', 'UrlUnescapeA', 'UrlUnescapeW'],

"cache": ['CommitUrlCacheEntryA', 'CommitUrlCacheEntryW', 'CreateUrlCacheContainerA', 'CreateUrlCacheContainerW', 'CreateUrlCacheEntryA',\
          'CreateUrlCacheEntryW', 'CreateUrlCacheGroup', 'DeleteIE3Cache', 'DeleteUrlCacheContainerA', 'DeleteUrlCacheContainerW', \
          'DeleteUrlCacheEntry', 'DeleteUrlCacheEntryA', 'DeleteUrlCacheEntryW', 'DeleteUrlCacheGroup', 'FindCloseUrlCache', 'FindFirstUrlCacheContainerA',\
          'FindFirstUrlCacheContainerW', 'FindFirstUrlCacheEntryA', 'FindFirstUrlCacheEntryExA', 'FindFirstUrlCacheEntryExW', 'FindFirstUrlCacheEntryW', \
          'FindFirstUrlCacheGroup', 'FindNextUrlCacheContainerA', 'FindNextUrlCacheContainerW', 'FindNextUrlCacheEntryA', 'FindNextUrlCacheEntryExA',\
          'FindNextUrlCacheEntryExW', 'FindNextUrlCacheEntryW', 'FindNextUrlCacheGroup', 'FreeUrlCacheSpaceA', 'FreeUrlCacheSpaceW', 'GetUrlCacheConfigInfoA', \
          'GetUrlCacheConfigInfoW', 'GetUrlCacheEntryInfoA', 'GetUrlCacheEntryInfoExA', 'GetUrlCacheEntryInfoExW', 'GetUrlCacheEntryInfoW', \
          'GetUrlCacheGroupAttributeA', 'GetUrlCacheGroupAttributeW', 'GetUrlCacheHeaderData', 'IncrementUrlCacheHeaderData', 'IsUrlCacheEntryExpiredA',\
          'IsUrlCacheEntryExpiredW', 'LoadUrlCacheContent', 'ReadUrlCacheEntryStream', 'RegisterUrlCacheNotification', 'RetrieveUrlCacheEntryFileA', \
          'RetrieveUrlCacheEntryFileW', 'RetrieveUrlCacheEntryStreamA', 'RetrieveUrlCacheEntryStreamW', 'RunOnceUrlCache', 'SetUrlCacheConfigInfoA',\
          'SetUrlCacheConfigInfoW', 'SetUrlCacheEntryGroup', 'SetUrlCacheEntryGroupA', 'SetUrlCacheEntryGroupW', 'SetUrlCacheEntryInfoA', 'SetUrlCacheEntryInfoW',\
          'SetUrlCacheGroupAttributeA', 'SetUrlCacheGroupAttributeW', 'SetUrlCacheHeaderData', 'UnlockUrlCacheEntryFile', 'UnlockUrlCacheEntryFileA', \
          'UnlockUrlCacheEntryFileW', 'UnlockUrlCacheEntryStream', 'UpdateUrlCacheContentPath'],

# Mutex
"mutex": ['CreateMutexA', 'CreateMutexW', 'OpenMutexA', 'OpenMutexW', 'ReleaseMutex'],

# Pipe 
"pipe": ['CallNamedPipeA', 'CallNamedPipeW', 'ConnectNamedPipe', 'CreateNamedPipeA', 'CreateNamedPipeW', 'CreatePipe', 'DisconnectNamedPipe',\
         'GetNamedPipeHandleStateA', 'GetNamedPipeHandleStateW', 'GetNamedPipeInfo', 'PeekNamedPipe', 'SetNamedPipeHandleState', 'TransactNamedPipe',\
         'WaitNamedPipeA', 'WaitNamedPipeW'],

# List of APIs related to HTTP from WinINet
"http": ['HttpAddRequestHeadersA', 'HttpAddRequestHeadersW', 'HttpCheckDavCompliance', 'HttpEndRequestA', 'HttpEndRequestW',\
         'HttpOpenRequestA', 'HttpOpenRequestW', 'HttpQueryInfoA', 'HttpQueryInfoW', 'HttpSendRequestA', 'HttpSendRequestExA', \
         'HttpSendRequestExW', 'HttpSendRequestW' ], 

# List of APIs related to hashing files
"hash": ['CryptCreateHash', 'CryptDestroyHash', 'CryptDuplicateHash', 'CryptGetHashParam', 'CryptHashData', 'CryptHashSessionKey', \
        'CryptSetHashParam', 'CryptSignHashA', 'CryptSignHashW', 'FreeEncryptionCertificateHashList'],

# List of APIs related to Cryptograpy files
"crypt": ['CryptAcquireContextA', 'CryptAcquireContextW', 'CryptContextAddRef', 'CryptDecrypt', 'CryptDeriveKey', 'CryptDestroyKey', \
         'CryptDuplicateKey', 'CryptEncrypt', 'CryptEnumProviderTypesA', 'CryptEnumProviderTypesW', 'CryptEnumProvidersA', 'CryptEnumProvidersW'\
        , 'CryptExportKey', 'CryptGenKey', 'CryptGenRandom', 'CryptGetDefaultProviderA', 'CryptGetDefaultProviderW', 'CryptGetKeyParam', \
         'CryptGetProvParam', 'CryptGetUserKey', 'CryptImportKey', 'CryptReleaseContext', 'CryptSetKeyParam', 'CryptSetProvParam', \
         'CryptSetProviderA', 'CryptSetProviderExA', 'CryptSetProviderExW', 'CryptSetProviderW', 'CryptVerifySignatureA', 'CryptVerifySignatureW', \
         'DecryptFileA', 'DecryptFileW', 'EncryptFileA', 'EncryptFileW', 'EncryptedFileKeyInfo', 'EncryptionDisable', 'WriteEncryptedFileRaw', \
         'OpenEncryptedFileRawA', 'OpenEncryptedFileRawW', 'DuplicateEncryptionInfoFile', 'SetUserFileEncryptionKey', 'ReadEncryptedFileRaw', \
         'RemoveUsersFromEncryptedFile', 'FileEncryptionStatusA', 'FileEncryptionStatusW', 'FreeEncryptedFileKeyInfo', 'CloseEncryptedFileRaw', \
         'AddUsersToEncryptedFile', 'QueryRecoveryAgentsOnEncryptedFile', 'QueryUsersOnEncryptedFile', 'ChainWlxLogoffEvent', 'CryptAcquireContextU', \
         'CryptBinaryToStringA', 'CryptBinaryToStringW', 'CryptCloseAsyncHandle', 'CryptCreateAsyncHandle', 'CryptDecodeMessage', 'CryptDecodeObject', \
         'CryptDecodeObjectEx', 'CryptDecryptAndVerifyMessageSignature', 'CryptDecryptMessage', 'CryptEncodeObject', 'CryptEncodeObjectEx', \
         'CryptEncryptMessage', 'CryptEnumKeyIdentifierProperties', 'CryptEnumOIDFunction', 'CryptEnumOIDInfo', 'CryptEnumProvidersU', 'CryptExportPKCS8', \
         'CryptExportPublicKeyInfo', 'CryptExportPublicKeyInfoEx', 'CryptFindLocalizedName', 'CryptFindOIDInfo', 'CryptFormatObject', \
         'CryptFreeOIDFunctionAddress', 'CryptGetAsyncParam', 'CryptGetDefaultOIDDllList', 'CryptGetDefaultOIDFunctionAddress', \
         'CryptGetKeyIdentifierProperty', 'CryptGetMessageCertificates', 'CryptGetMessageSignerCount', 'CryptGetOIDFunctionAddress', \
         'CryptGetOIDFunctionValue', 'CryptHashCertificate', 'CryptHashMessage', 'CryptHashPublicKeyInfo', 'CryptHashToBeSigned', \
         'CryptImportPKCS8', 'CryptImportPublicKeyInfo', 'CryptImportPublicKeyInfoEx', 'CryptInitOIDFunctionSet', 'CryptInstallDefaultContext', \
         'CryptInstallOIDFunctionAddress', 'CryptLoadSip', 'CryptMemAlloc', 'CryptMemFree', 'CryptMemRealloc', 'CryptMsgCalculateEncodedLength', \
         'CryptMsgClose', 'CryptMsgControl', 'CryptMsgCountersign', 'CryptMsgCountersignEncoded', 'CryptMsgDuplicate', 'CryptMsgEncodeAndSignCTL', \
         'CryptMsgGetAndVerifySigner', 'CryptMsgGetParam', 'CryptMsgOpenToDecode', 'CryptMsgOpenToEncode', 'CryptMsgSignCTL', 'CryptMsgUpdate', \
         'CryptMsgVerifyCountersignatureEncoded', 'CryptMsgVerifyCountersignatureEncodedEx', 'CryptProtectData', 'CryptQueryObject', \
         'CryptRegisterDefaultOIDFunction', 'CryptRegisterOIDFunction', 'CryptRegisterOIDInfo', 'CryptSIPAddProvider', \
         'CryptSIPCreateIndirectData', 'CryptSIPGetSignedDataMsg', 'CryptSIPLoad', 'CryptSIPPutSignedDataMsg', 'CryptSIPRemoveProvider', \
         'CryptSIPRemoveSignedDataMsg', 'CryptSIPRetrieveSubjectGuid', 'CryptSIPRetrieveSubjectGuidForCatalogFile', 'CryptSIPVerifyIndirectData', \
         'CryptSetAsyncParam', 'CryptSetKeyIdentifierProperty', 'CryptSetOIDFunctionValue', 'CryptSetProviderU', 'CryptSignAndEncodeCertificate', \
         'CryptSignAndEncryptMessage', 'CryptSignCertificate', 'CryptSignHashU', 'CryptSignMessage', 'CryptSignMessageWithKey', \
         'CryptStringToBinaryA', 'CryptStringToBinaryW', 'CryptUninstallDefaultContext', 'CryptUnprotectData', 'CryptUnregisterDefaultOIDFunction', \
         'CryptUnregisterOIDFunction', 'CryptUnregisterOIDInfo', 'CryptVerifyCertificateSignature', 'CryptVerifyCertificateSignatureEx', \
         'CryptVerifyDetachedMessageHash', 'CryptVerifyDetachedMessageSignature', 'CryptVerifyMessageHash', 'CryptVerifyMessageSignature', \
         'CryptVerifyMessageSignatureWithKey', 'CryptVerifySignatureU', 'I_CertProtectFunction', 'I_CertSrvProtectFunction', 'I_CertSyncStore', \
         'I_CertUpdateStore', 'I_CryptAddRefLruEntry', 'I_CryptAddSmartCardCertToStore', 'I_CryptAllocTls', 'I_CryptCreateLruCache', \
         'I_CryptCreateLruEntry', 'I_CryptDetachTls', 'I_CryptDisableLruOfEntries', 'I_CryptEnableLruOfEntries', 'I_CryptEnumMatchingLruEntries', \
         'I_CryptFindLruEntry', 'I_CryptFindLruEntryData', 'I_CryptFindSmartCardCertInStore', 'I_CryptFlushLruCache', 'I_CryptFreeLruCache', \
         'I_CryptFreeTls', 'I_CryptGetAsn1Decoder', 'I_CryptGetAsn1Encoder', 'I_CryptGetDefaultCryptProv', 'I_CryptGetDefaultCryptProvForEncrypt', \
         'I_CryptGetFileVersion', 'I_CryptGetLruEntryData', 'I_CryptGetLruEntryIdentifier', 'I_CryptGetOssGlobal', 'I_CryptGetTls', 'I_CryptInsertLruEntry', \
         'I_CryptInstallAsn1Module', 'I_CryptInstallOssGlobal', 'I_CryptReadTrustedPublisherDWORDValueFromRegistry', 'I_CryptRegisterSmartCardStore', \
         'I_CryptReleaseLruEntry', 'I_CryptRemoveLruEntry', 'I_CryptSetTls', 'I_CryptTouchLruEntry', 'I_CryptUninstallAsn1Module', \
         'I_CryptUninstallOssGlobal', 'I_CryptUnregisterSmartCardStore', 'I_CryptWalkAllLruCacheEntries'],

# List of APIs related to hashing files
"cert": ['CertAddCRLContextToStore', 'CertAddCRLLinkToStore', 'CertAddCTLContextToStore', 'CertAddCTLLinkToStore', \
        'CertAddCertificateContextToStore', 'CertAddCertificateLinkToStore', 'CertAddEncodedCRLToStore', 'CertAddEncodedCertificateToStore', \
        'CertAddEncodedCertificateToSystemStoreA', 'CertAddEncodedCertificateToSystemStoreW', 'CertAddEnhancedKeyUsageIdentifier', \
        'CertAddSerializedElementToStore', 'CertAddStoreToCollection', 'CertAlgIdToOID', 'CertCloseStore', 'CertCompareCertificate', \
        'CertCompareCertificateName', 'CertCompareIntegerBlob', 'CertComparePublicKeyInfo', 'CertControlStore', 'CertCreateCTLContext', \
        'CertCreateCTLEntryFromCertificateContextProperties', 'CertCreateCertificateChainEngine', 'CertCreateCertificateContext', 'CertCreateContext',\
        'CertCreateSelfSignCertificate', 'CertDeleteCTLFromStore', 'CertDeleteCertificateFromStore', 'CertDuplicateCTLContext', \
        'CertDuplicateCertificateChain', 'CertDuplicateCertificateContext', 'CertDuplicateStore', 'CertEnumCRLContextProperties', \
        'CertEnumCRLsInStore', 'CertEnumCTLContextProperties', 'CertEnumCTLsInStore', 'CertEnumCertificateContextProperties', \
        'CertEnumCertificatesInStore', 'CertEnumPhysicalStore', 'CertEnumSubjectInSortedCTL', 'CertEnumSystemStore', \
        'CertEnumSystemStoreLocation', 'CertFindAttribute', 'CertFindCRLInStore', 'CertFindCertificateInCRL', 'CertFindCertificateInStore',\
        'CertFindChainInStore', 'CertFindExtension', 'CertFindRDNAttr', 'CertFindSubjectInCTL', 'CertFindSubjectInSortedCTL', \
        'CertFreeCRLContext', 'CertFreeCertificateChain', 'CertFreeCertificateChainEngine', 'CertFreeCertificateContext', 'CertGetCRLContextProperty', \
        'CertGetCRLFromStore', 'CertGetCTLContextProperty', 'CertGetCertificateChain', 'CertGetCertificateContextProperty', 'CertGetEnhancedKeyUsage', \
        'CertGetIssuerCertificateFromStore', 'CertGetNameStringA', 'CertGetNameStringW', 'CertGetPublicKeyLength', 'CertGetStoreProperty', \
        'CertGetSubjectCertificateFromStore', 'CertGetValidUsages', 'CertIsRDNAttrsInCertificateName', 'CertIsValidCRLForCertificate', \
        'CertNameToStrA', 'CertNameToStrW', 'CertOIDToAlgId', 'CertOpenStore', 'CertOpenSystemStoreA', 'CertOpenSystemStoreW', 'CertRDNValueToStrA',\
        'CertRDNValueToStrW', 'CertRegisterPhysicalStore', 'CertRegisterSystemStore', 'CertRemoveEnhancedKeyUsageIdentifier', \
        'CertRemoveStoreFromCollection', 'CertResyncCertificateChainEngine', 'CertSaveStore', 'CertSerializeCRLStoreElement', \
        'CertSerializeCertificateStoreElement', 'CertSetCRLContextProperty', 'CertSetCertificateContextPropertiesFromCTLEntry', \
        'CertSetCertificateContextProperty', 'CertSetEnhancedKeyUsage', 'CertSetStoreProperty', 'CertStrToNameA', 'CertStrToNameW', \
        'CertUnregisterPhysicalStore', 'CertUnregisterSystemStore', 'CertVerifyCRLRevocation', 'CertVerifyCRLTimeValidity', \
        'CertVerifyCTLUsage', 'CertVerifyCertificateChainPolicy', 'CertVerifyCertificateChainPolicy', 'CertVerifyRevocation', \
        'CertVerifySubjectCertificateContext','CertVerifyTimeValidity', 'CertVerifyValidityNesting', 'CloseCertPerformanceData', \
        'CollectCertPerformanceData', 'CryptAcquireCertificatePrivateKey', 'CryptFindCertificateKeyProvInfo', 'CryptGetMessageCertificates', \
        'CryptHashCertificate', 'CryptSignAndEncodeCertificate', 'CryptSignCertificate', 'CryptVerifyCertificateSignature', \
        'CryptVerifyCertificateSignatureEx', 'I_CertProtectFunction', 'I_CertSrvProtectFunction', 'I_CertSyncStore', 'I_CertUpdateStore', \
        'I_CryptAddSmartCardCertToStore', 'I_CryptFindSmartCardCertInStore', 'OpenCertPerformanceData', 'PFXExportCertStore', 'PFXExportCertStoreEx', 'PFXImportCertStore'], 

# Possible Hook or Injection functions
"virtual": ['VirtualAlloc', 'VirtualAllocEx', 'VirtualBufferExceptionHandler', 'VirtualFree', 'VirtualFreeEx', 'VirtualLock', 
           'VirtualProtect', 'VirtualProtectEx', 'VirtualQuery', 'VirtualQueryEx', 'VirtualUnlock'],

"critical_section": ['DeleteCriticalSection', 'EnterCriticalSection', 'InitializeCriticalSection', 
                     'InitializeCriticalSectionAndSpinCount', 'LeaveCriticalSection', 'SetCriticalSectionSpinCount', 'TryEnterCriticalSection'],
}

class import_obj:
    def __init__(self, name):
        self.name = name
        self.xrefs = []
        self.num_of_xrefs = 0
    def __str__(self):
        return self.name

class groups_obj:
    def __init__(self):
        self.groups = config 
        for k in self.groups.keys():
            for i in range(len(self.groups[k])):
                self.groups[k][i] = import_obj(self.groups[k][i])

    def num_of_group_xrefs(self, group_name):
        g = self.groups[group_name]
        num = 0
        for i in g:
            num += i.num_of_xrefs
        return num

    def g_names(self):
        return self.groups.keys()

    def get_imp_list(self, group_name):
        return self.groups[group_name]

    def get_groups(self):
        return self.groups.keys()

    def get_import(self, imp_name):
        for g in self.g_names():
            for i in self.get_imp_list(g):
                if i.name == imp_name:
                    return i
        return None
    
    def clear(self):
        for g in self.get_groups():
            for i in self.get_imp_list(g):
                i.xrefs.clear()
                i.num_of_xrefs = 0
        pass

g_obj = groups_obj()


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(634, 806)
        self.gridLayout = QtWidgets.QGridLayout(Form)
        self.gridLayout.setObjectName("gridLayout")
        self.stackedWidget = QtWidgets.QStackedWidget(Form)
        self.stackedWidget.setStyleSheet("background-color: rgb(182, 182, 182);")
        self.stackedWidget.setObjectName("stackedWidget")
        self.groups = QtWidgets.QWidget()
        self.groups.setObjectName("groups")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.groups)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.listWidget_groups = QtWidgets.QListWidget(self.groups)
        self.listWidget_groups.setStyleSheet("background-color: rgb(112, 112, 112);")
        self.listWidget_groups.setObjectName("listWidget")
        self.horizontalLayout.addWidget(self.listWidget_groups)
        self.stackedWidget.addWidget(self.groups)
        self.imports = QtWidgets.QWidget()
        self.imports.setObjectName("imports")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.imports)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.listWidget_imports = QtWidgets.QListWidget(self.imports)
        self.listWidget_imports.setStyleSheet("background-color: rgb(112, 112, 112);")
        self.listWidget_imports.setObjectName("listWidget_2")
        self.horizontalLayout_2.addWidget(self.listWidget_imports)
        self.stackedWidget.addWidget(self.imports)
        self.xrefs = QtWidgets.QWidget()
        self.xrefs.setObjectName("xrefs")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.xrefs)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")

        self.tableWidget = QtWidgets.QTableWidget(self.xrefs)
        self.tableWidget.setStyleSheet("background-color: rgb(112, 112, 112);")
        self.tableWidget.setObjectName("tableWidget_3")
        self.tableWidget.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)

        self.horizontalLayout_3.addWidget(self.tableWidget)
        self.stackedWidget.addWidget(self.xrefs)
        self.gridLayout.addWidget(self.stackedWidget, 0, 0, 1, 2)
        self.backButton = QtWidgets.QPushButton(Form)
        self.backButton.setObjectName("backButton")
        self.gridLayout.addWidget(self.backButton, 1, 0, 1, 1)
        self.refreshButton = QtWidgets.QPushButton(Form)
        self.refreshButton.setObjectName("refreshButton")
        self.gridLayout.addWidget(self.refreshButton, 1, 1, 1, 1)

        self.retranslateUi(Form)
        self.stackedWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(Form)

#------------- my code -----------------------
        self.backButton.clicked.connect(self.to_prev_page)
        self.listWidget_groups.itemDoubleClicked.connect(self.show_imports)
        self.listWidget_imports.itemDoubleClicked.connect(self.show_xrefs)
        self.refreshButton.clicked.connect(refresh_xrefs)
        self.tableWidget.itemDoubleClicked.connect(self.go_to_addr_in_ida)

    def go_to_addr_in_ida(self):
        addr = self.tableWidget.selectedItems()[0].text()
        if addr[:2] == '0x':
            idaapi.jumpto(int(addr[2:], 16))
        else:
            idaapi.jumpto(ida_name.get_name_ea(idaapi.BADADDR, addr))

    def to_prev_page(self):
        i = self.stackedWidget.currentIndex()
        self.stackedWidget.setCurrentIndex(i - 1)

    def show_imports(self):
        self.stackedWidget.setCurrentIndex(1)
        self.listWidget_imports.clear()
        this_item_text = self.listWidget_groups.selectedItems()[0].text().split()[0]
        imports = g_obj.groups[this_item_text]
        for i in imports:
            number_of_xrefs = i.num_of_xrefs
            if  number_of_xrefs > 0:
                self.listWidget_imports.addItem("{0:<50}{1}".format(i.name, str(number_of_xrefs)))

    def show_xrefs(self):
        self.stackedWidget.setCurrentIndex(2)
        # self.listWidget_xrefs.clear()
        self.tableWidget.clear()
        imp_name = self.listWidget_imports.selectedItems()[0].text().split()[0]

        xrefs_rows = g_obj.get_import(imp_name).xrefs

        self.tableWidget.setColumnCount(2)
        self.tableWidget.setRowCount(len(xrefs_rows))
        row_counter = 0
        header = self.tableWidget.horizontalHeader()       
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        self.tableWidget.setHorizontalHeaderLabels(['Function', 'Address'])

        for xref in xrefs_rows:
            self.tableWidget.setItem(row_counter, 0, QtWidgets.QTableWidgetItem(xref[0]))
            # self.tableWidget.item(row_counter, 0).setFlags(QtCore.Qt.ItemIsEnabled)
            self.tableWidget.setItem(row_counter, 1, QtWidgets.QTableWidgetItem(xref[1]))
            # self.tableWidget.item(row_counter, 1).setFlags(QtCore.Qt.ItemIsEnabled)
            row_counter += 1
    
    def show_groups(self):
        self.stackedWidget.setCurrentIndex(0)

        for i in g_obj.g_names():
            num_group_xrefs = g_obj.num_of_group_xrefs(i)
            if num_group_xrefs > 0:
                new_item = QtWidgets.QListWidgetItem()
                new_item.setText("{0:<50}{1}".format(i, str(num_group_xrefs)))
                self.listWidget_groups.addItem(new_item)

#---------------------------------------------

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Interesting imports plugin"))
        self.backButton.setText(_translate("Form", "<- back"))
        self.refreshButton.setText(_translate("Form", "refresh names"))




def refresh_xrefs():
    nimps = ida_nalt.get_import_module_qty()
    g_obj.clear()
    for i in range(nimps):

        def imp_cb(ea, imp_name, ordinal):
            imp_obj = g_obj.get_import(imp_name)

            if imp_obj != None:
                current_xref = ida_xref.get_first_cref_to(ea)

                while (current_xref != idaapi.BADADDR):
                    imp_obj.xrefs.append([ida_funcs.get_func_name(current_xref), "0x%x" % current_xref])
                    imp_obj.num_of_xrefs += 1
                    current_xref = ida_xref.get_next_cref_to(ea, current_xref)

            return True

        ida_nalt.enum_import_names(i, imp_cb)
        if ui.stackedWidget.currentIndex() == 2:
            ui.tableWidget.clear()
            ui.show_xrefs()
        elif ui.stackedWidget.currentIndex() == 1:
            ui.listWidget_imports.clear()
            ui.show_imports()
        elif ui.stackedWidget.currentIndex() == 0:
            ui.listWidget_groups.clear()
            ui.show_groups()

Form = QtWidgets.QWidget()
ui = Ui_Form()
ui.setupUi(Form)

import idaapi

class myplugin_t(idaapi.plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = "This plugin shows the most interesting imports"
    help = ""
    wanted_name = "Interesting imports"
    wanted_hotkey = "Ctrl+Shift+I"

    def init(self):
        # idaapi.msg("init() called!\n")
        return idaapi.PLUGIN_OK
    def run(self, arg):
        Form.show()
        ui.stackedWidget.setCurrentIndex(0)
        refresh_xrefs()
        # idaapi.msg("run() called with %d!\n" % arg)
    def term(self):
        # idaapi.msg("term() called!\n")
        pass

def PLUGIN_ENTRY():
    return myplugin_t()



