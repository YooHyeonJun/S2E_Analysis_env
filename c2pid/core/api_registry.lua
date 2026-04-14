local M = {}

local DEFAULT_META = {
    param_count = 0,
    fork = false,
    convention = "cdecl",
}

local DEFINITIONS = {
    { api = "WSAStartup", handler = "hook_wsastartup", modules = { "ws2_32.dll" }, param_count = 2, convention = "stdcall" },
    { api = "socket", handler = "hook_socket", modules = { "ws2_32.dll" }, param_count = 3, convention = "stdcall" },
    { api = "closesocket", handler = "hook_closesocket", modules = { "ws2_32.dll" }, param_count = 1, convention = "stdcall" },
    { api = "recv", handler = "hook_recv", modules = { "ws2_32.dll" }, param_count = 4, convention = "stdcall" },
    { api = "WSARecv", handler = "hook_wsarecv", modules = { "ws2_32.dll" }, param_count = 7, convention = "stdcall" },
    { api = "InternetReadFile", handler = "hook_internetreadfile", modules = { "wininet.dll" }, param_count = 4, convention = "stdcall" },
    { api = "WinHttpReadData", handler = "hook_winhttpreaddata", modules = { "winhttp.dll" }, param_count = 4, convention = "stdcall" },
    { api = "InternetOpenA", handler = "hook_internetopena", modules = { "wininet.dll" }, param_count = 5, convention = "stdcall" },
    { api = "InternetOpenW", handler = "hook_internetopenw", modules = { "wininet.dll" }, param_count = 5, convention = "stdcall" },
    { api = "InternetConnectA", handler = "hook_internetconnecta", modules = { "wininet.dll" }, param_count = 8, convention = "stdcall" },
    { api = "InternetConnectW", handler = "hook_internetconnectw", modules = { "wininet.dll" }, param_count = 8, convention = "stdcall" },
    { api = "InternetOpenUrlA", handler = "hook_internetopenurla", modules = { "wininet.dll" }, param_count = 6, convention = "stdcall" },
    { api = "InternetOpenUrlW", handler = "hook_internetopenurlw", modules = { "wininet.dll" }, param_count = 6, convention = "stdcall" },
    { api = "URLDownloadToFileA", handler = "hook_urldownloadtofilea", modules = { "urlmon.dll" }, param_count = 5, convention = "stdcall" },
    { api = "URLDownloadToFileW", handler = "hook_urldownloadtofilew", modules = { "urlmon.dll" }, param_count = 5, convention = "stdcall" },
    { api = "InternetWriteFile", handler = "hook_internetwritefile", modules = { "wininet.dll" }, param_count = 4, convention = "stdcall" },
    { api = "InternetQueryDataAvailable", handler = "hook_internetquerydataavailable", modules = { "wininet.dll" }, param_count = 4, convention = "stdcall" },
    { api = "HttpQueryInfoA", handler = "hook_httpqueryinfoa", modules = { "wininet.dll" }, param_count = 5, convention = "stdcall" },
    { api = "HttpQueryInfoW", handler = "hook_httpqueryinfow", modules = { "wininet.dll" }, param_count = 5, convention = "stdcall" },
    { api = "HttpOpenRequestA", handler = "hook_httpopenrequesta", modules = { "wininet.dll" }, param_count = 8, convention = "stdcall" },
    { api = "HttpOpenRequestW", handler = "hook_httpopenrequestw", modules = { "wininet.dll" }, param_count = 8, convention = "stdcall" },
    { api = "HttpSendRequestA", handler = "hook_httpsendrequesta", modules = { "wininet.dll" }, param_count = 5, convention = "stdcall" },
    { api = "HttpSendRequestW", handler = "hook_httpsendrequestw", modules = { "wininet.dll" }, param_count = 5, convention = "stdcall" },
    { api = "FtpOpenFileA", handler = "hook_ftpopenfilea", modules = { "wininet.dll" }, param_count = 5, convention = "stdcall" },
    { api = "FtpOpenFileW", handler = "hook_ftpopenfilew", modules = { "wininet.dll" }, param_count = 5, convention = "stdcall" },
    { api = "FtpSetCurrentDirectoryA", handler = "hook_ftpsetcurrentdirectorya", modules = { "wininet.dll" }, param_count = 2, convention = "stdcall" },
    { api = "FtpSetCurrentDirectoryW", handler = "hook_ftpsetcurrentdirectoryw", modules = { "wininet.dll" }, param_count = 2, convention = "stdcall" },
    { api = "InternetCloseHandle", handler = "hook_internetclosehandle", modules = { "wininet.dll", "winhttp.dll" }, param_count = 1, convention = "stdcall" },
    { api = "connect", handler = "hook_connect", modules = { "ws2_32.dll" }, param_count = 3, convention = "stdcall" },
    { api = "WSAConnect", handler = "hook_wsaconnect", modules = { "ws2_32.dll" }, param_count = 7, convention = "stdcall" },
    { api = "WSAAsyncSelect", handler = "hook_wsaasyncselect", modules = { "ws2_32.dll" }, param_count = 4, convention = "stdcall" },
    { api = "WSAEventSelect", handler = "hook_wsaeventselect", modules = { "ws2_32.dll" }, param_count = 3, convention = "stdcall" },
    { api = "WSAEnumNetworkEvents", handler = "hook_wsaenumnetworkevents", modules = { "ws2_32.dll" }, param_count = 3, convention = "stdcall" },
    { api = "WSAGetLastError", handler = "hook_wsagetlasterror", modules = { "ws2_32.dll" }, param_count = 0, convention = "stdcall" },
    { api = "WSASetLastError", handler = "hook_wsasetlasterror", modules = { "ws2_32.dll" }, param_count = 1, convention = "stdcall" },
    { api = "ioctlsocket", handler = "hook_ioctlsocket", modules = { "ws2_32.dll" }, param_count = 3, convention = "stdcall" },
    { api = "accept", handler = "hook_accept", modules = { "ws2_32.dll" }, param_count = 3, convention = "stdcall" },
    { api = "select", handler = "hook_select", modules = { "ws2_32.dll" }, param_count = 5, convention = "stdcall" },
    { api = "WSAPoll", handler = "hook_wsapoll", modules = { "ws2_32.dll" }, param_count = 3, convention = "stdcall" },
    { api = "WSAWaitForMultipleEvents", handler = "hook_wsawaitformultipleevents", modules = { "ws2_32.dll" }, param_count = 5, convention = "stdcall" },
    { api = "send", handler = "hook_send", modules = { "ws2_32.dll" }, param_count = 4, convention = "stdcall" },
    { api = "WSASend", handler = "hook_wsasend", modules = { "ws2_32.dll" }, param_count = 7, convention = "stdcall" },
    { api = "sendto", handler = "hook_sendto", modules = { "ws2_32.dll" }, param_count = 6, convention = "stdcall" },
    { api = "recvfrom", handler = "hook_recvfrom", modules = { "ws2_32.dll" }, param_count = 6, convention = "stdcall" },
    { api = "gethostbyname", handler = "hook_gethostbyname", modules = { "ws2_32.dll" }, param_count = 1, convention = "stdcall" },
    { api = "gethostbyaddr", handler = "hook_gethostbyaddr", modules = { "ws2_32.dll" }, param_count = 3, convention = "stdcall" },
    { api = "getaddrinfo", handler = "hook_getaddrinfo", modules = { "ws2_32.dll" }, param_count = 4, convention = "stdcall" },
    { api = "GetAddrInfoW", handler = "hook_getaddrinfow", modules = { "ws2_32.dll" }, param_count = 4, convention = "stdcall" },
    { api = "getsockopt", handler = "hook_getsockopt", modules = { "ws2_32.dll" }, param_count = 5, convention = "stdcall" },
    { api = "setsockopt", handler = "hook_setsockopt", modules = { "ws2_32.dll" }, param_count = 5, convention = "stdcall" },
    { api = "shutdown", handler = "hook_shutdown", modules = { "ws2_32.dll" }, param_count = 2, convention = "stdcall" },
    { api = "getpeername", handler = "hook_getpeername", modules = { "ws2_32.dll" }, param_count = 3, convention = "stdcall" },
    { api = "getsockname", handler = "hook_getsockname", modules = { "ws2_32.dll" }, param_count = 3, convention = "stdcall" },
    { api = "WSAIoctl", handler = "hook_wsaioctl", modules = { "ws2_32.dll" }, param_count = 9, convention = "stdcall" },
    { api = "gethostname", handler = "hook_gethostname", modules = { "ws2_32.dll" }, param_count = 2, convention = "stdcall" },
    { api = "getservbyname", handler = "hook_getservbyname", modules = { "ws2_32.dll" }, param_count = 2, convention = "stdcall" },
    { api = "inet_addr", handler = "hook_inet_addr", modules = { "ws2_32.dll" }, param_count = 1, convention = "stdcall" },
    { api = "inet_ntoa", handler = "hook_inet_ntoa", modules = { "ws2_32.dll" }, param_count = 1, convention = "stdcall" },
    { api = "htonl", handler = "hook_htonl", modules = { "ws2_32.dll" }, param_count = 1, convention = "stdcall" },
    { api = "htons", handler = "hook_htons", modules = { "ws2_32.dll" }, param_count = 1, convention = "stdcall" },
    { api = "WNetOpenEnumA", handler = "hook_wnetopenenuma", modules = { "mpr.dll" }, param_count = 5, convention = "stdcall" },
    { api = "WNetEnumResourceA", handler = "hook_wnetenumresourcea", modules = { "mpr.dll" }, param_count = 4, convention = "stdcall" },
    { api = "WNetCloseEnum", handler = "hook_wnetcloseenum", modules = { "mpr.dll" }, param_count = 1, convention = "stdcall" },
    { api = "IcmpCreateFile", handler = "hook_icmpcreatefile", modules = { "iphlpapi.dll" }, param_count = 0, convention = "stdcall" },
    { api = "IcmpSendEcho", handler = "hook_icmpsendecho", modules = { "iphlpapi.dll" }, param_count = 8, convention = "stdcall" },
    { api = "WinHttpOpen", handler = "hook_winhttpopen", modules = { "winhttp.dll" }, param_count = 5, convention = "stdcall" },
    { api = "WinHttpConnect", handler = "hook_winhttpconnect", modules = { "winhttp.dll" }, param_count = 3, convention = "stdcall" },
    { api = "WinHttpOpenRequest", handler = "hook_winhttpopenrequest", modules = { "winhttp.dll" }, param_count = 7, convention = "stdcall" },
    { api = "WinHttpSendRequest", handler = "hook_winhttpsendrequest", modules = { "winhttp.dll" }, param_count = 7, convention = "stdcall" },
    { api = "WinHttpReceiveResponse", handler = "hook_winhttpreceiveresponse", modules = { "winhttp.dll" }, param_count = 2, convention = "stdcall" },
    { api = "WinHttpQueryDataAvailable", handler = "hook_winhttpquerydataavailable", modules = { "winhttp.dll" }, param_count = 2, convention = "stdcall" },
    { api = "WinHttpCloseHandle", handler = "hook_winhttpclosehandle", modules = { "winhttp.dll" }, param_count = 1, convention = "stdcall" },
    { api = "WlanOpenHandle", handler = "hook_wlanopenhandle", modules = { "wlanapi.dll" }, param_count = 4, convention = "stdcall" },
    { api = "WlanEnumInterfaces", handler = "hook_wlanenuminterfaces", modules = { "wlanapi.dll" }, param_count = 3, convention = "stdcall" },
    { api = "WlanQueryInterface", handler = "hook_wlanqueryinterface", modules = { "wlanapi.dll" }, param_count = 7, convention = "stdcall" },
    { api = "CryptAcquireContextA", handler = "hook_cryptacquirecontexta", modules = { "advapi32.dll" }, param_count = 5, convention = "stdcall" },
    { api = "CryptAcquireContextW", handler = "hook_cryptacquirecontextw", modules = { "advapi32.dll" }, param_count = 5, convention = "stdcall" },
    { api = "CryptReleaseContext", handler = "hook_cryptreleasecontext", modules = { "advapi32.dll" }, param_count = 2, convention = "stdcall" },
    { api = "CryptGenKey", handler = "hook_cryptgenkey", modules = { "advapi32.dll" }, param_count = 4, convention = "stdcall" },
    { api = "CryptImportKey", handler = "hook_cryptimportkey", modules = { "advapi32.dll" }, param_count = 6, convention = "stdcall" },
    { api = "CryptDestroyKey", handler = "hook_cryptdestroykey", modules = { "advapi32.dll" }, param_count = 1, convention = "stdcall" },
    { api = "CryptCreateHash", handler = "hook_cryptcreatehash", modules = { "advapi32.dll" }, param_count = 5, convention = "stdcall" },
    { api = "CryptHashData", handler = "hook_crypthashdata", modules = { "advapi32.dll" }, param_count = 4, convention = "stdcall" },
    { api = "CryptDeriveKey", handler = "hook_cryptderivekey", modules = { "advapi32.dll" }, param_count = 5, convention = "stdcall" },
    { api = "CryptGetHashParam", handler = "hook_cryptgethashparam", modules = { "advapi32.dll" }, param_count = 5, convention = "stdcall" },
    { api = "CryptSetHashParam", handler = "hook_cryptsethashparam", modules = { "advapi32.dll" }, param_count = 4, convention = "stdcall" },
    { api = "CryptEncrypt", handler = "hook_cryptencrypt", modules = { "advapi32.dll" }, param_count = 7, convention = "stdcall" },
    { api = "CryptDecrypt", handler = "hook_cryptdecrypt", modules = { "advapi32.dll" }, param_count = 6, convention = "stdcall" },
    { api = "SystemFunction032", handler = "hook_systemfunction032", modules = { "advapi32.dll" }, param_count = 2, convention = "stdcall" },
    { api = "SystemFunction033", handler = "hook_systemfunction033", modules = { "advapi32.dll" }, param_count = 2, convention = "stdcall" },
    { api = "CryptProtectData", handler = "hook_cryptprotectdata", modules = { "crypt32.dll" }, param_count = 7, convention = "stdcall" },
    { api = "CryptUnprotectData", handler = "hook_cryptunprotectdata", modules = { "crypt32.dll" }, param_count = 7, convention = "stdcall" },
    { api = "BCryptOpenAlgorithmProvider", handler = "hook_bcryptopenalgorithmprovider", modules = { "bcrypt.dll" }, param_count = 4, convention = "stdcall" },
    { api = "BCryptCloseAlgorithmProvider", handler = "hook_bcryptclosealgorithmprovider", modules = { "bcrypt.dll" }, param_count = 2, convention = "stdcall" },
    { api = "BCryptSetProperty", handler = "hook_bcryptsetproperty", modules = { "bcrypt.dll" }, param_count = 5, convention = "stdcall" },
    { api = "BCryptGenerateSymmetricKey", handler = "hook_bcryptgeneratesymmetrickey", modules = { "bcrypt.dll" }, param_count = 7, convention = "stdcall" },
    { api = "BCryptImportKey", handler = "hook_bcryptimportkey", modules = { "bcrypt.dll" }, param_count = 9, convention = "stdcall" },
    { api = "BCryptCreateHash", handler = "hook_bcryptcreatehash", modules = { "bcrypt.dll" }, param_count = 7, convention = "stdcall" },
    { api = "BCryptHashData", handler = "hook_bcrypthashdata", modules = { "bcrypt.dll" }, param_count = 4, convention = "stdcall" },
    { api = "BCryptFinishHash", handler = "hook_bcryptfinishhash", modules = { "bcrypt.dll" }, param_count = 4, convention = "stdcall" },
    { api = "BCryptDestroyHash", handler = "hook_bcryptdestroyhash", modules = { "bcrypt.dll" }, param_count = 1, convention = "stdcall" },
    { api = "BCryptEncrypt", handler = "hook_bcryptencrypt", modules = { "bcrypt.dll" }, param_count = 8, convention = "stdcall" },
    { api = "BCryptDecrypt", handler = "hook_bcryptdecrypt", modules = { "bcrypt.dll" }, param_count = 8, convention = "stdcall" },
    { api = "BCryptDestroyKey", handler = "hook_bcryptdestroykey", modules = { "bcrypt.dll" }, param_count = 1, convention = "stdcall" },
    { api = "NCryptEncrypt", handler = "hook_ncryptencrypt", modules = { "ncrypt.dll" }, param_count = 7, convention = "stdcall" },
    { api = "NCryptDecrypt", handler = "hook_ncryptdecrypt", modules = { "ncrypt.dll" }, param_count = 7, convention = "stdcall" },
    { api = "NCryptImportKey", handler = "hook_ncryptimportkey", modules = { "ncrypt.dll" }, param_count = 9, convention = "stdcall" },
    { api = "NCryptFreeObject", handler = "hook_ncryptfreeobject", modules = { "ncrypt.dll" }, param_count = 1, convention = "stdcall" },
    { api = "CreateFileA", handler = "hook_createfilea", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 7, convention = "stdcall" },
    { api = "CreateFileW", handler = "hook_createfilew", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 7, convention = "stdcall" },
    { api = "ReadFile", handler = "hook_readfile", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 5, convention = "stdcall" },
    { api = "GetFileAttributesA", handler = "hook_getfileattributesa", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 1, convention = "stdcall" },
    { api = "GetFileAttributesW", handler = "hook_getfileattributesw", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 1, convention = "stdcall" },
    { api = "WriteFile", handler = "hook_writefile", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 5, convention = "stdcall" },
    { api = "CloseHandle", handler = "hook_closehandle", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 1, convention = "stdcall" },
    { api = "LoadLibraryA", handler = "hook_loadlibrarya", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 1, convention = "stdcall" },
    { api = "LoadLibraryW", handler = "hook_loadlibraryw", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 1, convention = "stdcall" },
    { api = "LoadLibraryExA", handler = "hook_loadlibraryexa", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 3, convention = "stdcall" },
    { api = "LoadLibraryExW", handler = "hook_loadlibraryexw", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 3, convention = "stdcall" },
    { api = "GetProcAddress", handler = "hook_getprocaddress", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 2, convention = "stdcall" },
    { api = "CreateMutexA", handler = "hook_createmutexa", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 3, convention = "stdcall" },
    { api = "CreateMutexW", handler = "hook_createmutexw", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 3, convention = "stdcall" },
    { api = "CreateThread", handler = "hook_createthread", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 6, convention = "stdcall" },
    { api = "CreateRemoteThread", handler = "hook_createremotethread", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 7, convention = "stdcall" },
    { api = "VirtualAllocEx", handler = "hook_virtualallocex", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 5, convention = "stdcall" },
    { api = "WriteProcessMemory", handler = "hook_writeprocessmemory", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 5, convention = "stdcall" },
    { api = "OpenProcess", handler = "hook_openprocess", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 3, convention = "stdcall" },
    { api = "QueryFullProcessImageNameA", handler = "hook_queryfullprocessimagenamea", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 4, convention = "stdcall" },
    { api = "QueryFullProcessImageNameW", handler = "hook_queryfullprocessimagenamew", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 4, convention = "stdcall" },
    { api = "CreateToolhelp32Snapshot", handler = "hook_createtoolhelp32snapshot", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 2, convention = "stdcall" },
    { api = "Process32FirstA", handler = "hook_process32firsta", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 2, convention = "stdcall" },
    { api = "Process32FirstW", handler = "hook_process32firstw", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 2, convention = "stdcall" },
    { api = "Process32NextA", handler = "hook_process32nexta", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 2, convention = "stdcall" },
    { api = "Process32NextW", handler = "hook_process32nextw", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 2, convention = "stdcall" },
    { api = "GetVersion", handler = "hook_getversion", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 0, convention = "stdcall" },
    { api = "GetVersionExA", handler = "hook_getversionexa", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 1, convention = "stdcall" },
    { api = "GetVersionExW", handler = "hook_getversionexw", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 1, convention = "stdcall" },
    { api = "GetLastError", handler = "hook_getlasterror", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 0, convention = "stdcall" },
    { api = "SetLastError", handler = "hook_setlasterror", modules = { "kernel32.dll", "kernelbase.dll" }, param_count = 1, convention = "stdcall" },
    { api = "GetKeyState", handler = "hook_getkeystate", modules = { "user32.dll" }, param_count = 1, convention = "stdcall" },
    { api = "GetAsyncKeyState", handler = "hook_getasynckeystate", modules = { "user32.dll" }, param_count = 1, convention = "stdcall" },
    { api = "GetKeyboardState", handler = "hook_getkeyboardstate", modules = { "user32.dll" }, param_count = 1, convention = "stdcall" },
    { api = "ShellExecuteA", handler = "hook_shellexecutea", modules = { "shell32.dll" }, param_count = 6, convention = "stdcall" },
    { api = "ShellExecuteW", handler = "hook_shellexecutew", modules = { "shell32.dll" }, param_count = 6, convention = "stdcall" },
    { api = "ExitProcess", handler = "hook_exitprocess", modules = { "kernel32.dll" }, param_count = 1, convention = "stdcall" },
    { api = "RtlExitUserProcess", handler = "hook_exitprocess", modules = { "ntdll.dll" }, param_count = 1, convention = "stdcall" },
    { api = "TerminateProcess", handler = "hook_terminateprocess", modules = { "kernel32.dll" }, param_count = 2, convention = "stdcall" },
    { api = "NtTerminateProcess", handler = "hook_terminateprocess", modules = { "ntdll.dll" }, param_count = 2, convention = "stdcall" },
    { api = "NtQueryInformationProcess", handler = "hook_ntqueryinformationprocess", modules = { "ntdll.dll" }, param_count = 5, convention = "stdcall" },
    { api = "RtlGetVersion", handler = "hook_rtlgetversion", modules = { "ntdll.dll" }, param_count = 1, convention = "stdcall" },
    { api = "NtMapViewOfSection", handler = "hook_ntmapviewofsection", modules = { "ntdll.dll" }, param_count = 10, convention = "stdcall" },
    { api = "strcmp", handler = "hook_strcmp", modules = { "msvcrt.dll", "ucrtbase.dll" }, param_count = 2, convention = "cdecl" },
    { api = "stricmp", handler = "hook_stricmp", modules = { "msvcrt.dll", "ucrtbase.dll" }, param_count = 2, convention = "cdecl" },
    { api = "_stricmp", handler = "hook_stricmp", modules = { "msvcrt.dll", "ucrtbase.dll" }, param_count = 2, convention = "cdecl" },
    { api = "_strcmpi", handler = "hook_stricmp", modules = { "msvcrt.dll", "ucrtbase.dll" }, param_count = 2, convention = "cdecl" },
    { api = "strncmp", handler = "hook_strncmp", modules = { "msvcrt.dll", "ucrtbase.dll" }, param_count = 3, convention = "cdecl" },
    { api = "memcmp", handler = "hook_memcmp", modules = { "msvcrt.dll", "ucrtbase.dll" }, param_count = 3, convention = "cdecl" },
    { api = "memcpy", handler = "hook_memcpy", modules = { "msvcrt.dll", "ucrtbase.dll" }, param_count = 3, convention = "cdecl" },
    { api = "memmove", handler = "hook_memmove", modules = { "msvcrt.dll", "ucrtbase.dll" }, param_count = 3, convention = "cdecl" },
    { api = "RtlMoveMemory", handler = "hook_rtlmovememory", modules = { "kernel32.dll", "kernelbase.dll", "ntdll.dll" }, param_count = 3, convention = "stdcall" },
    { api = "RtlCopyMemory", handler = "hook_rtlcopymemory", modules = { "kernel32.dll", "kernelbase.dll", "ntdll.dll" }, param_count = 3, convention = "stdcall" },
    { api = "_beginthreadex", handler = "hook_beginthreadex", modules = { "msvcrt.dll", "ucrtbase.dll" }, param_count = 6, convention = "cdecl" },
    { api = "lstrcmpA", handler = "hook_strcmp", modules = { "kernel32.dll" }, param_count = 2, convention = "stdcall" },
    { api = "lstrcmpiA", handler = "hook_strcmp", modules = { "kernel32.dll" }, param_count = 2, convention = "stdcall" },
    { api = "exit", handler = "hook_exit", modules = { "msvcrt.dll", "ucrtbase.dll" }, param_count = 1, convention = "cdecl" },
    { api = "_exit", handler = "hook_exit", modules = { "msvcrt.dll", "ucrtbase.dll" }, param_count = 1, convention = "cdecl" },
    { api = "abort", handler = "hook_abort", modules = { "msvcrt.dll", "ucrtbase.dll" }, param_count = 0, convention = "cdecl" },
}

local BY_API = {}

for _, def in ipairs(DEFINITIONS) do
    BY_API[def.api] = def
end

function M.get_hook_meta(api_name)
    local def = api_name and BY_API[api_name] or nil
    local meta = def or DEFAULT_META
    return {
        param_count = meta.param_count,
        fork = meta.fork or false,
        convention = meta.convention,
    }
end

function M.get_handler_name(api_name)
    local def = api_name and BY_API[api_name] or nil
    return def and def.handler or nil
end

function M.build_module_api_map(target_profile)
    local out = {}
    for _, def in ipairs(DEFINITIONS) do
        for _, module_name in ipairs(def.modules or {}) do
            local key = string.lower(module_name)
            local list = out[key]
            if list == nil then
                list = {}
                out[key] = list
            end
            list[#list + 1] = def.api
        end
    end
    if target_profile and target_profile.kind == "dll" then
        out[target_profile.target_dll_name_l] = target_profile.target_exports
    end
    return out
end

return M
