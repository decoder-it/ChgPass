#include <stdio.h>
#include <ntstatus.h>
#include "ms-samr.h"
#include <sddl.h>
#include <dsparse.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <wincrypt.h>
#include <ctype.h>

#include <dsgetdc.h>
#include <WinBase.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Ntdsapi.lib")
#pragma comment(lib, "netapi32.lib") 
#pragma warning(disable : 4996)
#define MAXIMUM_ALLOWED 0x02000000
#define RtlEncryptNtOwfPwdWithNtOwfPwd SystemFunction014
#define RtlEncryptNtOwfPwdWithIndex			SystemFunction026
#define RtlGetUserSessionKeyClient			SystemFunction028
#define RtlGetUserSessionKeyServer			SystemFunction029
#define RtlGetUserSessionKeyClientBinding	SystemFunction034
#define RtlEncryptNtOwfPwdWithUserKey		SystemFunction022
#define RtlGetUserSessionKeyClientBinding	SystemFunction034
#define RtlEncryptLmOwfPwdWithLmOwfPwd		SystemFunction012
NTSTATUS WINAPI RtlEncryptNtOwfPwdWithIndex(IN LPCBYTE NtOwfPassword, IN LPDWORD Index, OUT LPBYTE EncryptedNtOwfPassword);
NTSTATUS WINAPI RtlGetUserSessionKeyClient(IN PVOID RpcContextHandle, OUT LPBYTE UserSessionKey);
NTSTATUS WINAPI RtlGetUserSessionKeyServer(IN PVOID RpcContextHandle OPTIONAL, OUT LPBYTE UserSessionKey);
NTSTATUS WINAPI RtlGetUserSessionKeyClientBinding(IN PVOID RpcBindingHandle, OUT HANDLE* RedirHandle, OUT LPBYTE UserSessionKey);
NTSTATUS WINAPI RtlEncryptNtOwfPwdWithUserKey(IN LPCBYTE NtOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE EncryptedNtOwfPassword);
NTSTATUS WINAPI RtlGetUserSessionKeyClientBinding(IN PVOID RpcBindingHandle, OUT HANDLE* RedirHandle, OUT LPBYTE UserSessionKey);
NTSTATUS WINAPI RtlEncryptLmOwfPwdWithLmOwfPwd(IN LPCBYTE DataLmOwfPassword, IN LPCBYTE KeyLmOwfPassword, OUT LPBYTE EncryptedLmOwfPassword);
NTSTATUS WINAPI RtlEncryptNtOwfPwdWithNtOwfPwd(IN LPCBYTE DataNtOwfPassword, IN LPCBYTE KeyNtOwfPassword, OUT LPBYTE EncryptedNtOwfPassword);
#define SAM_SERVER_CONNECT 0x00000001
#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define SAM_SERVER_CONNECT 0x00000001
#define SAM_SERVER_ENUMERATE_DOMAINS 0x00000010
#define SAM_SERVER_LOOKUP_DOMAIN 0x00000020
#define DOMAIN_LOOKUP 0x00000200

#define USER_CHANGE_PASSWORD 0x00000040

#define STATUS_WRONG_PASSWORD 0xC000006A
#define STATUS_PASSWORD_RESTRICTION 0xC000006C
#define STATUS_MORE_ENTRIES 0x00000105L
NTSTATUS status = STATUS_DATA_ERROR;

unsigned char oldNT[16];
unsigned char newNT[16];
unsigned char newLM[16];
char DCName[256];
char DCIp[65];

char DomainName[256];

void RemoveBackslashes(char* str) 
{
	char* src = str, * dst = str;

	while (*src) {
		if (*src != '\\') {  
			*dst = *src;
			dst++;
		}
		src++;
	}
	*dst = '\0';  
}
BOOL GetCurrentDomainController() 
{
	PDOMAIN_CONTROLLER_INFOA pDcInfo = NULL;
	DWORD dwError;

	// Step 1: Call DsGetDcName to get the current domain controller
	dwError = DsGetDcNameA(
		NULL,       // ComputerName (NULL for local computer)
		NULL,       // DomainName (NULL for current domain)
		NULL,       // DomainGuid
		NULL,       // SiteGuid
		0,          // Flags
		&pDcInfo    // Pointer to DOMAIN_CONTROLLER_INFO structure
	);

	// Step 2: Check if the function succeeded
	if (dwError == ERROR_SUCCESS) {
		strcpy_s(DCName, 255, pDcInfo->DomainControllerName);
		strcpy_s(DomainName, 255, pDcInfo->DomainName);
		RemoveBackslashes(DCName);
		printf("[*] Domain Controller Name: %s\n", DCName);
		printf("[*] Domain Name: %s\n", DomainName);
		printf("[*] Domain Controller Address: %s\n", pDcInfo->DomainControllerAddress);

		
		/*
		if (pDcInfo->Flags & DS_PDC_REQUIRED) {
			printf("[i] This domain controller is the Primary Domain Controller (PDC).\n");
		}
		if (pDcInfo->Flags & DS_DS_FLAG) {
			printf("[i]  This domain controller is running Active Directory.\n");
		}
		if (pDcInfo->Flags & DS_GC_SERVER_REQUIRED) {
			printf("This domain controller is a Global Catalog Server.\n");
		}*/
	}
	else {
		printf("[-] DsGetDcName failed. Error: %lu\n", dwError);
		return 0;
	}
	free(pDcInfo);
	return 1;
}
void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		}
		else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s \n", ascii);
			}
			else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}



void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
	return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
	free(p);
}

handle_t __RPC_USER PSAMPR_SERVER_NAME_bind()
{

	handle_t hBinding = NULL;
	RPC_CSTR pszStringBinding;
	RPC_STATUS status;
	RPC_CSTR ProtSeq = "ncacn_np";
	RPC_CSTR Endpoint ="\\pipe\\samr";

	status = RpcStringBindingComposeA(NULL,
		ProtSeq,
		DCName,
		Endpoint,
		NULL,
		&(RPC_CSTR)pszStringBinding);
	if (status)
	{
	   printf("[-] RpcStringBindingCompose  0x%x\n", status);
		return NULL;
	}

	
	status = RpcBindingFromStringBindingA(pszStringBinding,
		&hBinding);
	if (status)
	{
		printf("[-] RpcBindingFromStringBinding  0x%x\n", status);
	}
	status = RpcStringFreeA(&pszStringBinding);
	if (status)
	{
		printf("[-] RpcStringFree  0x%x-%d\n", status, GetLastError());
	}

	return hBinding;
}
long toBigEndian(int value) 
{
	return ((value & 0x000000FF) << 24) |  
		((value & 0x0000FF00) << 8) |  
		((value & 0x00FF0000) >> 8) |  
		((value & 0xFF000000) >> 24);  
}
BOOL CalculateNTLMHash(LPCSTR password, BYTE hash[16]) 
{
	HCRYPTPROV hCryptProv = 0; 
	HCRYPTHASH hHash = 0;      
	BOOL result = FALSE;

	
	int passwordLength = (int)strlen(password); 
	int unicodeLength = MultiByteToWideChar(CP_ACP, 0, password, passwordLength, NULL, 0);
	if (unicodeLength == 0) {
		printf("[-] CalculateNTLMHash: Error converting password to UTF-16LE. Error: %lu\n", GetLastError());
		return FALSE;
	}

	WCHAR* unicodePassword = (WCHAR*)malloc(unicodeLength * sizeof(WCHAR));
	if (unicodePassword == NULL) {
		printf("[-] CalculateNTLMHash: Memory allocation failed.\n");
		return FALSE;
	}

	if (MultiByteToWideChar(CP_ACP, 0, password, passwordLength, unicodePassword, unicodeLength) == 0) {
		printf("[-] CalculateNTLMHash: Error converting password to UTF-16LE. Error: %lu\n", GetLastError());
		free(unicodePassword);
		return FALSE;
	}

	
	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		printf("[-] CalculateNTLMHash: CryptAcquireContext failed. Error: %lu\n", GetLastError());
		free(unicodePassword);
		return FALSE;
	}

	
	if (!CryptCreateHash(hCryptProv, CALG_MD4, 0, 0, &hHash)) {
		printf("[-] CalculateNTLMHash: CryptCreateHash failed. Error: %lu\n", GetLastError());
		CryptReleaseContext(hCryptProv, 0);
		free(unicodePassword);
		return FALSE;
	}

	
	if (!CryptHashData(hHash, (BYTE*)unicodePassword, unicodeLength * sizeof(WCHAR), 0)) {
		printf("[-] CalculateNTLMHash: CryptHashData failed. Error: %lu\n", GetLastError());
		CryptDestroyHash(hHash);
		CryptReleaseContext(hCryptProv, 0);
		free(unicodePassword);
		return FALSE;
	}

	
	DWORD hashLen = 16; 
	if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
		result = TRUE; 
	}
	else {
		printf("[-] CalculateNTLMHash: CryptGetHashParam failed. Error: %lu\n", GetLastError());
	}

	
	CryptDestroyHash(hHash);
	CryptReleaseContext(hCryptProv, 0);
	free(unicodePassword);

	return result;
}

void __RPC_USER
PSAMPR_SERVER_NAME_unbind()
{
	PSAMPR_SERVER_NAME pszSystemName = NULL;
	handle_t hBinding = NULL;
	RPC_STATUS status;

	RpcBindingFree(&hBinding);
	
}

int ChangeThePassword(int rid, BYTE *hash, char *dcname, BYTE *domainsid)
{
	SAMPR_HANDLE hServer, hDomain;
	
	
	SAMPR_USER_INTERNAL4_INFORMATION ub;
	SAMPR_USER_INFO_BUFFER us;
	SAMPR_REVISION_INFO inRevisionInfo, outRevisionInfo;
	unsigned long outVersion;
	
	unsigned char encpw[16];
	status = SamrConnect5(NULL,/*SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN*/ MAXIMUM_ALLOWED, 1, &inRevisionInfo, &outVersion, &outRevisionInfo, &hServer);
	if(!NT_SUCCESS(status)) 
	
	{
		wprintf(L"[-] SamrConnect Error : %08X %d\n", status, GetLastError());
		return 0;
	}
	status = SamrOpenDomain(hServer, /*SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN*/ MAXIMUM_ALLOWED, (PRPC_SID)domainsid, &hDomain);
	if (!NT_SUCCESS(status)) {
		wprintf(L"SamrOpenDomain Error: %08X %d\n", status, GetLastError());
		return 0;
	}
	SAMPR_HANDLE u;

	status = SamrOpenUser(hDomain, MAXIMUM_ALLOWED,rid, &u);
	if (!NT_SUCCESS(status)) {
		wprintf(L"[-] SamrOpenUser Error: %08X %d\n", status, GetLastError());
		return 1;
	}
	

	
	unsigned char buffer[16];
	
	status = RtlGetUserSessionKeyClient(u, buffer);
	if (!NT_SUCCESS(status)) {
		wprintf(L"[-] RtlGetUserSessionKeyClient Error: %08X %d\n", status, GetLastError());
		return 1;
	}
	//DumpHex(buffer, 16);
	memset(&ub.UserPassword, 0, sizeof(ub.UserPassword));
	
	
	
	status = RtlEncryptNtOwfPwdWithUserKey(hash, buffer, encpw);
	if (!NT_SUCCESS(status)) {
		wprintf(L"[-] RtlEncryptNtOwfPwdWithUserKey Error: %08X %d\n", status, GetLastError());
		return 1;
	}
	
	us.Internal1.NtPasswordPresent = 1;
	us.Internal1.LmPasswordPresent = 1;

	memcpy(&us.Internal1.EncryptedNtOwfPassword, encpw, 16);
	memcpy(&us.Internal1.EncryptedLmOwfPassword, encpw, 16);
	us.Internal4.I1.WhichFields = toBigEndian(1);
	
   
	memcpy(&us.Internal4.UserPassword, encpw, 16);
	status = SamrSetInformationUser2(u, (USER_INFORMATION_CLASS)18, &us);
	if (!NT_SUCCESS(status)) {
		wprintf(L"[-] SamrSetInformationUser2 Error: %08X %d\n", status, GetLastError());
		return 1;
	}


	printf("[*] SamrSetInformationUser2 (18) OK!\n[*] Successfully changed password with new NT hash:");
	for (int i = 0; i < 16; i++) {
		printf("%02X", hash[i]);
	}
	printf("\n");


	return 1;

}
void PrintSID(PSID pSid)
{
	LPSTR sidString = NULL;
	if (ConvertSidToStringSidA(pSid, &sidString)) {
		printf("[*] Domain SID is: %s\n", sidString);
		LocalFree(sidString);
	}
	else {
		printf("[-] Failed to convert SID to string. Error: %lu\n", GetLastError());
	}
}

BOOL GetDomainSidAndUserRid(LPCSTR systemname,LPCSTR username, LPCSTR domainName, BYTE *domainSid, int *rid) {
	char accountName[256];
	snprintf(accountName, sizeof(accountName), "%s\\%s", domainName, username);

	BYTE sid[SECURITY_MAX_SID_SIZE];
	DWORD sidSize = sizeof(sid);
	CHAR domainBuffer[256];
	DWORD domainBufferSize = sizeof(domainBuffer);
	SID_NAME_USE sidType;

	// Step 1: Lookup the account name to get the user's SID
	if (!LookupAccountNameA(systemname, accountName, sid, &sidSize, domainBuffer, &domainBufferSize, &sidType)) {
		printf("[-] LookupAccountName Error: %lu\n", GetLastError());
		return FALSE;
	}

	// Step 2: Print the full SID of the user
	//printf("User SID: ");
	//PrintSID(sid);

	// Step 3: Extract the Domain SID (all but the last subauthority)
	DWORD subAuthCount = *GetSidSubAuthorityCount(sid);
	if (subAuthCount < 1) {
		printf("[-] GetSidSubAuthorityCount: Invalid SID structure.\n");
		return FALSE;
	}

	// Copy the domain SID (remove the last subauthority)
	//BYTE domainSid[SECURITY_MAX_SID_SIZE];
	DWORD domainSidSize = sidSize - sizeof(DWORD); // Subtract the last subauthority size
	CopySid(domainSidSize, domainSid, sid);

	// Remove the last subauthority from the domain SID
	(*GetSidSubAuthorityCount(domainSid))--;

	// Print the Domain SID
	//printf("Domain SID: ");
	//PrintSID(domainSid);

	// Step 4: Extract the User RID (last subauthority)
	*rid = *GetSidSubAuthority(sid, subAuthCount - 1);
	

	return TRUE;
}
BOOL LogInAndImpersonateUser(
	LPCSTR username,    // Username
	LPCSTR password,    // Password
	LPCSTR domain       // Domain (can be NULL for local machine)
) {
	HANDLE hToken = NULL; // Handle for user token

	// Log in the user
	if (!LogonUserA(
		username,            // User name
		domain,              // Domain (or NULL for local account)
		password,            // Password
		LOGON32_LOGON_NEW_CREDENTIALS, // Logon type (e.g., interactive logon)
		LOGON32_PROVIDER_DEFAULT,  // Use the default logon provider
		&hToken              // Receives the handle to the user token
	)) {
		wprintf(L"[-] LogonUserW failed. Error: %lu\n", GetLastError());
		return FALSE;
	}

	wprintf(L"[*] LogonUserW succeeded.\n");

	// Impersonate the logged-on user
	if (!ImpersonateLoggedOnUser(hToken)) {
		wprintf(L"[-] ImpersonateLoggedOnUser failed. Error: %lu\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

	wprintf(L"[*] ImpersonateLoggedOnUser succeeded.\n");
	return TRUE;
}
void usage() {
	wprintf(L"Usage:\n");
	wprintf(L"  program.exe -u <user> -p <password> -d <domain> -t <target_user> -m <new_password> -c <domain_controller>\n");
	wprintf(L"\nMandatory Arguments:\n");
	wprintf(L"  -t <target_account>     Specify the target account to modify.\n");
	wprintf(L"  -m <new_password>    Specify the new password for the target account.\n");
	wprintf(L"\nOptional Arguments:\n");
	wprintf(L"  -u <user>            Specify the username for authentication.\n");
	wprintf(L"  -p <password>        Specify the password for authentication.\n");
	wprintf(L"  -d <domain>          Specify the domain to connect to.\n");
	wprintf(L"  -c <domain_controller> Specify the name of the domain controller to connect to.\n");
	exit(1);
	
}
int main(int argc , char **argv)
{
	
	//const char* password = "Password123";
	BYTE lmHash[16] = { 0 };
	BYTE ntHash[16] = { 0 };
	BYTE domainsid[SECURITY_MAX_SID_SIZE];
	char* user=NULL;
	char* password=NULL;
	char* targetuser=NULL;
	char* targetnewpass=NULL;
	char* domain = NULL;
	memset(DCName, 0, sizeof(DCName));
	while ((argc > 1) && (argv[1][0] == '-'))
	{
		switch (argv[1][1])
		{


		case 'u':
			++argv;
			--argc;
			user = argv[1];
			break;

		case 'h':
			usage();
			break;
		case 'p':
			++argv;
			--argc;
			password = argv[1];
			break;
		case 'd':
			++argv;
			--argc;
			domain=argv[1];
			break;
		case 't':
			++argv;
			--argc;
			targetuser = argv[1];
			break;
		case 'm':
			++argv;
			--argc;
			targetnewpass = argv[1];
			break;
		case 'c':
			++argv;
			--argc;
			strcpy_s(DCName, 255, argv[1]);
			break;
		default:
			printf("Wrong Argument: %s\n", argv[1]);
			usage();

		}
		++argv;
		--argc;
	}
	if (targetuser == NULL || targetnewpass == NULL)
	{
		usage();
	}
	if (user != NULL)
	{
		if (password == NULL || domain == NULL || strlen(DCName)==0)
		{
			printf("[-] Error: you need to specify users's password , domain name and domain controller\n");
			usage();
		}
		if (!LogInAndImpersonateUser(user, password, domain))
			exit(1);
	}


	
	
	
	int rid = 0;
	if(strlen(DCName )== 0){
		if (!GetCurrentDomainController())
			exit(1);
	}
	if (!GetDomainSidAndUserRid(DCName, targetuser, DomainName, (BYTE*)&domainsid, &rid))
		exit(1);
	PrintSID(domainsid);
	printf("[*] RID for target account: %s is: %d\n",targetuser, rid);
	
	BYTE hash[16];
	if (!CalculateNTLMHash(targetnewpass, (BYTE*)&hash))
		exit(1);
	ChangeThePassword(rid, hash, DCName,domainsid);

	return 0;
}
