#include <stdio.h>
#include <ntstatus.h>
#include "ms-samr.h"
#include <sddl.h>
#include <dsparse.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <wincrypt.h>
#include <ctype.h>
#include <psapi.h>
#include <dsgetdc.h>
#include <WinBase.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Ntdsapi.lib")
#pragma comment(lib, "netapi32.lib") 
#pragma comment(lib, "bcrypt.lib")
#pragma warning(disable : 4996)
#define MAXIMUM_ALLOWED 0x02000000
#define RtlEncryptBlock						SystemFunction001 // DES
#define RtlDecryptBlock						SystemFunction002 // DES
#define RtlEncryptStdBlock					SystemFunction003 // DES with key "KGS!@#$%" for LM hash
#define RtlEncryptData						SystemFunction004 // DES/ECB
#define RtlDecryptData						SystemFunction005 // DES/ECB
#define RtlCalculateLmOwfPassword			SystemFunction006
#define RtlCalculateNtOwfPassword			SystemFunction007
#define RtlCalculateLmResponse				SystemFunction008
#define RtlCalculateNtResponse				SystemFunction009
#define RtlCalculateUserSessionKeyLm		SystemFunction010
#define RtlCalculateUserSessionKeyNt		SystemFunction011
#define RtlEncryptLmOwfPwdWithLmOwfPwd		SystemFunction012
#define RtlDecryptLmOwfPwdWithLmOwfPwd		SystemFunction013
#define RtlEncryptNtOwfPwdWithNtOwfPwd		SystemFunction014
#define RtlDecryptNtOwfPwdWithNtOwfPwd		SystemFunction015
#define RtlEncryptLmOwfPwdWithLmSesKey		SystemFunction016
#define RtlDecryptLmOwfPwdWithLmSesKey		SystemFunction017
#define RtlEncryptNtOwfPwdWithNtSesKey		SystemFunction018
#define RtlDecryptNtOwfPwdWithNtSesKey		SystemFunction019
#define RtlEncryptLmOwfPwdWithUserKey		SystemFunction020
#define RtlDecryptLmOwfPwdWithUserKey		SystemFunction021
#define RtlEncryptNtOwfPwdWithUserKey		SystemFunction022
#define RtlDecryptNtOwfPwdWithUserKey		SystemFunction023
#define RtlEncryptLmOwfPwdWithIndex			SystemFunction024
#define RtlDecryptLmOwfPwdWithIndex			SystemFunction025
#define RtlEncryptNtOwfPwdWithIndex			SystemFunction026
#define RtlDecryptNtOwfPwdWithIndex			SystemFunction027
#define RtlGetUserSessionKeyClient			SystemFunction028
#define RtlGetUserSessionKeyServer			SystemFunction029
#define RtlEqualLmOwfPassword				SystemFunction030
#define RtlEqualNtOwfPassword				SystemFunction031
#define RtlEncryptData2						SystemFunction032 // RC4
#define RtlDecryptData2						SystemFunction033 // RC4
#define RtlGetUserSessionKeyClientBinding	SystemFunction034
#define RtlCheckSignatureInFile				SystemFunction035

NTSTATUS WINAPI RtlEncryptBlock(IN LPCBYTE ClearBlock, IN LPCBYTE BlockKey, OUT LPBYTE CypherBlock);
NTSTATUS WINAPI RtlDecryptBlock(IN LPCBYTE CypherBlock, IN LPCBYTE BlockKey, OUT LPBYTE ClearBlock);
NTSTATUS WINAPI RtlEncryptStdBlock(IN LPCBYTE BlockKey, OUT LPBYTE CypherBlock);
//NTSTATUS WINAPI RtlEncryptData(IN PCLEAR_DATA ClearData, IN PDATA_KEY DataKey, OUT PCYPHER_DATA CypherData);
//NTSTATUS WINAPI RtlDecryptData(IN PCYPHER_DATA CypherData, IN PDATA_KEY DataKey, OUT PCLEAR_DATA ClearData);
NTSTATUS WINAPI RtlCalculateLmOwfPassword(IN LPCSTR data, OUT LPBYTE output);
//NTSTATUS WINAPI RtlCalculateNtOwfPassword(IN PCUNICODE_STRING data, OUT LPBYTE output);
NTSTATUS WINAPI RtlCalculateLmResponse(IN LPCBYTE LmChallenge, IN LPCBYTE LmOwfPassword, OUT LPBYTE LmResponse);
NTSTATUS WINAPI RtlCalculateNtResponse(IN LPCBYTE NtChallenge, IN LPCBYTE NtOwfPassword, OUT LPBYTE NtResponse);
NTSTATUS WINAPI RtlCalculateUserSessionKeyLm(IN LPCBYTE LmResponse, IN LPCBYTE LmOwfPassword, OUT LPBYTE UserSessionKey);
NTSTATUS WINAPI RtlCalculateUserSessionKeyNt(IN LPCBYTE NtResponse, IN LPCBYTE NtOwfPassword, OUT LPBYTE UserSessionKey);
NTSTATUS WINAPI RtlEncryptLmOwfPwdWithLmOwfPwd(IN LPCBYTE DataLmOwfPassword, IN LPCBYTE KeyLmOwfPassword, OUT LPBYTE EncryptedLmOwfPassword);
NTSTATUS WINAPI RtlDecryptLmOwfPwdWithLmOwfPwd(IN LPCBYTE EncryptedLmOwfPassword, IN LPCBYTE KeyLmOwfPassword, OUT LPBYTE DataLmOwfPassword);
NTSTATUS WINAPI RtlEncryptNtOwfPwdWithNtOwfPwd(IN LPCBYTE DataNtOwfPassword, IN LPCBYTE KeyNtOwfPassword, OUT LPBYTE EncryptedNtOwfPassword);
NTSTATUS WINAPI RtlDecryptNtOwfPwdWithNtOwfPwd(IN LPCBYTE EncryptedNtOwfPassword, IN LPCBYTE KeyNtOwfPassword, OUT LPBYTE DataNtOwfPassword);
NTSTATUS WINAPI RtlEncryptLmOwfPwdWithLmSesKey(IN LPCBYTE LmOwfPassword, IN LPCBYTE LmSessionKey, OUT LPBYTE EncryptedLmOwfPassword);
NTSTATUS WINAPI RtlDecryptLmOwfPwdWithLmSesKey(IN LPCBYTE EncryptedLmOwfPassword, IN LPCBYTE LmSessionKey, OUT LPBYTE LmOwfPassword);
NTSTATUS WINAPI RtlEncryptNtOwfPwdWithNtSesKey(IN LPCBYTE NtOwfPassword, IN LPCBYTE NtSessionKey, OUT LPBYTE EncryptedNtOwfPassword);
NTSTATUS WINAPI RtlDecryptNtOwfPwdWithNtSesKey(IN LPCBYTE EncryptedNtOwfPassword, IN LPCBYTE NtSessionKey, OUT LPBYTE NtOwfPassword);
NTSTATUS WINAPI RtlEncryptLmOwfPwdWithUserKey(IN LPCBYTE LmOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE EncryptedLmOwfPassword);
NTSTATUS WINAPI RtlDecryptLmOwfPwdWithUserKey(IN LPCBYTE EncryptedLmOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE LmOwfPassword);
NTSTATUS WINAPI RtlEncryptNtOwfPwdWithUserKey(IN LPCBYTE NtOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE EncryptedNtOwfPassword);
NTSTATUS WINAPI RtlDecryptNtOwfPwdWithUserKey(IN LPCBYTE EncryptedNtOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE NtOwfPassword);
NTSTATUS WINAPI RtlEncryptLmOwfPwdWithIndex(IN LPCBYTE LmOwfPassword, IN LPDWORD Index, OUT LPBYTE EncryptedLmOwfPassword);
NTSTATUS WINAPI RtlDecryptLmOwfPwdWithIndex(IN LPCBYTE EncryptedLmOwfPassword, IN LPDWORD Index, OUT LPBYTE LmOwfPassword);
NTSTATUS WINAPI RtlEncryptNtOwfPwdWithIndex(IN LPCBYTE NtOwfPassword, IN LPDWORD Index, OUT LPBYTE EncryptedNtOwfPassword);
NTSTATUS WINAPI RtlDecryptNtOwfPwdWithIndex(IN LPCBYTE EncryptedNtOwfPassword, IN LPDWORD Index, OUT LPBYTE NtOwfPassword);
NTSTATUS WINAPI RtlGetUserSessionKeyClient(IN PVOID RpcContextHandle, OUT LPBYTE UserSessionKey);
NTSTATUS WINAPI RtlGetUserSessionKeyServer(IN PVOID RpcContextHandle OPTIONAL, OUT LPBYTE UserSessionKey);
BOOLEAN WINAPI RtlEqualLmOwfPassword(IN LPCBYTE LmOwfPassword1, IN LPCBYTE LmOwfPassword2);
BOOLEAN WINAPI RtlEqualNtOwfPassword(IN LPCBYTE NtOwfPassword1, IN LPCBYTE NtOwfPassword2);
//NTSTATUS WINAPI RtlEncryptData2(IN OUT PCRYPT_BUFFER pData, IN PDATA_KEY pkey);
//NTSTATUS WINAPI RtlDecryptData2(IN OUT PCRYPT_BUFFER pData, IN PDATA_KEY pkey);
NTSTATUS WINAPI RtlGetUserSessionKeyClientBinding(IN PVOID RpcBindingHandle, OUT HANDLE* RedirHandle, OUT LPBYTE UserSessionKey);
ULONG WINAPI RtlCheckSignatureInFile(IN LPCWSTR filename);


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
#define ENC_KEY_SIZE 32
#define MAC_KEY_SIZE 64
#define AES_BLOCK_SIZE 16
#define SAM_MAX_PASSWORD_LENGTH 256
#define SHA512_DIGEST_SIZE 64
#define SAM_AES256_ENC_KEY_STRING "Microsoft SAM encryption key AEAD-AES-256-CBC-HMAC-SHA512 16"
#define SAM_AES256_MAC_KEY_STRING "Microsoft SAM MAC key AEAD-AES-256-CBC-HMAC-SHA512 16"
UCHAR CEK[16]; // Random key for encryption (CEK)
UCHAR* gCipher;
BCRYPT_KEY_HANDLE ghKey = NULL;
#define AES_BUFFER_SIZE 514
typedef struct _SAMPR_USER_PASSWORD_AES {
	USHORT PasswordLength; // Length of the password in bytes
	WCHAR Buffer[SAM_MAX_PASSWORD_LENGTH]; // UTF-16 encoded password


} SAMPR_USER_PASSWORD_AES, * PSAMPR_USER_PASSWORD_AES;
typedef NTSTATUS(WINAPI* SamrEncryptClearPasswordWithSessionKeyAES)(
	SAMPR_HANDLE DomainHandle,
	SAMPR_USER_PASSWORD_AES* ClearTextPassword,
	SAMPR_ENCRYPTED_PASSWORD_AES* EncryptedPassword
	);
void* FindPattern(void* base, size_t size, const unsigned char* pattern, size_t patternSize) {
	unsigned char* start = (unsigned char*)base;
	unsigned char* end = start + size - patternSize;

	for (unsigned char* current = start; current < end; current++) {
		if (memcmp(current, pattern, patternSize) == 0) {
			printf("[*] Found address for SamrEncryptClearPasswordWithSessionKeyAES at:%p\n", current);
			return current;// 0x00007ffb2908596c;// 0x00007ffb29085e5c;  // Return the address of the match
		}
	}

	return  NULL;  // Pattern not found
}
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
void generate_random_bytes(UCHAR* buffer, size_t size) {
	srand((unsigned int)time(NULL));
	for (size_t i = 0; i < size; i++) {
		buffer[i] = rand() % 256;
	}
}
NTSTATUS derive_hmac_sha512(UCHAR* key, ULONG key_len, const char* data, ULONG data_len, UCHAR* output, ULONG output_len) {
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	NTSTATUS status;
	DWORD result_size;

	status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA512_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (status != STATUS_SUCCESS) {
		printf("status 0 %d\n", status);

		return status;
	}

	status = BCryptCreateHash(hAlg, &hHash, NULL, 0, key, key_len, 0);
	if (status != STATUS_SUCCESS) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
		printf("status 1 %d\n", status);
		return status;
	}

	status = BCryptHashData(hHash, (PUCHAR)data, data_len, 0);
	if (status != STATUS_SUCCESS) {
		BCryptDestroyHash(hHash);
		BCryptCloseAlgorithmProvider(hAlg, 0);
		printf("status 2 %d\n;", status);
		return status;
	}

	status = BCryptFinishHash(hHash, output, output_len, 0);
	printf("status 3 %d\n", status);
	BCryptDestroyHash(hHash);
	BCryptCloseAlgorithmProvider(hAlg, 0);

	return status;
}
NTSTATUS hmac_sha512_authdata(UCHAR* mac_key, UCHAR* iv, PUCHAR cipher, ULONG cipher_len, UCHAR* auth_data) {
	UCHAR version_byte = 0x01; // Example version byte
	ULONG total_len = 1 + AES_BLOCK_SIZE + cipher_len + 1; // version + IV + Cipher + version length
	PUCHAR auth_input = (PUCHAR)malloc(total_len);
	printf("cyer len=%d totallen=%d\n", cipher_len, total_len);
	if (!auth_input) {
		return STATUS_NO_MEMORY;
	}
	//Let AuthData ::= HMAC-SHA-512(mac_key, versionbyte + IV + Cipher + versionbyte_length)
	// 
	// Concatenate version, IV, Cipher, and version length
	auth_input[0] = version_byte;
	memcpy(auth_input + 1, iv, AES_BLOCK_SIZE);
	memcpy(auth_input + 1 + AES_BLOCK_SIZE, cipher, cipher_len);
	auth_input[1 + AES_BLOCK_SIZE + cipher_len] = 1;// sizeof(version_byte);
	//DumpHex(auth_input, 546);
	//getchar();
	// Generate HMAC
	NTSTATUS status = derive_hmac_sha512(mac_key, MAC_KEY_SIZE, (char*)auth_input, total_len, auth_data, SHA512_DIGEST_SIZE);

	free(auth_input);
	return status;
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

	
	RPC_CSTR pszStringBinding;
	RPC_STATUS status;
	RPC_CSTR ProtSeq = "ncacn_np";
	RPC_CSTR Endpoint ="\\pipe\\samr";
	handle_t hBinding = NULL;
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
	/*
	status = RpcBindingSetAuthInfoA(
		hBinding,
		NULL,                              // Server principal name (NULL = use SPN)
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,     // Authentication level (packet privacy)
		RPC_C_AUTHN_WINNT,                 // Authentication service (Windows NT)
		NULL,                              // Auth identity (use current user credentials)
		RPC_C_AUTHZ_NAME                   // Authorization service
	);
	if (status)
	{
		printf("[-]pcBindingSetAuthInfo  0x%x\n", status);
	}
	*/
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
	
	status = RtlEncryptNtOwfPwdWithUserKey(hash, buffer, encpw);
	if (!NT_SUCCESS(status)) {
		wprintf(L"[-] RtlEncryptNtOwfPwdWithUserKey Error: %08X %d\n", status, GetLastError());
		return 1;
	}
	
	us.Internal1.NtPasswordPresent = 1;
	us.Internal1.LmPasswordPresent = 0;

	memcpy(&us.Internal1.EncryptedNtOwfPassword, encpw, 16);
	memcpy(&us.Internal1.EncryptedLmOwfPassword, encpw, 16);
	//us.Internal4.I1.WhichFields = toBigEndian(1);
	
   
	//memcpy(&us.Internal4.UserPassword, encpw, 16);
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
void SetRpcUnicodeString(RPC_UNICODE_STRING* rpcString, const wchar_t* value) {
	size_t length = wcslen(value) * sizeof(WCHAR); // Length in bytes

	rpcString->Length = (USHORT)length;
	rpcString->MaximumLength = (USHORT)(length + sizeof(WCHAR)); // +2 for null terminator
	rpcString->Buffer = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, rpcString->MaximumLength);

	if (rpcString->Buffer == NULL) {
		fprintf(stderr, "Failed to allocate memory for RPC_UNICODE_STRING buffer.\n");
		exit(EXIT_FAILURE);
	}

	// Copy the string into the buffer
	memcpy(rpcString->Buffer, value, length);
}
typedef struct _USER_INFO_1008X {
	LPWSTR usri1008_password;  // The password to be set
} USER_INFO_1008X;
void ChangePassword(const wchar_t* server, const wchar_t* username, const wchar_t* new_password) {
	// User info structure for setting password
	USER_INFO_1008X userInfo;
	NET_API_STATUS ret;

	// Initialize the structure with the new password
	userInfo.usri1008_password = (wchar_t*)new_password;

	// Call NetUserSetInfo to update the password
	ret= NetUserSetInfo(server, username, 1003, (LPBYTE)&userInfo, NULL);

	if (!ret) {
		wprintf(L"[*] Password changed successfully for user %s on %s\n", username, server);
	}
	else {
		wprintf(L"[!] Failed to change password. Error code: %d\n", ret);
	}
}
int ChangeDSRMPassword(int rid, BYTE* hash, char* dcname)
{
	SAMPR_HANDLE  hServer, hDomain;


	SAMPR_USER_INFO_BUFFER us;
	SAMPR_REVISION_INFO inRevisionInfo, outRevisionInfo;
	unsigned long outVersion;
	RPC_UNICODE_STRING rpcString;
	const wchar_t* value = L"Administrator";

	SetRpcUnicodeString(&rpcString, value);

	unsigned char encpw[16];
	hServer = PSAMPR_SERVER_NAME_bind();
	if (hServer == NULL)
	{
		wprintf(L"[-] SamrConnect Error : %08X %d\n", status, GetLastError());

	}
		status = RtlEncryptNtOwfPwdWithIndex(hash, &rid, &encpw);
	if (!NT_SUCCESS(status)) {
		wprintf(L"[-] RtlEncryptNtOwfPwdWithIndexError: %08X %d\n", status, GetLastError());
		return 1;
	}
		
	status = SamrSetDSRMPassword(hServer, NULL, rid, encpw);
	if(!status)
		wprintf(L"[*] SamrSetDSRMPassword Success!!!: %08X\n", status);
	else
		wprintf(L"[*] SamrSetDSRMPassword error: %08X\n", status);


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
#define MAX_PASS_LEN 0x200
void KEEncryptDataWithAES(
	PUCHAR plaintext,
	ULONG plaintextSize,
	PUCHAR iv,
	PUCHAR key,
	ULONG keySize,
	PUCHAR* ciphertext,
	ULONG* ciphertextSize)
{
	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	NTSTATUS status;
	ULONG blockLength = 0, resultSize = 0;
	PUCHAR outputBuffer = NULL;

	*ciphertext = NULL;
	*ciphertextSize = 0;

	// Open an algorithm provider for AES
	status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (status != STATUS_SUCCESS) {
		printf("[-] BCryptOpenAlgorithmProvider failed: 0x%x\n", status);
		return;
	}

	// Get AES block size
	status = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PUCHAR)&blockLength, sizeof(ULONG), &resultSize, 0);
	if (status != STATUS_SUCCESS || blockLength != 16) {
		printf("[-] BCryptGetProperty failed or invalid block size: 0x%x\n", status);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return;
	}

	// Set chaining mode to CBC
	status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (status != STATUS_SUCCESS) {
		printf("[-] BCryptSetProperty failed: 0x%x\n", status);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return;
	}

	// Generate a symmetric key
	status = BCryptGenerateSymmetricKey(hAlgorithm, &ghKey, NULL, 0, key, keySize, 0);
	if (status != STATUS_SUCCESS) {
		printf("[-] BCryptGenerateSymmetricKey failed: 0x%x\n", status);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return;
	}

	// Get required buffer size
	status = BCryptEncrypt(ghKey, plaintext, plaintextSize, NULL, iv, blockLength, NULL, 0, ciphertextSize, BCRYPT_BLOCK_PADDING);
	if (status != STATUS_SUCCESS) {
		printf("[-] BCryptEncrypt (size query) failed: 0x%x\n", status);
		BCryptDestroyKey(hKey);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return;
	}

	// Allocate buffer for ciphertext
	/*
	outputBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, *ciphertextSize);
	if (!outputBuffer) {
		printf("[-] Memory allocation failed\n");
		BCryptDestroyKey(hKey);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return;
	}
	*/
	// Encrypt data

	gCipher = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, *ciphertextSize);
	if (!gCipher) {
		printf("[-] Memory allocation failed\n");
		BCryptDestroyKey(hKey);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return;
	}


	status = BCryptEncrypt(ghKey, plaintext, plaintextSize, NULL, iv, blockLength, gCipher, *ciphertextSize, ciphertextSize, BCRYPT_BLOCK_PADDING);
	if (status != STATUS_SUCCESS) {
		printf("[-] BCryptEncrypt failed: 0x%x\n", status);
		HeapFree(GetProcessHeap(), 0, outputBuffer);
		outputBuffer = NULL;
		*ciphertextSize = 0;
	}

	*ciphertext = outputBuffer;
	//ghKey = hKey;
	// Cleanup
	if (hKey) BCryptDestroyKey(hKey);
	if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
}

int ChanegPasswordMoreComplexMode(int rid, BYTE* hash, char* dcname, BYTE* domainsid, wchar_t* password) {
	NTSTATUS status;
	SAMPR_USER_PASSWORD_AES userPassword;

	UCHAR enc_key[ENC_KEY_SIZE];
	UCHAR mac_key[MAC_KEY_SIZE];
	UCHAR iv[AES_BLOCK_SIZE];
	UCHAR iv2[AES_BLOCK_SIZE];
	UCHAR cipher = NULL;
	ULONG cipher_len;
	SAMPR_HANDLE hServer, hDomain;
	unsigned char AuthData[64];

	SAMPR_USER_INFO_BUFFER us;
	SAMPR_ENCRYPTED_PASSWORD_AES uaes, * pp;
	SAMPR_REVISION_INFO inRevisionInfo, outRevisionInfo;
	unsigned long outVersion;

	unsigned char encpw[16];
	status = SamrConnect5(NULL, MAXIMUM_ALLOWED, 1, &inRevisionInfo, &outVersion, &outRevisionInfo, &hServer);
	if (!NT_SUCCESS(status))

	{
		wprintf(L"[-] SamrConnect Error : %08X %d\n", status, GetLastError());
		return 0;
	}
	status = SamrOpenDomain(hServer, MAXIMUM_ALLOWED, (PRPC_SID)domainsid, &hDomain);
	if (!NT_SUCCESS(status)) {
		wprintf(L"SamrOpenDomain Error: %08X %d\n", status, GetLastError());
		return 0;
	}


	SAMPR_HANDLE u;

	status = SamrOpenUser(hDomain, MAXIMUM_ALLOWED, rid, &u);
	if (!NT_SUCCESS(status)) {
		wprintf(L"[-] SamrOpenUser Error: %08X %d\n", status, GetLastError());
		return 1;
	}

	
	status = RtlGetUserSessionKeyClient(hDomain, CEK);
	if (!NT_SUCCESS(status)) {
		wprintf(L"[-] RtlGetUserSessionKeyClient Error: %08X %d\n", status, GetLastError());
		return 1;
	}

	

	status = RtlGetUserSessionKeyClient(hServer, CEK);
	if (!NT_SUCCESS(status)) {
		wprintf(L"[-] RtlGetUserSessionKeyClient Error: %08X %d\n", status, GetLastError());
		return 1;
	}
	status = RtlGetUserSessionKeyClient(u, CEK);
	DumpHex(CEK, 16);
	if (!NT_SUCCESS(status)) {
		wprintf(L"[-] RtlGetUserSessionKeyClient Error: %08X %d\n", status, GetLastError());
		return 1;
	}
	
	UCHAR dummy[64];

	derive_hmac_sha512(CEK, sizeof(CEK), SAM_AES256_ENC_KEY_STRING, 61, dummy, MAC_KEY_SIZE);
	memcpy(enc_key, dummy, ENC_KEY_SIZE);
	derive_hmac_sha512(CEK, sizeof(CEK), SAM_AES256_MAC_KEY_STRING, 54, mac_key, MAC_KEY_SIZE);
	//py(tocrypt, password, wcslen(password));
	UNICODE_STRING uString;


	PUCHAR ciphertext = NULL;
	ULONG ciphertextSize = 0;
	UCHAR passwordBuffer[AES_BUFFER_SIZE] = { 0 };
	USHORT passwordLength;
	passwordLength = wcslen(password) * 2;
	if (passwordLength >= 0x201) {
		printf("[-] Password too long\n");
		return;
	}
	memset(passwordBuffer, 0, AES_BUFFER_SIZE);
	generate_random_bytes(passwordBuffer, AES_BUFFER_SIZE);
	memcpy(&passwordBuffer[0], &passwordLength, sizeof(passwordLength));
	//passwordBuffer[1] = 0;

	memcpy(passwordBuffer + 2, password, passwordLength);
	generate_random_bytes(iv, 16);
	memcpy(iv2, iv, 16);
	memset(&us, 0, sizeof(us));
	DumpHex(iv, 16);
	KEEncryptDataWithAES(&passwordBuffer[0], 514, iv, enc_key, 32, &ciphertext, &ciphertextSize);
	if (status != STATUS_SUCCESS) {
		printf("AES encryption failed: 0x%08x\n", status);
		return 1;
	}
	status = hmac_sha512_authdata(mac_key, iv2, gCipher, 528, AuthData);
	if (status != STATUS_SUCCESS) {
		printf("HMAC generation failed: 0x%08x\n", status);
		free(cipher);
		return 1;
	}
	memcpy(us.Internal8.UserPassword.Salt, iv2, 16);
	memcpy(us.Internal8.UserPassword.AuthData, AuthData, 64);
	us.Internal8.UserPassword.cbCipher = 528;// cipher_len;
	us.Internal8.UserPassword.PBKDF2Iterations = 0;
	us.Internal8.I1.WhichFields = toBigEndian(1);
	us.Internal8.UserPassword.Cipher = gCipher;

	status = SamrSetInformationUser2(u, (USER_INFORMATION_CLASS)32, &us);

	wprintf(L"[*] SamrSetInformationUser2: %08X\n", status);

	return 0;
}
int ChanegPasswordComplexMode(int rid, BYTE* hash, char* dcname, BYTE* domainsid, wchar_t* newpass) {
	NTSTATUS status;
	SAMPR_USER_PASSWORD_AES* puserPassword = NULL;
	SAMPR_USER_PASSWORD_AES userPassword;

	UCHAR enc_key[ENC_KEY_SIZE];
	UCHAR mac_key[MAC_KEY_SIZE];
	UCHAR iv[AES_BLOCK_SIZE];
	PUCHAR cipher = NULL;
	ULONG cipher_len;
	SAMPR_HANDLE hServer, hDomain;
	unsigned char AuthData[64];

	SAMPR_USER_INFO_BUFFER us;
	SAMPR_ENCRYPTED_PASSWORD_AES uaes, * pp;
	SAMPR_REVISION_INFO inRevisionInfo, outRevisionInfo;
	unsigned long outVersion;

	unsigned char encpw[16];
	puserPassword = malloc(sizeof(SAMPR_USER_PASSWORD_AES));
	status = SamrConnect5(NULL, MAXIMUM_ALLOWED, 1, &inRevisionInfo, &outVersion, &outRevisionInfo, &hServer);
	if (!NT_SUCCESS(status))

	{
		wprintf(L"[-] SamrConnect Error : %08X %d\n", status, GetLastError());
		return 0;
	}
	status = SamrOpenDomain(hServer, MAXIMUM_ALLOWED, (PRPC_SID)domainsid, &hDomain);
	if (!NT_SUCCESS(status)) {
		wprintf(L"SamrOpenDomain Error: %08X %d\n", status, GetLastError());
		return 0;
	}


	SAMPR_HANDLE u;

	status = SamrOpenUser(hDomain, MAXIMUM_ALLOWED, rid, &u);
	if (!NT_SUCCESS(status)) {
		wprintf(L"[-] SamrOpenUser Error: %08X %d\n", status, GetLastError());
		return 1;
	}
	BYTE pattern[] = { 0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x57, 0x48, 0x83, 0xEC,0x70,0x48,0x8b };
	char mask[] = "xxxxxxxxxxxxx";  // Adjust for wildcard bytes

	// Locate the function address in memory
	//void* pFunc = FindPattern(base, size, pattern, mask);
	HMODULE hSamlib = LoadLibraryA("c:\\windows\\system32\\samlib.dll");
	if (!hSamlib) {
		printf("[-] Failed to load samlib.dll (Error: %lu)\n", GetLastError());
		return 1;
	}
	MODULEINFO moduleInfo;
	if (GetModuleInformation(GetCurrentProcess(), hSamlib, &moduleInfo, sizeof(moduleInfo)) == 0) {
		printf("[-] Failed to get module information\n");
		return -1;
	}

	void* pFunc = FindPattern(moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage, pattern, 13);
	if (!pFunc) {
		printf("[-] Failed to locate function in memory.\n");
		FreeLibrary(hSamlib);
		return 1;
	}

	void* pFunc1 = 0x00007FFB29085E5C;

	SamrEncryptClearPasswordWithSessionKeyAES SamiEncrypt = (SamrEncryptClearPasswordWithSessionKeyAES)pFunc;
	UNICODE_STRING uString;
	
	RtlInitUnicodeString(&uString, newpass);
	status = SamiEncrypt(u, &uString, &uaes);
		wprintf(L"[*] SamrEncryptClearPasswordWithSessionKeyAES status %08X\n", status);
	memset(&us, 0, sizeof(us));
	memcpy(us.Internal8.UserPassword.Salt, uaes.Salt, 16);
	memcpy(us.Internal8.UserPassword.AuthData, uaes.AuthData, 64);
	us.Internal8.UserPassword.cbCipher = uaes.cbCipher;
	us.Internal8.UserPassword.PBKDF2Iterations = 0;
	us.Internal8.I1.WhichFields = toBigEndian(1);// oBigEndian(0x40000000);
	us.Internal8.UserPassword.Cipher = uaes.Cipher;// cipherbuff;// cipher;// encryptedPassword.Cipher;// encryptedPassword.Cipher;
		status = SamrSetInformationUser2(u, (USER_INFORMATION_CLASS)32, &us);
	wprintf(L"[*] SamrSetInformationUser2 status: %08X\n", status);

		return 0;
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
	wprintf(L"\n\n** chgpass - @decoder_it 2025 **\n\nUsage:\n");
	wprintf(L"chgpass.exe [-u <user>] [-p <password>] [-d <domain>] -t <target_user> -m <new_password> [-c <domain_controller>] [-l <target_server>]\n");
	wprintf(L"\nMandatory Arguments:\n");
	wprintf(L"  -t <target_account>     Specify the target account to modify. Use **DSRM** for changing DSRM password, can be blank too\n");
	wprintf(L"  -m <target_password>    Specify the target password to modify.\n");
	
	
	wprintf(L"\nOptional Arguments:\n");
	wprintf(L"  -l <target server>      Specify the destination server for target account\n");
	wprintf(L"  -u <user>               Specify the alternate username for authentication.\n");
	wprintf(L"  -p <password>           Specify the alternate password for authentication.\n");
	wprintf(L"  -d <domain>             Specify the domain name to authenticate to.\n");
	wprintf(L"  -c <domain_controller>  Specify the name of the domain controller to connect to.\n");
	exit(1);
	
}
void HexStringToByteArray(const char* hexString, unsigned char* byteArray, size_t* byteArrayLen) {
	size_t hexLen = strlen(hexString);
	if (hexLen % 2 != 0) {
		fprintf(stderr, "Invalid hex string length.\n");
		exit(EXIT_FAILURE);
	}

	*byteArrayLen = hexLen / 2;
	for (size_t i = 0; i < *byteArrayLen; ++i) {
		char byteChars[3] = { hexString[i * 2], hexString[i * 2 + 1], '\0' };
		byteArray[i] = (unsigned char)strtol(byteChars, NULL, 16);
	}
}
int main(int argc , char **argv)
{
	
	
	BYTE domainsid[SECURITY_MAX_SID_SIZE];
	char* user=NULL;
	char* password=NULL;
	char* targetuser=NULL;
	char* targetnewpass=NULL;
	char* domain = NULL;
	char* targetserver = NULL;
	wchar_t wtargetserver[256], wtargetuser[256], wtargetnewpass[256];
	memset(DCName, 0, sizeof(DCName));
	BYTE hash[16], b[16];
	DWORD index = 0;
	
	
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
		case 'l':
			++argv;
			--argc;
			targetserver = argv[1];
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


	
	
	
	int rid = 500;
	int len=0;
	
	if (strlen(DCName) == 0) {
		if (!GetCurrentDomainController())
			exit(1);
	}
	else
	{
		printf("[*] Targeting Domain Controller/Server: %s\n", DCName);
		
	}
	if (targetserver == NULL)
		targetserver = &DCName;
	if (strlen(targetnewpass) > 0)
	{
		if (!CalculateNTLMHash(targetnewpass, (BYTE*)&hash))
			exit(1);
		printf("[*] New NT Hash: ");
	}
	else
	{
		HexStringToByteArray("31d6cfe0d16ae931b73c59d7e0c089c0", &hash, &len);
		printf("[*] You choose en empty pass corresponding to NT Hash: ");
	}
	
	
	for (int i = 0; i < 16; i++) {
		printf("%02X", hash[i]);
	}
	printf("\n");
	if (!strcmp(targetuser, "**DSRM**"))
	{
		printf("[*] Resetting DSRM password on: %s\n", DCName);
		ChangeDSRMPassword(rid, hash, DCName);
		exit(0);
	}
	mbstowcs(wtargetserver, targetserver, strlen(targetserver)+1);
	mbstowcs(wtargetuser, targetuser, strlen(targetuser)+1);
	mbstowcs(wtargetnewpass, targetnewpass, strlen(targetnewpass)+1);
	ChangePassword(wtargetserver, wtargetuser, wtargetnewpass);
	
	/*
	if (!GetDomainSidAndUserRid(DCName, targetuser, DomainName, (BYTE*)&domainsid, &rid))
		exit(1);
	PrintSID(domainsid);
	printf("[*] RID for target account: %s is: %d\n", targetuser, rid);

	ChangePasswordComplexMode(rid, hash, DCName, domainsid, wtargetnewpass);
	ChangePasswordMoreComplexMode(rid, hash, DCName, domainsid, wtargetnewpass);
	*/
	return 0;
}
