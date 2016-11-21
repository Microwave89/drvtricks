#ifndef _STRINGPOOL_H_
#define _STRINGPOOL_H_

typedef struct _STRINGPOOL {
	char* pFileInstallPath;
	char* pServicesKeyPath;
	char* pClassPath;
	char* pBCDKeyPathAboveGuid;
	char* pHiderSvc;
	//char* pBCDKeyPathBeneathGuid;
} STRINGPOOL, *PSTRINGPOOL;

PSTRINGPOOL g_pCommonStrings;

#endif