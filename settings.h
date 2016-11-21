#ifndef _SETTINGS_H_
#define _SETTINGS_H_

//#define DEBUGBUILD

#ifdef DEBUGBUILD
#define MYDBGPRINT DbgPrint
#else
#define MYDBGPRINT(...)
#endif
#endif
