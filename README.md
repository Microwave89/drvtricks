# drvtricks
drvtricks kernel driver for Windows 7 SP1 and 8.1 x64, that tricks around in your system.

===== IMPORTANT WORDS ABOUT THE SOURCE =====


- What is this?

It is a small Windows kernel driver that serves as a non-malicious Proof of Concept (PoC) for demo purposes on the subject of rootkit techniques.
Normally, rootkits are used by attackers in order to conceal both various malware as well as its activity. In this example the payload consists of a local keylogger which stores key presses into an NTFS special file hidden by Windows itself.


- What makes it special against existing PoCs?

The same way a classic 32 bits rootkit does WITH hooking my rootkit attempts to conceal the vast majority of its existence WITHOUT hooking. Note that with Kernel Patch Protection no persistent hooks are permitted. Furthermore, it aims to exhibiting strong persistence.


- What functions does it have?

==> Passive concealment of: its driver file, the keylogger file, its driver image, its system threads,
    its own (service) registry key, and its IRP hook. Driver file and keylogger file are hidden by leveraging
    undocumented directory C:\$Extend\$RmMetadata passively hidden by ntfs.sys. Service key is hidden by exploiting
    regedit's ability to not display keys with names longer than ~250? characters and all keys following the faulty
    key. IRP hook is hidden due to very working principle of Windows keyboard device stack.

==> Persistence of: its driver file, its registry key, its testsigning entry, and the "kbdclass" entry in the
    "\Registry\Machine\SYSTEM\CurrentControlSet\Control\Class\{4d36e96b-e325-11ce-bfc1-08002be10318}\\UpperFilters"
    value. A bunch of passive callback routines as well as exclusive file openings either recover deleted or modified
    keys and values, that are being observed, or prevent their deletion (as in case of files) in the first place.
    The testsigning entry normally is in "\Registry\Machine\BCD00000000\Objects\%ws\Elements\16000049" but
    somehow "\Registry\Machine\BCD00000000\Objects\%ws\Elements\ 16000049" is also accepted and when booting
    is always looked into first. With bcdedit you can only edit or remove the "\16000049" key but never the rogue
    "\ 16000049\" key.
    
==> Driverless driver design that first refuses loading with error 0xC0000025 but secretly runs afterwards.
    This leverages callback functions (ZwNotifyChangeKey(), NtNotifyChangeDirectoryFile(), Dynamic IRP hook on
    pKbdDrvObj->MajorFunction[IRP_MJ_READ]), and a few system worker threads (Created by ExQueueWorkItem() and then
    executed by an nt!ExpWorkerThread) all of which execute from nonpaged RWX system memory.
    
==> Independent randomization of driver service name, driver file name, and of various service settings such as
    service type, type of the registry value for "service type", etc.
    
==> Configuration as SERVICE_SYSTEM_START and also working in all kinds of safe mode due to addition to
    "System Bus Extender" group.
    
- How do I make this?
IIRC I used Visual Studio 2013 for build after somewhat customizing the build process so the binary is as small as possible. Final size was little over 19 KB.
