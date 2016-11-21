# drvtricks
drvtricks kernel driver for Windows 7 SP1 and 8.1 x64, that tricks around in your system.



===== IMPORTANT INFORMATION REGARDING THE SOURCE CODE COMMENTS =====

The source code appears to be commented but those comments are wrong and misleading. Unfortunately the comments were never adapted when implementing a new concept in the driver allowing for persistance when killing off the machine. Initially the old concept was about removing the driver file upon machine boot, keeping it in system memory during runtime and rewriting it during machine shutdown.
With the new concept the file is only rewritten at boot time and then kept at disk in undocumented C:\$Extend\$RmMetadata directory. Rewriting serves for randomizing the file name in order to hinder offline analysis by tools such as FRST64 (Farbar Recovery Scan Tool).



===== Information regarding the source code =====

main.c --> allocates non-pagable kernel memory and sets up global variables such as strings
       --> allocates readable-writeable-executable memory and copies the driver image in it
       --> sets up global structures for starting system threads and runs the init thread
       --> unloads itself

cloak.c --> waits for keyboard device to exist
        --> makes payload.c patch keyboard driver object (IRP hook on pKbdDrvObj->MajorFunction[IRP_MJ_READ])
        --> runs callback routines which install various registry and directory callbacks
        --> removes old driver file and creates file with randomized file name

payload.c --> attempts to open or creates keylogger log file
          --> checks keyboard patch and if failed then repatches keyboard driver object
          --> waits for keyboard driver to send an IO Request Packet (IRP) and patches its completion routine pointer
          --> removes the IRP hook so it cannot be detected by Kernel Patch Protection (PatchGuard) or rootkit scanners
          --> upon key press the completion routine runs and repatches the keyboard and extracts the key press from IRP
          --> in a workerthread the key press is written into the keylogger log file



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
