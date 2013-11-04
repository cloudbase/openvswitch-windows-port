#include <unistd.h>
#include <signal.h>
#include <Windows.h>
#include <config.h>
#include <tlhelp32.h>

unsigned int getpagesize(void)
{
    SYSTEM_INFO info_temp;
    GetSystemInfo(&info_temp);
    long int value = info_temp.dwPageSize;

    return value;
}
int GetNumLogicalProcessors(void)
{
    SYSTEM_INFO info_temp;
    GetSystemInfo(&info_temp);
    long int n_cores = info_temp.dwNumberOfProcessors;
    return n_cores;
}
long sysconf(int name)
{
    long val = -1;
    long val2 = -1;
    SYSTEM_INFO sysInfo;
    MEMORYSTATUSEX status;

    switch (name)
    {
    case _SC_NPROCESSORS_ONLN:
        val = GetNumLogicalProcessors();
        break;

    case _SC_PAGESIZE:
        GetSystemInfo(&sysInfo);
        val = sysInfo.dwPageSize;
        break;

    case _SC_PHYS_PAGES:
        status.dwLength = sizeof(status);
        val2 = sysconf(_SC_PAGESIZE);
        if (GlobalMemoryStatusEx(&status) && val2 != -1)
            val = status.ullTotalPhys / val2;
        break;
    default:
        break;
    }

    return val;
}

int getloadavg(double loadavg[], int nelem)
{
    int i;

    for (i = 0; i < nelem; i++) {
        loadavg[i] = 0.0;
    }
    return i;
}

int getppid()
{
    HANDLE hProcess, thProcess;
    PROCESSENTRY32 ProcessEntry;

    thProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (thProcess == INVALID_HANDLE_VALUE) {
        _set_errno(ENOSYS);
        return -1;
    }
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32);
    ProcessEntry.th32ParentProcessID = 0;
    if (!Process32First(thProcess, &ProcessEntry)) {
        _set_errno(ENOSYS);
        return -1;
    }
    CloseHandle(thProcess);
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessEntry.th32ProcessID);
    if (hProcess == NULL) {
        _set_errno(ENOSYS);
        return -1;
    }
    CloseHandle(hProcess);
    return ProcessEntry.th32ParentProcessID;
}
/*--------------------------------------------------------------------------*/
#include <WinNT.h>
#include <setjmp.h>
/*--------------------------------------------------------------------------*/
typedef LONG NTSTATUS;
/*--------------------------------------------------------------------------*/
typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG ProcessId;
    UCHAR ObjectTypeNumber;
    UCHAR Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
/*--------------------------------------------------------------------------*/
typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PVOID /* really PUNICODE_STRING */  ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;       /* type SECURITY_DESCRIPTOR */
    PVOID SecurityQualityOfService; /* type SECURITY_QUALITY_OF_SERVICE */
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
/*--------------------------------------------------------------------------*/
typedef enum _THREAD_INFORMATION_CLASS1
{
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger
} THREAD_INFORMATION_CLASS1, *PTHREAD_INFORMATION_CLASS1;

typedef enum _MEMORY_INFORMATION_
{
    MemoryBasicInformation,
    MemoryWorkingSetList,
    MemorySectionName,
    MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;
/*--------------------------------------------------------------------------*/
typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
/*--------------------------------------------------------------------------*/
typedef struct _USER_STACK
{
    PVOID FixedStackBase;
    PVOID FixedStackLimit;
    PVOID ExpandableStackBase;
    PVOID ExpandableStackLimit;
    PVOID ExpandableStackBottom;
} USER_STACK, *PUSER_STACK;
/*--------------------------------------------------------------------------*/
typedef LONG KPRIORITY;
typedef ULONG_PTR KAFFINITY;
typedef KAFFINITY *PKAFFINITY;
/*--------------------------------------------------------------------------*/
typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;
/*--------------------------------------------------------------------------*/
typedef enum _SYSTEM_INFORMATION_CLASS { SystemHandleInformation = 0x10 } SYSTEM_INFORMATION_CLASS;
/*--------------------------------------------------------------------------*/
typedef NTSTATUS(NTAPI *ZwWriteVirtualMemory_t)(IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress,
    IN PVOID                Buffer,
    IN ULONG                NumberOfBytesToWrite,
    OUT PULONG              NumberOfBytesWritten OPTIONAL);
/*--------------------------------------------------------------------------*/
typedef NTSTATUS(NTAPI *ZwCreateProcess_t)(OUT PHANDLE            ProcessHandle,
    IN  ACCESS_MASK        DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    IN  HANDLE             InheriteFromProcessHandle,
    IN  BOOLEAN            InheritHandles,
    IN  HANDLE             SectionHandle    OPTIONAL,
    IN  HANDLE             DebugPort        OPTIONAL,
    IN  HANDLE             ExceptionPort    OPTIONAL);
/*--------------------------------------------------------------------------*/
typedef NTSTATUS(WINAPI *ZwQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);
typedef NTSTATUS(NTAPI *ZwQueryVirtualMemory_t)(IN  HANDLE ProcessHandle,
    IN  PVOID BaseAddress,
    IN  MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN  ULONG MemoryInformationLength,
    OUT PULONG ReturnLength OPTIONAL);
/*--------------------------------------------------------------------------*/
typedef NTSTATUS(NTAPI *ZwGetContextThread_t)(IN HANDLE ThreadHandle, OUT PCONTEXT Context);
typedef NTSTATUS(NTAPI *ZwCreateThread_t)(OUT PHANDLE ThreadHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    IN  HANDLE ProcessHandle,
    OUT PCLIENT_ID ClientId,
    IN  PCONTEXT ThreadContext,
    IN  PUSER_STACK UserStack,
    IN  BOOLEAN CreateSuspended);
/*--------------------------------------------------------------------------*/
typedef NTSTATUS(NTAPI *ZwResumeThread_t)(IN HANDLE ThreadHandle, OUT PULONG SuspendCount OPTIONAL);
typedef NTSTATUS(NTAPI *ZwClose_t)(IN HANDLE ObjectHandle);
typedef NTSTATUS(NTAPI *ZwQueryInformationThread_t)(IN HANDLE               ThreadHandle,
    IN THREAD_INFORMATION_CLASS ThreadInformationClass,
    OUT PVOID               ThreadInformation,
    IN ULONG                ThreadInformationLength,
    OUT PULONG              ReturnLength OPTIONAL);
/*--------------------------------------------------------------------------*/
static ZwCreateProcess_t ZwCreateProcess = NULL;
static ZwQuerySystemInformation_t ZwQuerySystemInformation = NULL;
static ZwQueryVirtualMemory_t ZwQueryVirtualMemory = NULL;
static ZwCreateThread_t ZwCreateThread = NULL;
static ZwGetContextThread_t ZwGetContextThread = NULL;
static ZwResumeThread_t ZwResumeThread = NULL;
static ZwClose_t ZwClose = NULL;
static ZwQueryInformationThread_t ZwQueryInformationThread = NULL;
static ZwWriteVirtualMemory_t ZwWriteVirtualMemory = NULL;
/*--------------------------------------------------------------------------*/
#define NtCurrentProcess() ((HANDLE)-1)
#define NtCurrentThread() ((HANDLE) -2)
/* we use really the Nt versions - so the following is just for completeness */
#define ZwCurrentProcess() NtCurrentProcess()     
#define ZwCurrentThread() NtCurrentThread()
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
/*--------------------------------------------------------------------------*/
/* setjmp env for the jump back into the fork() function */
static jmp_buf jenv;
/*--------------------------------------------------------------------------*/
/* entry point for our child thread process - just longjmp into fork */
static int child_entry(void)
{
    longjmp(jenv, 1);
    return 0;
}
/*--------------------------------------------------------------------------*/
static BOOL haveLoadedFunctionsForFork(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll");
    if (ntdll == NULL) return FALSE;

    if (ZwCreateProcess && ZwQuerySystemInformation && ZwQueryVirtualMemory &&
        ZwCreateThread && ZwGetContextThread && ZwResumeThread &&
        ZwQueryInformationThread && ZwWriteVirtualMemory && ZwClose)
    {
        return TRUE;
    }

    ZwCreateProcess = (ZwCreateProcess_t)GetProcAddress(ntdll, "ZwCreateProcess");
    ZwQuerySystemInformation = (ZwQuerySystemInformation_t)GetProcAddress(ntdll, "ZwQuerySystemInformation");
    ZwQueryVirtualMemory = (ZwQueryVirtualMemory_t)GetProcAddress(ntdll, "ZwQueryVirtualMemory");
    ZwCreateThread = (ZwCreateThread_t)GetProcAddress(ntdll, "ZwCreateThread");
    ZwGetContextThread = (ZwGetContextThread_t)GetProcAddress(ntdll, "ZwGetContextThread");
    ZwResumeThread = (ZwResumeThread_t)GetProcAddress(ntdll, "ZwResumeThread");
    ZwQueryInformationThread = (ZwQueryInformationThread_t)GetProcAddress(ntdll, "ZwQueryInformationThread");
    ZwWriteVirtualMemory = (ZwWriteVirtualMemory_t)GetProcAddress(ntdll, "ZwWriteVirtualMemory");
    ZwClose = (ZwClose_t)GetProcAddress(ntdll, "ZwClose");

    if (ZwCreateProcess && ZwQuerySystemInformation && ZwQueryVirtualMemory &&
        ZwCreateThread && ZwGetContextThread && ZwResumeThread &&
        ZwQueryInformationThread && ZwWriteVirtualMemory && ZwClose)
    {
        return TRUE;
    }
    else
    {
        ZwCreateProcess = NULL;
        ZwQuerySystemInformation = NULL;
        ZwQueryVirtualMemory = NULL;
        ZwCreateThread = NULL;
        ZwGetContextThread = NULL;
        ZwResumeThread = NULL;
        ZwQueryInformationThread = NULL;
        ZwWriteVirtualMemory = NULL;
        ZwClose = NULL;
    }
    return FALSE;
}
/*--------------------------------------------------------------------------*/
pid_t fork(void)
{
    /*
    HANDLE hProcess = 0, hThread = 0;
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    MEMORY_BASIC_INFORMATION mbi;
    CLIENT_ID cid;
    USER_STACK stack;
    PNT_TIB tib;
    THREAD_BASIC_INFORMATION tbi;

    CONTEXT context = { CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS | CONTEXT_FLOATING_POINT };
    */
    //if (setjmp(jenv) != 0) return 0; /* return as a child */

    /* check whether the entry points are initilized and get them if necessary */
    //if (!ZwCreateProcess && !haveLoadedFunctionsForFork()) return -1;

    /* create forked process */
    //ZwCreateProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, NtCurrentProcess(), TRUE, 0, 0, 0);

    /* set the Eip for the child process to our child function */
    //ZwGetContextThread(NtCurrentThread(), &context);

    /* In x64 the Eip and Esp are not present, their x64 counterparts are Rip and
    Rsp respectively.
    */
#if _WIN64
    //context.Rip = (ULONG)child_entry;
#else
    //context.Eip = (ULONG)child_entry;
#endif

#if _WIN64
    //ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)context.Rsp, MemoryBasicInformation, &mbi, sizeof mbi, 0);
#else
    //ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)context.Esp, MemoryBasicInformation, &mbi, sizeof mbi, 0);
#endif
    /*
    stack.FixedStackBase = 0;
    stack.FixedStackLimit = 0;
    stack.ExpandableStackBase = (PCHAR)mbi.BaseAddress + mbi.RegionSize;
    stack.ExpandableStackLimit = mbi.BaseAddress;
    stack.ExpandableStackBottom = mbi.AllocationBase;
    */

    /* create thread using the modified context and stack */
    //ZwCreateThread(&hThread, THREAD_ALL_ACCESS, &oa, hProcess, &cid, &context, &stack, TRUE);

    /* copy exception table */
    //ZwQueryInformationThread(NtCurrentThread(), (THREAD_INFORMATION_CLASS)ThreadBasicInformation, &tbi, sizeof tbi, 0);
    //tib = (PNT_TIB)tbi.TebBaseAddress;
    //ZwQueryInformationThread(hThread, (THREAD_INFORMATION_CLASS)ThreadBasicInformation, &tbi, sizeof tbi, 0);
    //ZwWriteVirtualMemory(hProcess, tbi.TebBaseAddress, &tib->ExceptionList, sizeof tib->ExceptionList, 0);
    //InformCsrss(hProcess, hThread, cid.UniqueProcess, cid.UniqueThread);

    /* start (resume really) the child */
    //ZwResumeThread(hThread, 0);

    /* clean up */
    //ZwClose(hThread);
    //ZwClose(hProcess);

    /* exit with child's pid */
    //return (int)cid.UniqueProcess;
    return 0;
}
/*--------------------------------------------------------------------------*/

int kill(pid_t pid, int sig)
{
    int res = 0;
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);

    if (hProcess == NULL) {
        _set_errno(ENOSYS);
        return -1;
    }
    switch (sig) {
    case SIGABRT:
    case SIGKILL:
        if (!TerminateProcess(hProcess, -1)) {
            _set_errno(ENOSYS);
            res = -1;
        }
        break;
    case 0:
        break;
    case SIGHUP:
    case SIGINT:
    case SIGQUIT:
    case SIGALRM:
    case SIGTERM:
    default:
        _set_errno(EINVAL);
        res = -1;
        break;
    }
    CloseHandle(hProcess);
    return res;
}
BOOL link(char* pszNewLinkName, char*pszExistingFileName)
    {
    BOOL f;
    f = CreateHardLink(pszExistingFileName, pszNewLinkName , NULL);

    if (!f)
        {
        return -1;
        }
    return 0;
    }
long pathconf(char* smth, int n)
    {
    return _MAX_PATH;
    }

#define SIGINT_MASK    1 
#define SIGILL_MASK    2 
#define SIGFPE_MASK    4 
#define SIGSEGV_MASK   8 
#define SIGTERM_MASK  16 
#define SIGBREAK_MASK 32 
#define SIGABRT_MASK  64 

// The sigaddset call adds the individual signal specified to the signal set pointed to by set. 
int sigaddset(sigset_t *set, int signo)
{
    switch (signo)
    {
    case SIGINT:
        *set |= SIGINT_MASK;
        break;
    case SIGILL:
        *set |= SIGILL_MASK;
        break;
    case SIGFPE:
        *set |= SIGFPE_MASK;
        break;
    case SIGSEGV:
        *set |= SIGSEGV_MASK;
        break;
    case SIGTERM:
        *set |= SIGTERM_MASK;
        break;
    case SIGBREAK:
        *set |= SIGBREAK_MASK;
        break;
    case SIGABRT:
    case SIGABRT_COMPAT:
        *set |= SIGABRT_MASK;
        break;
    }

    return 0;
}

// The sigdelset call removes the individual signal specified from the signal set pointed to by set. 
int sigdelset(sigset_t *set, int signo)
{
    switch (signo)
    {
    case SIGINT:
        *set &= ~(DWORD)SIGINT_MASK;
        break;
    case SIGILL:
        *set &= ~(DWORD)SIGILL_MASK;
        break;
    case SIGFPE:
        *set &= ~(DWORD)SIGFPE_MASK;
        break;
    case SIGSEGV:
        *set &= ~(DWORD)SIGSEGV_MASK;
        break;
    case SIGTERM:
        *set &= ~(DWORD)SIGTERM_MASK;
        break;
    case SIGBREAK:
        *set &= ~(DWORD)SIGBREAK_MASK;
        break;
    case SIGABRT:
    case SIGABRT_COMPAT:
        *set &= ~(DWORD)SIGABRT_MASK;
        break;
    }

    return 0;
}


// The sigemptyset call creates a new mask set and excludes all signals from it. 
int sigemptyset(sigset_t *set)
{
    *set = 0;
    return 0;
}

// The sigfillset call creates a new mask set and includes all signals in it. 
int sigfillset(sigset_t *set)
{
    *set = 0xffffffff;
    return 0;
}

// The sigismember call tests the signal mask set pointed to by set for the existence of the specified signal (signo). 
int sigismember(const sigset_t *set, int signo)
{
    switch (signo)
    {
    case SIGINT:
        return *set & SIGINT_MASK;
    case SIGILL:
        return *set & SIGILL_MASK;
    case SIGFPE:
        return *set & SIGFPE_MASK;
    case SIGSEGV:
        return *set & SIGSEGV_MASK;
    case SIGTERM:
        return *set & SIGTERM_MASK;
    case SIGBREAK:
        return *set & SIGBREAK_MASK;
    case SIGABRT:
    case SIGABRT_COMPAT:
        return *set & SIGABRT_MASK;
    }

    return 0;
}

// The strsignal() function returns a string describing the signal number passed in the argument sig. 
char *strsignal(int sig)
{
    switch (sig)
    {
    case SIGINT:
        return "SIGINT";
        break;
    case SIGILL:
        return "SIGILL";
        break;
    case SIGFPE:
        return "SIGFPE";
        break;
    case SIGSEGV:
        return "SIGSEGV";
        break;
    case SIGTERM:
        return "SIGTERM";
        break;
    case SIGBREAK:
        return "SIGBREAK";
        break;
    case SIGABRT:
    case SIGABRT_COMPAT:
        return "SIGABRT";
        break;
    }

    return 0;
}

struct sigaction sigaction_table[NSIG] = { 0 };

int
sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    switch (signum)
    {
    case SIGINT:
    case SIGILL:
    case SIGFPE:
    case SIGSEGV:
    case SIGTERM:
    case SIGBREAK:
    case SIGABRT:
        /* signal is valid, do nothing */
        break;
    default:
        /* signal is invalid */
        errno = EINVAL;
        return 0;
    }

    if (oldact)
    {
        /* save old action */
        oldact->sa_handler = sigaction_table[signum].sa_handler;
        oldact->sa_sigaction = sigaction_table[signum].sa_sigaction;
        oldact->sa_mask = sigaction_table[signum].sa_mask;
        oldact->sa_flags = sigaction_table[signum].sa_flags;
        /*oldact->sa_restorer = sigaction_table[signum].sa_restorer;*/
    }

    if (act)
    {
        /* set new action */
        sigaction_table[signum].sa_handler = act->sa_handler;
        sigaction_table[signum].sa_sigaction = act->sa_sigaction;
        sigaction_table[signum].sa_mask = act->sa_mask;
        sigaction_table[signum].sa_flags = act->sa_flags;
        /*sigaction_table[signum].sa_restorer = act->sa_restorer;*/

        signal(signum, act->sa_handler);
    }

    return 0;
}

int sigprocmask(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    return 0;
}

char* strsep(char** stringp, const char* delim)
{
	char* start = *stringp;
	char* p;

	p = (start != NULL) ? strpbrk(start, delim) : NULL;

	if (p == NULL)
	{
		*stringp = NULL;
	}
	else
	{
		*p = '\0';
		*stringp = p + 1;
	}

	return start;
}