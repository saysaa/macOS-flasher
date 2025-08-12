#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <winioctl.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define HASH_SIZE 32
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

static void print_human_size(unsigned long long s) {
    const char *units[] = {"B","KB","MB","GB","TB"};
    double val = (double)s;
    int i = 0;
    while (val >= 1024.0 && i < 4) { val /= 1024.0; i++; }
    printf("%.2f %s", val, units[i]);
}

int IsRunAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

static bool get_physical_device_number_from_driveletter(char driveLetter, DWORD *outDevNum) {
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "\\\\.\\%c:", driveLetter);
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;

    STORAGE_DEVICE_NUMBER sdn;
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &sdn, sizeof(sdn), &bytes, NULL);
    CloseHandle(h);
    if (!ok) return false;
    *outDevNum = sdn.DeviceNumber;
    return true;
}

static bool get_disk_size_by_physicaldrive(DWORD devNum, unsigned long long *outSize) {
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "\\\\.\\PhysicalDrive%u", devNum);
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;

    GET_LENGTH_INFORMATION gli;
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &gli, sizeof(gli), &bytes, NULL);
    CloseHandle(h);
    if (!ok) return false;
    *outSize = (unsigned long long)gli.Length.QuadPart;
    return true;
}

/* --- SHA-256 helpers using BCrypt --- */
static bool sha256_file_a(const char *path, unsigned char out[HASH_SIZE]) {
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return false;

    BCRYPT_ALG_HANDLE hAlg = 0;
    BCRYPT_HASH_HANDLE hHash = 0;
    NTSTATUS status;
    DWORD cbData = 0, cbHash = 0, cbHashObject = 0;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) { CloseHandle(f); return false; }
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg,0); CloseHandle(f); return false; }
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg,0); CloseHandle(f); return false; }

    PBYTE pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
    if (!NT_SUCCESS(status)) { HeapFree(GetProcessHeap(),0,pbHashObject); BCryptCloseAlgorithmProvider(hAlg,0); CloseHandle(f); return false; }

    const DWORD BUFSZ = 1024 * 1024;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, BUFSZ);
    DWORD read = 0;
    while (ReadFile(f, buf, BUFSZ, &read, NULL) && read > 0) {
        status = BCryptHashData(hHash, buf, read, 0);
        if (!NT_SUCCESS(status)) break;
    }
    status = BCryptFinishHash(hHash, out, HASH_SIZE, 0);

    HeapFree(GetProcessHeap(),0,buf);
    BCryptDestroyHash(hHash);
    HeapFree(GetProcessHeap(),0,pbHashObject);
    BCryptCloseAlgorithmProvider(hAlg,0);
    CloseHandle(f);
    return NT_SUCCESS(status);
}

static bool sha256_handle_by_reading(HANDLE hDevice, unsigned long long len, unsigned char out[HASH_SIZE]) {
    LARGE_INTEGER li; li.QuadPart = 0;
    if (!SetFilePointerEx(hDevice, li, NULL, FILE_BEGIN)) return false;

    BCRYPT_ALG_HANDLE hAlg = 0;
    BCRYPT_HASH_HANDLE hHash = 0;
    NTSTATUS status;
    DWORD cbData = 0, cbHashObject = 0;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return false;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg,0); return false; }

    PBYTE pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
    if (!NT_SUCCESS(status)) { HeapFree(GetProcessHeap(),0,pbHashObject); BCryptCloseAlgorithmProvider(hAlg,0); return false; }

    const DWORD BUFSZ = 1024 * 1024;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, BUFSZ);
    unsigned long long remaining = len;
    DWORD toRead = 0, read = 0;
    while (remaining > 0) {
        toRead = (DWORD)((remaining > BUFSZ) ? BUFSZ : (DWORD)remaining);
        if (!ReadFile(hDevice, buf, toRead, &read, NULL) || read == 0) break;
        status = BCryptHashData(hHash, buf, read, 0);
        if (!NT_SUCCESS(status)) break;
        remaining -= read;
    }
    status = BCryptFinishHash(hHash, out, HASH_SIZE, 0);

    HeapFree(GetProcessHeap(),0,buf);
    BCryptDestroyHash(hHash);
    HeapFree(GetProcessHeap(),0,pbHashObject);
    BCryptCloseAlgorithmProvider(hAlg,0);
    return NT_SUCCESS(status);
}

/* --- Flash core --- */
int flash_iso_to_physicaldrive(const char *isoPath, DWORD physDevNum) {
    char physPath[MAX_PATH];
    snprintf(physPath, sizeof(physPath), "\\\\.\\PhysicalDrive%u", physDevNum);

    HANDLE hISO = CreateFileA(isoPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hISO == INVALID_HANDLE_VALUE) { printf("Cannot open ISO: %s\n", isoPath); return 1; }

    LARGE_INTEGER li;
    if (!GetFileSizeEx(hISO, &li)) { CloseHandle(hISO); printf("Failed get ISO size\n"); return 1; }
    unsigned long long isoSize = (unsigned long long)li.QuadPart;

    HANDLE hDev = CreateFileA(physPath, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, 0, NULL);
    if (hDev == INVALID_HANDLE_VALUE) { CloseHandle(hISO); printf("Cannot open device %s (need admin)\n", physPath); return 1; }

    unsigned long long devSize = 0;
    if (!get_disk_size_by_physicaldrive(physDevNum, &devSize)) { CloseHandle(hISO); CloseHandle(hDev); printf("Cannot get device size\n"); return 1; }
    if (devSize < isoSize) { printf("ISO is larger than device capacity.\n"); CloseHandle(hISO); CloseHandle(hDev); return 1; }

    unsigned char isoHash[HASH_SIZE], devHash[HASH_SIZE];
    printf("Computing ISO SHA-256...\n");
    if (!sha256_file_a(isoPath, isoHash)) { printf("Failed to hash ISO\n"); CloseHandle(hISO); CloseHandle(hDev); return 1; }

    const DWORD BUFSZ = 1024 * 1024;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, BUFSZ);
    DWORD read=0, written=0;
    unsigned long long total = 0;
    LARGE_INTEGER zero; zero.QuadPart = 0;
    SetFilePointerEx(hDev, zero, NULL, FILE_BEGIN);
    SetFilePointerEx(hISO, zero, NULL, FILE_BEGIN);

    printf("Writing ISO to %s ...\n", physPath);
    while (ReadFile(hISO, buf, BUFSZ, &read, NULL) && read > 0) {
        if (!WriteFile(hDev, buf, read, &written, NULL) || written != read) {
            printf("\nWrite error\n");
            HeapFree(GetProcessHeap(),0,buf);
            CloseHandle(hISO); CloseHandle(hDev);
            return 1;
        }
        total += written;
        int pct = (int)((total * 100) / isoSize);
        printf("\r%llu / %llu bytes  (%d%%)   ", total, isoSize, pct);
        fflush(stdout);
    }
    printf("\nFlushing buffers...\n");
    FlushFileBuffers(hDev);

    printf("Verifying (SHA-256 of device first %llu bytes)...\n", isoSize);
    if (!sha256_handle_by_reading(hDev, isoSize, devHash)) {
        printf("Failed to hash device\n");
        HeapFree(GetProcessHeap(),0,buf);
        CloseHandle(hISO); CloseHandle(hDev);
        return 1;
    }

    if (memcmp(isoHash, devHash, HASH_SIZE) == 0) {
        printf("Verification OK: SHA-256 matches.\n");
    } else {
        printf("Verification FAILED: hashes differ!\n");
        printf("ISO SHA-256: ");
        for (int i=0;i<HASH_SIZE;i++) printf("%02x", isoHash[i]); printf("\n");
        printf("DEV SHA-256: ");
        for (int i=0;i<HASH_SIZE;i++) printf("%02x", devHash[i]); printf("\n");
    }

    HeapFree(GetProcessHeap(),0,buf);
    CloseHandle(hISO); CloseHandle(hDev);
    return 0;
}

int main(void) {
    if (!IsRunAsAdmin()) {
        SHELLEXECUTEINFO sei = { sizeof(sei) };
        sei.lpVerb = "runas";
        sei.lpFile = "MacOS_flasher.exe"; // nom du .exe
        sei.nShow = SW_SHOWNORMAL;

        if (!ShellExecuteEx(&sei)) {
            MessageBox(NULL, "ELEVATION PRIVILEGE ERROR: Please execute MacOS_flasher in admin.", "Erreur", MB_ICONERROR);
            return 1;
        }
        return 0;
    }
    SetConsoleTitle("| MacOS-flasher 1.0");
    printf(">> MacOS-flasher - Saysaa\n");
    printf("-------------------------------------------------\n");
    printf("Scanning removable drives (A:..Z:)...\n");
    bool foundAny = false;
    for (char d='A'; d<='Z'; d++) {
        char root[4] = {d,':','\\','\0'};
        UINT type = GetDriveTypeA(root);
        if (type == DRIVE_REMOVABLE || type == DRIVE_FIXED) {
            DWORD devNum;
            if (get_physical_device_number_from_driveletter(d, &devNum)) {
                unsigned long long devSize = 0;
                if (!get_disk_size_by_physicaldrive(devNum, &devSize)) continue;
                printf("Drive %c: -> PhysicalDrive%u (", d, devNum);
                print_human_size(devSize);
                printf(")\n");
                foundAny = true;
            }
        }
    }
    if (!foundAny) {
        printf("No removable drives detected. Insert a USB drive and try again.\n");
        system("pause");
        return 1;
    }

    char isoPath[MAX_PATH];
    char driveLetterStr[8];
    printf("\nEnter full path to ISO (e.g. C:\\path\\image.iso):\n> ");
    if (!fgets(isoPath, sizeof(isoPath), stdin)) { system("pause"); return 1; }
    isoPath[strcspn(isoPath, "\r\n")] = 0;

    printf("Enter target drive letter (example: E):\n> ");
    if (!fgets(driveLetterStr, sizeof(driveLetterStr), stdin)) { system("pause"); return 1; }
    char driveLetter = driveLetterStr[0];
    if (driveLetter >= 'a' && driveLetter <= 'z') driveLetter -= 32;

    DWORD devNum;
    if (!get_physical_device_number_from_driveletter(driveLetter, &devNum)) {
        printf("Cannot map drive letter %c to a physical device.\n", driveLetter);
        system("pause");
        return 1;
    }
    unsigned long long devSize=0;
    if (!get_disk_size_by_physicaldrive(devNum, &devSize)) {
        printf("Cannot read device size.\n");
        system("pause");
        return 1;
    }

    printf("\nWARNING: You are about to overwrite the entire device PhysicalDrive%u (", devNum);
    print_human_size(devSize);
    printf(") from ISO: %s\n", isoPath);
    printf("Type 'YES' to confirm: ");
    char confirm[8];
    if (!fgets(confirm, sizeof(confirm), stdin)) { system("pause"); return 1; }
    confirm[strcspn(confirm, "\r\n")] = 0;
    if (strcmp(confirm, "YES") != 0) {
        printf("Aborted by user.\n");
        system("pause");
        return 0;
    }

    int rc = flash_iso_to_physicaldrive(isoPath, devNum);
    if (rc == 0) printf("Done.\n");
    else printf("Failed with code %d\n", rc);

    system("pause");
    return rc;
}
