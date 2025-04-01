#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

typedef struct _SIGNER_FILE_INFO {
    DWORD cbSize;
    LPCWSTR pwszFileName;
    HANDLE hFile;
} SIGNER_FILE_INFO, * PSIGNER_FILE_INFO;

typedef struct _SIGNER_SUBJECT_INFO {
    DWORD cbSize;
    DWORD dwSubjectChoice;
    union {
        PSIGNER_FILE_INFO pSignerFileInfo;
    };
} SIGNER_SUBJECT_INFO, * PSIGNER_SUBJECT_INFO;

typedef struct _SIGNER_CERT_STORE_INFO {
    DWORD cbSize;
    PCCERT_CONTEXT pSigningCert;
    DWORD dwCertPolicy;
    HCERTSTORE hCertStore;
} SIGNER_CERT_STORE_INFO, * PSIGNER_CERT_STORE_INFO;

typedef struct _SIGNER_CERT {
    DWORD cbSize;
    DWORD dwCertChoice;
    union {
        PSIGNER_CERT_STORE_INFO pCertStoreInfo;
    };
    HWND hwnd;
} SIGNER_CERT, * PSIGNER_CERT;

typedef struct _SIGNER_SIGNATURE_INFO {
    DWORD cbSize;
    ALG_ID algidHash;
    DWORD dwAttrChoice;
    void* pAttrAuthcode;
    PCRYPT_ATTRIBUTES psAuthenticated;
    PCRYPT_ATTRIBUTES psUnauthenticated;
} SIGNER_SIGNATURE_INFO, * PSIGNER_SIGNATURE_INFO;

#define SIGNER_SUBJECT_FILE 1
#define SIGNER_CERT_STORE 2
#define SIGNER_CERT_POLICY_CHAIN 0x80000000
#define SIGNER_NO_ATTR 0

// Display detailed Windows error messages
void DisplayError(const char* context) {
    DWORD error = GetLastError();
    char buffer[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, error, 0, buffer, sizeof(buffer), NULL);
    printf("%s failed with error %d: %s\n", context, error, buffer);
}

// Read certificate from a PFX file
BOOL ReadCertificateFromFile(const wchar_t* pfxFilePath, const wchar_t* password, HCERTSTORE* hCertStore, PCCERT_CONTEXT* pCertContext) {
    HANDLE hFile = CreateFileW(pfxFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DisplayError("Opening PFX file");
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        DisplayError("Getting PFX file size");
        CloseHandle(hFile);
        return FALSE;
    }

    BYTE* pfxData = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (!pfxData) {
        printf("Memory allocation failed\n");
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, pfxData, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        DisplayError("Reading PFX file");
        HeapFree(GetProcessHeap(), 0, pfxData);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    CRYPT_DATA_BLOB pfxBlob;
    pfxBlob.cbData = fileSize;
    pfxBlob.pbData = pfxData;

    *hCertStore = PFXImportCertStore(&pfxBlob, password, CRYPT_USER_KEYSET);
    HeapFree(GetProcessHeap(), 0, pfxData);

    if (!*hCertStore) {
        DisplayError("Importing PFX");
        return FALSE;
    }

    *pCertContext = CertFindCertificateInStore(*hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, NULL, NULL);
    if (!*pCertContext) {
        DisplayError("Finding certificate");
        CertCloseStore(*hCertStore, 0);
        return FALSE;
    }

    return TRUE;
}

// Sign PE file
BOOL SignPEFile(const wchar_t* filePath, HCERTSTORE hCertStore, PCCERT_CONTEXT pCertContext) {
    SIGNER_FILE_INFO fileInfo = { sizeof(SIGNER_FILE_INFO), filePath, NULL };
    SIGNER_SUBJECT_INFO subjectInfo = { sizeof(SIGNER_SUBJECT_INFO), SIGNER_SUBJECT_FILE, &fileInfo };
    SIGNER_CERT_STORE_INFO certStoreInfo = { sizeof(SIGNER_CERT_STORE_INFO), pCertContext, SIGNER_CERT_POLICY_CHAIN, hCertStore };
    SIGNER_CERT certInfo = { sizeof(SIGNER_CERT), SIGNER_CERT_STORE, &certStoreInfo, NULL };
    SIGNER_SIGNATURE_INFO signatureInfo = { sizeof(SIGNER_SIGNATURE_INFO), CALG_SHA_256, SIGNER_NO_ATTR, NULL, NULL, NULL };

    HMODULE hMsSign32 = LoadLibraryA("mssign32.dll");
    if (!hMsSign32) {
        DisplayError("Loading mssign32.dll");
        return FALSE;
    }

    typedef HRESULT(WINAPI* SIGNERSIGN)(PSIGNER_SUBJECT_INFO, PSIGNER_CERT, PSIGNER_SIGNATURE_INFO, void*);
    SIGNERSIGN pfnSignerSign = (SIGNERSIGN)GetProcAddress(hMsSign32, "SignerSign");
    if (!pfnSignerSign) {
        DisplayError("Getting SignerSign function");
        FreeLibrary(hMsSign32);
        return FALSE;
    }

    HRESULT hr = pfnSignerSign(&subjectInfo, &certInfo, &signatureInfo, NULL);
    FreeLibrary(hMsSign32);

    if (FAILED(hr)) {
        printf("Signing failed with HRESULT 0x%08x\n", hr);
        return FALSE;
    }

    printf("File signed successfully!\n");
    return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        printf("Usage: PEFileSigner.exe <PE_file_path> <certificate_path> [certificate_password]\n");
        return 1;
    }

    HCERTSTORE hCertStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;

    if (!ReadCertificateFromFile(argv[2], argc > 3 ? argv[3] : L"", &hCertStore, &pCertContext)) {
        return 1;
    }

    BOOL success = SignPEFile(argv[1], hCertStore, pCertContext);

    if (pCertContext) CertFreeCertificateContext(pCertContext);
    if (hCertStore) CertCloseStore(hCertStore, 0);

    return success ? 0 : 1;
}
