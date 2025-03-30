#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string>

#pragma comment(lib, "crypt32.lib")

// Structure definitions for Signer API
typedef struct _SIGNER_FILE_INFO {
    DWORD       cbSize;
    LPCWSTR     pwszFileName;
    HANDLE      hFile;
} SIGNER_FILE_INFO, * PSIGNER_FILE_INFO;

typedef struct _SIGNER_BLOB_INFO {
    DWORD       cbSize;
    GUID* pGuidSubject;
    DWORD       cbBlob;
    BYTE* pbBlob;
    LPCWSTR     pwszDisplayName;
} SIGNER_BLOB_INFO, * PSIGNER_BLOB_INFO;

typedef enum _SIGNER_SUBJECT_CHOICE {
    SIGNER_SUBJECT_FILE = 1,
    SIGNER_SUBJECT_BLOB
} SIGNER_SUBJECT_CHOICE, * PSIGNER_SUBJECT_CHOICE;

typedef struct _SIGNER_SUBJECT_INFO {
    DWORD                   cbSize;
    DWORD* pdwIndex;
    SIGNER_SUBJECT_CHOICE   dwSubjectChoice;
    union {
        PSIGNER_FILE_INFO   pSignerFileInfo;
        PSIGNER_BLOB_INFO   pSignerBlobInfo;
    };
} SIGNER_SUBJECT_INFO, * PSIGNER_SUBJECT_INFO;

typedef enum _SIGNER_CERT_POLICY {
    SIGNER_CERT_POLICY_CHAIN = 1,
    SIGNER_CERT_POLICY_CHAIN_NO_ROOT,
    SIGNER_CERT_POLICY_STORE
} SIGNER_CERT_POLICY, * PSIGNER_CERT_POLICY;

typedef struct _SIGNER_CERT_STORE_INFO {
    DWORD                   cbSize;
    PCCERT_CONTEXT          pSigningCert;
    DWORD                   dwCertPolicy;
    HCERTSTORE              hCertStore;
} SIGNER_CERT_STORE_INFO, * PSIGNER_CERT_STORE_INFO;

typedef struct _SIGNER_SPC_CHAIN_INFO {
    DWORD                   cbSize;
    LPCWSTR                 pwszSpcFile;
    DWORD                   dwCertPolicy;
    HCERTSTORE              hCertStore;
} SIGNER_SPC_CHAIN_INFO, * PSIGNER_SPC_CHAIN_INFO;

typedef enum _SIGNER_CERT_CHOICE {
    SIGNER_CERT_STORE = 1,
    SIGNER_CERT_SPC,
    SIGNER_CERT_CUSTOM
} SIGNER_CERT_CHOICE, * PSIGNER_CERT_CHOICE;

typedef struct _SIGNER_CERT {
    DWORD                   cbSize;
    SIGNER_CERT_CHOICE      dwCertChoice;
    union {
        PSIGNER_CERT_STORE_INFO     pCertStoreInfo;
        PSIGNER_SPC_CHAIN_INFO      pSpcChainInfo;
        void* pCustomCertInfo;
    };
    HWND                    hwnd;
} SIGNER_CERT, * PSIGNER_CERT;

typedef struct _SIGNER_ATTR_AUTHCODE {
    DWORD                   cbSize;
    BOOL                    fCommercial;
    BOOL                    fIndividual;
    LPCWSTR                 pwszName;
    LPCWSTR                 pwszInfo;
} SIGNER_ATTR_AUTHCODE, * PSIGNER_ATTR_AUTHCODE;

typedef enum _SIGNER_SIGNATURE_ATTRIBUTE_CHOICE {
    SIGNER_NO_ATTR = 0,
    SIGNER_AUTHCODE_ATTR
} SIGNER_SIGNATURE_ATTRIBUTE_CHOICE, * PSIGNER_SIGNATURE_ATTRIBUTE_CHOICE;

typedef struct _SIGNER_SIGNATURE_INFO {
    DWORD                               cbSize;
    ALG_ID                              algidHash;
    DWORD                               dwAttrChoice;
    union {
        PSIGNER_ATTR_AUTHCODE           pAttrAuthcode;
    };
    PCRYPT_ATTRIBUTES                   psAuthenticated;
    PCRYPT_ATTRIBUTES                   psUnauthenticated;
} SIGNER_SIGNATURE_INFO, * PSIGNER_SIGNATURE_INFO;

typedef struct _SIGNER_CONTEXT_INFO {
    DWORD       cbSize;
    DWORD       cbBlob;
    BYTE* pbBlob;
    void* pSignerContextInfo;
} SIGNER_CONTEXT_INFO, * PSIGNER_CONTEXT_INFO;

typedef struct _SIGNER_CONTEXT {
    DWORD       cbSize;
    DWORD       cbBlob;
    BYTE* pbBlob;
} SIGNER_CONTEXT, * PSIGNER_CONTEXT;

// Function to load a certificate from a PFX file
PCCERT_CONTEXT LoadCertificateFromFile(const std::wstring& certFilePath, const std::wstring& password, HCERTSTORE* phStore) {
    // Open the certificate file
    HANDLE hFile = CreateFileW(
        certFilePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open certificate file. Error: 0x%08x\n", GetLastError());
        return NULL;
    }

    // Get file size
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("Failed to get certificate file size. Error: 0x%08x\n", GetLastError());
        CloseHandle(hFile);
        return NULL;
    }

    // Allocate memory for certificate data
    BYTE* certData = new BYTE[fileSize];
    DWORD bytesRead = 0;

    // Read certificate file
    if (!ReadFile(hFile, certData, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("Failed to read certificate file. Error: 0x%08x\n", GetLastError());
        CloseHandle(hFile);
        delete[] certData;
        return NULL;
    }

    CloseHandle(hFile);

    // Create a memory store to hold the certificate
    *phStore = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_STORE_CREATE_NEW_FLAG,
        NULL);

    if (!*phStore) {
        printf("Failed to create certificate store. Error: 0x%08x\n", GetLastError());
        delete[] certData;
        return NULL;
    }

    // Import the PFX data
    CRYPT_DATA_BLOB pfxBlob;
    pfxBlob.cbData = fileSize;
    pfxBlob.pbData = certData;

    // Get the PFX import flags
    DWORD dwFlags = CRYPT_USER_KEYSET;

    // Import the PFX file into the store
    if (!PFXImportCertStore(
        &pfxBlob,
        password.empty() ? NULL : password.c_str(),
        dwFlags)) {
        printf("Failed to import PFX. Error: 0x%08x\n", GetLastError());
        CertCloseStore(*phStore, 0);
        delete[] certData;
        return NULL;
    }

    // Get the certificate context (first certificate with private key)
    PCCERT_CONTEXT pCertContext = NULL;
    pCertContext = CertFindCertificateInStore(
        *phStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        CERT_FIND_HAS_PRIVATE_KEY,
        CERT_FIND_ANY,
        NULL,
        NULL);

    delete[] certData;

    if (!pCertContext) {
        printf("No certificate with private key found. Error: 0x%08x\n", GetLastError());
        CertCloseStore(*phStore, 0);
        return NULL;
    }

    return pCertContext;
}

bool SignFile(const std::wstring& filePath, const std::wstring& certFilePath, const std::wstring& password) {
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    bool result = false;
    DWORD dwIndex = 0;  // Required for SIGNER_SUBJECT_INFO

    // Load certificate from file
    pCertContext = LoadCertificateFromFile(certFilePath, password, &hStore);
    if (!pCertContext) {
        return false;
    }

    // Initialize signing parameters
    SIGNER_FILE_INFO fileInfo = { 0 };
    fileInfo.cbSize = sizeof(SIGNER_FILE_INFO);
    fileInfo.pwszFileName = filePath.c_str();
    fileInfo.hFile = NULL;

    SIGNER_SUBJECT_INFO subjectInfo = { 0 };
    subjectInfo.cbSize = sizeof(SIGNER_SUBJECT_INFO);
    subjectInfo.dwSubjectChoice = SIGNER_SUBJECT_FILE;
    subjectInfo.pSignerFileInfo = &fileInfo;
    subjectInfo.pdwIndex = &dwIndex;

    // Certificate store info
    SIGNER_CERT_STORE_INFO certStoreInfo = { 0 };
    certStoreInfo.cbSize = sizeof(SIGNER_CERT_STORE_INFO);
    certStoreInfo.dwCertPolicy = SIGNER_CERT_POLICY_CHAIN;
    certStoreInfo.hCertStore = hStore;
    certStoreInfo.pSigningCert = pCertContext;

    // Certificate info
    SIGNER_CERT certInfo = { 0 };
    certInfo.cbSize = sizeof(SIGNER_CERT);
    certInfo.dwCertChoice = SIGNER_CERT_STORE;
    certInfo.pCertStoreInfo = &certStoreInfo;
    certInfo.hwnd = NULL;

    // Signature info
    SIGNER_SIGNATURE_INFO signatureInfo = { 0 };
    signatureInfo.cbSize = sizeof(SIGNER_SIGNATURE_INFO);
    signatureInfo.algidHash = CALG_SHA_256;
    signatureInfo.dwAttrChoice = SIGNER_NO_ATTR;
    signatureInfo.pAttrAuthcode = NULL;
    signatureInfo.psAuthenticated = NULL;
    signatureInfo.psUnauthenticated = NULL;

    SIGNER_CONTEXT_INFO contextInfo = { 0 };
    contextInfo.cbSize = sizeof(SIGNER_CONTEXT_INFO);
    contextInfo.pSignerContextInfo = NULL;
    SIGNER_CONTEXT* pSignerContext = NULL;

    // Load SignerSign function dynamically from MSSign32.dll
    HMODULE hMSSign32 = LoadLibrary(L"MSSign32.dll");
    if (!hMSSign32) {
        printf("Failed to load MSSign32.dll. Error: 0x%08x\n", GetLastError());
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hStore, 0);
        return false;
    }

    typedef HRESULT(WINAPI* PFSignerSign)(
        SIGNER_SUBJECT_INFO* pSubjectInfo,
        SIGNER_CERT* pSignerCert,
        SIGNER_SIGNATURE_INFO* pSignatureInfo,
        void* pTimestampSettings,  // Set to NULL to ignore timestamping
        SIGNER_CONTEXT_INFO* pSignerContextInfo,
        SIGNER_CONTEXT** ppSignerContext);

    PFSignerSign pfSignerSign = (PFSignerSign)GetProcAddress(hMSSign32, "SignerSign");
    if (!pfSignerSign) {
        printf("Failed to get SignerSign function. Error: 0x%08x\n", GetLastError());
        FreeLibrary(hMSSign32);
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hStore, 0);
        return false;
    }

    // Sign the file (no timestamping)
    HRESULT hr = pfSignerSign(
        &subjectInfo,
        &certInfo,
        &signatureInfo,
        NULL,  // No timestamp settings
        &contextInfo,
        &pSignerContext);

    if (SUCCEEDED(hr)) {
        printf("File signed successfully!\n");
        result = true;
    }
    else {
        printf("Signing failed. HRESULT: 0x%08x\n", hr);
    }

    // Cleanup
    if (pSignerContext) {
        typedef HRESULT(WINAPI* PFSignerFreeSignerContext)(SIGNER_CONTEXT* pSignerContext);
        PFSignerFreeSignerContext pfSignerFreeSignerContext =
            (PFSignerFreeSignerContext)GetProcAddress(hMSSign32, "SignerFreeSignerContext");

        if (pfSignerFreeSignerContext) {
            pfSignerFreeSignerContext(pSignerContext);
        }
    }

    FreeLibrary(hMSSign32);
    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hStore, 0);

    return result;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        printf("Usage: PESigner.exe <file_path> <certificate_file_path> [certificate_password]\n");
        printf("Example: PESigner.exe \"C:\\path\\to\\file.exe\" \"C:\\path\\to\\cert.pfx\" \"password\"\n");
        return 1;
    }

    std::wstring filePath = argv[1];
    std::wstring certFilePath = argv[2];
    std::wstring certPassword = (argc > 3) ? argv[3] : L"";

    bool success = SignFile(filePath, certFilePath, certPassword);

    return success ? 0 : 1;
}