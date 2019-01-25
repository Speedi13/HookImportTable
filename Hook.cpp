#include <Windows.h>
#include "Hook.h"

/// <summary> Detours an entry of the import table in memory on Windows x64/x86 </summary>
/// <param name="hModuleBase">address of dll to detour</param>
/// <param name="pImportToHook">address of the imported function</param>
/// <param name="HookFnc">address of the function to call instead</param>
/// <param name="HookByName">look for the import using its name (not recommended)</param>
/// <returns>returns the address of the original import table entry</returns>
void* HookImportTable( HMODULE hModuleBase, void* pImportToHook, void* HookFnc, bool HookByName = false )
{
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)hModuleBase;
	if ( !pDosHeader )
		return NULL;

	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
		return NULL;
#ifdef _AMD64_
	IMAGE_NT_HEADERS64* pNtHeader = (IMAGE_NT_HEADERS64*)( (DWORD_PTR)pDosHeader + pDosHeader->e_lfanew );
#else
	IMAGE_NT_HEADERS32* pNtHeader = (IMAGE_NT_HEADERS32*)( (DWORD_PTR)pDosHeader + pDosHeader->e_lfanew );
#endif
	if ( pNtHeader->Signature != IMAGE_NT_SIGNATURE )
		return NULL;

#ifdef _AMD64_
	//Check if dll is x64
	if (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return NULL;
#else
	//Check if dll is x86
	if (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return NULL;
#endif

	IMAGE_DATA_DIRECTORY* pImportDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	DWORD ImportDescriptorRVA = pImportDir->VirtualAddress;
	if ( !ImportDescriptorRVA )
		return NULL;

	DWORD ImportDescriptorSize = pImportDir->Size;
	if ( !ImportDescriptorSize )
		return NULL;

	IMAGE_IMPORT_DESCRIPTOR* pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)( (ULONG_PTR)pDosHeader + ImportDescriptorRVA );

	IMAGE_THUNK_DATA *OriginalFirstThunk = NULL, *FirstThunk = NULL;
	while( pImportDescriptor->Characteristics )
	{
		OriginalFirstThunk	= (IMAGE_THUNK_DATA*)( (ULONG_PTR)pDosHeader + pImportDescriptor->OriginalFirstThunk );
		FirstThunk   	        = (IMAGE_THUNK_DATA*)( (ULONG_PTR)pDosHeader + pImportDescriptor->FirstThunk );

		char* pModuleName = (char*)( (ULONG_PTR)pDosHeader + pImportDescriptor->Name );
		while( OriginalFirstThunk->u1.AddressOfData )
		{
			if ( HookByName == false && FirstThunk->u1.Function == (ULONG_PTR)pImportToHook )
			{
				ULONG_PTR OriginalImport = FirstThunk->u1.Function;
				DWORD dwOldPageProtection = NULL;
				VirtualProtect( &FirstThunk->u1.Function, sizeof(ULONG_PTR), PAGE_EXECUTE_READWRITE, &dwOldPageProtection );

				FirstThunk->u1.Function = (ULONG_PTR)HookFnc;

				VirtualProtect( &FirstThunk->u1.Function, sizeof(ULONG_PTR), dwOldPageProtection, NULL );
				return (void*)OriginalImport;
			}
			if ( HookByName == true )
			{
				if ( OriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )
				{
					HMODULE hModule = LoadLibraryA( pModuleName );

					ULONG_PTR OriginalImport = FirstThunk->u1.Function;

					char* Names[10] = {0,0,0,0,0,0,0,0,0,0};
					ResolveExportName( hModule, (void*)OriginalImport, Names, 10 );

					for (int N = 0; N < 10; N++)
					{
						if (Names[N] == NULL) break;
						if ( strcmp( (char*)pImportToHook, Names[N] ) == NULL )
						{
							DWORD dwOldPageProtection = NULL;
							VirtualProtect( &FirstThunk->u1.Function, sizeof(ULONG_PTR), PAGE_EXECUTE_READWRITE, &dwOldPageProtection );

							FirstThunk->u1.Function = (ULONG_PTR)HookFnc;

							VirtualProtect( &FirstThunk->u1.Function, sizeof(ULONG_PTR), dwOldPageProtection, NULL );
							return (void*)OriginalImport;
							break;
						}
					}

				}
				else
				{
					IMAGE_IMPORT_BY_NAME* pImportByName = (IMAGE_IMPORT_BY_NAME*)( (LPBYTE)pDosHeader + OriginalFirstThunk->u1.AddressOfData );
					if ( OriginalFirstThunk->u1.AddressOfData )
					{
						if ( strcmp( (char*)pImportToHook, pImportByName->Name ) == NULL )
						{
							ULONG_PTR OriginalImport = FirstThunk->u1.Function;
							DWORD dwOldPageProtection = NULL;
							VirtualProtect( &FirstThunk->u1.Function, sizeof(ULONG_PTR), PAGE_EXECUTE_READWRITE, &dwOldPageProtection );

							FirstThunk->u1.Function = (ULONG_PTR)HookFnc;

							VirtualProtect( &FirstThunk->u1.Function, sizeof(ULONG_PTR), dwOldPageProtection, NULL );
							return (void*)OriginalImport;
						}
					}
				}
			}
			//next
			OriginalFirstThunk =	(IMAGE_THUNK_DATA*)( (DWORD_PTR)OriginalFirstThunk + sizeof(IMAGE_THUNK_DATA) );
			FirstThunk =			(IMAGE_THUNK_DATA*)( (DWORD_PTR)FirstThunk + sizeof(IMAGE_THUNK_DATA) );
		}
		//next
		pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)( (DWORD_PTR)pImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR) );
	}	
	return NULL;
}

/// <summary> Resolves the exports name from its function address using the export table on Windows x64/x86 </summary>
/// <param name="hModuleBase">address of dll that contains the function</param>
/// <param name="ExportFunctionAddress">address of the exported function</param>
/// <param name="OutNameArray">some functions have more than one export name</param>
/// <param name="OutNameArraySize">max array size</param>
/// <returns>returns the name / array of the function name(s)</returns>
char* ResolveExportName( HMODULE hModuleBase, void* ExportFunctionAddress, char** OutNameArray = NULL, UINT OutNameArraySize = NULL )
{
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)hModuleBase;
	if ( !pDosHeader )
		return NULL;

	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
		return NULL;
#ifdef _AMD64_
	IMAGE_NT_HEADERS64* pNtHeader = (IMAGE_NT_HEADERS64*)( (DWORD_PTR)pDosHeader + pDosHeader->e_lfanew );
#else
	IMAGE_NT_HEADERS32* pNtHeader = (IMAGE_NT_HEADERS32*)( (DWORD_PTR)pDosHeader + pDosHeader->e_lfanew );
#endif
	if ( pNtHeader->Signature != IMAGE_NT_SIGNATURE )
		return NULL;

#ifdef _AMD64_
	//Check if dll is x64
	if (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return NULL;
#else
	//Check if dll is x86
	if (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return NULL;
#endif

	IMAGE_DATA_DIRECTORY* pExportDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	DWORD ExportEntryRVA = pExportDir->VirtualAddress;
	if ( !ExportEntryRVA ) //check if export table present
		return NULL;

	DWORD ExportEntrySize = pExportDir->Size;
	if ( !ExportEntrySize )
		return NULL;

	IMAGE_EXPORT_DIRECTORY* pExportTable = (IMAGE_EXPORT_DIRECTORY*)( (ULONG_PTR)pDosHeader + ExportEntryRVA );

	//check if any export names are present
	if ( !pExportTable->AddressOfNames )
		return NULL;

	//Some exports have multiple names:
	//NTDLL.RtlSetLastWin32Error
	UINT OutNameArrayPos = NULL;
	if ( OutNameArray != NULL && OutNameArraySize > NULL)
		for (int a = 0; a < OutNameArraySize; a++)
			OutNameArray[a] = NULL;

	DWORD* ExportNames = (DWORD*)( (ULONG_PTR)pDosHeader + pExportTable->AddressOfNames );
	DWORD* Functions = (DWORD*)( (ULONG_PTR)pDosHeader + pExportTable->AddressOfFunctions );
	WORD* Ordinals = (WORD*)( (ULONG_PTR)pDosHeader + pExportTable->AddressOfNameOrdinals );
	
	for (DWORD i = 0; i < pExportTable->NumberOfFunctions; i++)
	{
		char* pExportName = (char*)( (ULONG_PTR)pDosHeader + ExportNames[i] );
		WORD OrdIndex = (WORD)Ordinals[i];

		ULONG_PTR ExportFncOffset = Functions[OrdIndex];
		if ( !ExportFncOffset )
			continue;
		
		ULONG_PTR ExportFnc = (ULONG_PTR)pDosHeader + ExportFncOffset;
		if (ExportFnc > ((DWORD_PTR)pExportTable) && 
			ExportFnc < ((DWORD_PTR)pExportTable + ExportEntrySize))
		{
			char* ForwardedString = (char*)ExportFnc;
			DWORD ForwardedStringLen = strlen( ForwardedString );
			if ( ForwardedStringLen < 256 )
			{
				char szForwardedLibraryName[256];
				strcpy_s(szForwardedLibraryName, ForwardedString );
				char* ForwardedFunctionName = NULL;
				for (int s = 0; s < ForwardedStringLen; s++)
					if (szForwardedLibraryName[s] == '.')
					{
						szForwardedLibraryName[s] = NULL;
						ForwardedFunctionName = &ForwardedString[s+1];
						break;
					};
				if (szForwardedLibraryName)
				{
					HMODULE hForwardedDll = LoadLibraryA( szForwardedLibraryName );
					ULONG_PTR ForwardedFunction = (ULONG_PTR)GetProcAddress( hForwardedDll, ForwardedFunctionName );

					if ( OutNameArray != NULL && OutNameArraySize > NULL)
					{
						if (ForwardedFunction == (ULONG_PTR)ExportFunctionAddress)
						{
							if ( OutNameArrayPos < OutNameArraySize )
							{
								OutNameArray[OutNameArrayPos] = ForwardedFunctionName;
								OutNameArrayPos++;
							}
							else
								return (char*)OutNameArray;
						}
					}
					else
					{
						if (ForwardedFunction == (ULONG_PTR)ExportFunctionAddress)
							return (char*)ForwardedFunctionName;
					}
				}
			}
		}

		if ( OutNameArray != NULL && OutNameArraySize > NULL)
		{
			if (ExportFnc == (ULONG_PTR)ExportFunctionAddress)
			{
				if ( OutNameArrayPos < OutNameArraySize )
				{
					OutNameArray[OutNameArrayPos] = pExportName;
					OutNameArrayPos++;
				}
				else
					return (char*)OutNameArray;
			}
		}
		else
		{
			if (ExportFnc == (ULONG_PTR)ExportFunctionAddress)
				return (char*)pExportName;
		}

	}

	if ( OutNameArray != NULL && OutNameArraySize > NULL)
	{
		return (char*)OutNameArray;
	}
	return NULL;
}
