#pragma once

/// <summary> Detours an entry of the import table in memory on Windows x64/x86 </summary>
/// <param name="hModuleBase">address of dll to detour</param>
/// <param name="pImportToHook">address of the imported function</param>
/// <param name="HookFnc">address of the function to call instead</param>
/// <param name="HookByName">look for the import using its name (not recommended)</param>
/// <returns>returns the address of the original import table entry</returns>
void* HookImportTable( HMODULE hModuleBase, void* pImportToHook, void* HookFnc, bool HookByName = false );

/// <summary> Resolves the exports name from its function address using the export table on Windows x64/x86 </summary>
/// <param name="hModuleBase">address of dll that contains the function</param>
/// <param name="ExportFunctionAddress">address of the exported function</param>
/// <param name="OutNameArray">some functions have more than one export name</param>
/// <param name="OutNameArraySize">max array size</param>
/// <returns>returns the name / array of the function name(s)</returns>
char* ResolveExportName( HMODULE hModuleBase, void* ExportFunctionAddress, char** OutNameArray = NULL, UINT OutNameArraySize = NULL );
