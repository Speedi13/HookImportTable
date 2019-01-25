# Hook Import Table
Detours an entry of the import table in memory

# Example usage
```cpp
HMODULE hookfnc( LPCSTR lpLibFileName )
{
  MessageBoxA(0,lpLibFileName,"HOOK!",0);
  return NULL;
}

int main()
{
   HMODULE CurrentModule = GetModuleHandleA( NULL );
   
   HMODULE hKernel32 = GetModuleHandleA( "kernel32.dll" );
   void* FncLoadLibraryA = GetProcAddress( hKernel32, "LoadLibraryA" );
   
   //before our hook is in place it will result in the original function being called
   LoadLibraryA("Test123");
   
   //hook:
   //OriFncAddress could be used to call the original function in your hook
   void* OriFncAddress = HookImportTable( CurrentModule, FncLoadLibraryA, hookfnc, false );
   printf("OriFncAddress = 0x%p\n", OriFncAddress );
   
   //after our hook is placed it will result in the hookfnc being called
   //keep in mind this will only work for code inside the CurrentModule specified above!
   //It also won't work if the import gets resolved via GetProcAddress. Look at my export table hook for that
   //https://github.com/Speedi13/HookExportTable
   LoadLibraryA("Test456");
   
   //unhook:
   HookImportTable( CurrentModule, hookfnc, OriFncAddress, false );
   
   system("pause");
   return 0;
}
```
