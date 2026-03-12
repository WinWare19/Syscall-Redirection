#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <strsafe.h>

// ===================================================================

typedef struct _SYSCALL_STUB {
	LPBYTE stub_address;
	DWORD original_ssn;
	LIST_ENTRY link;
	CRITICAL_SECTION lock;
} SYSCALL_STUB, *PSYSCALL_STUB, *LPSYSCALL_STUB;
typedef HANDLE STUB_HANDLE;

// ===================================================================

void __stdcall InitializeListHead(PLIST_ENTRY);
void __stdcall InsertTailList(PLIST_ENTRY, PLIST_ENTRY);
void __stdcall RemoveFromList(PLIST_ENTRY);

BOOLEAN __stdcall LookupLoadedExeModule(LPCWSTR, INT, HMODULE*);
BOOLEAN __stdcall LookupExportItemByName(HMODULE, LPCSTR, INT, LPBYTE*);
BOOLEAN __stdcall CrackExportForwarder(LPSTR, INT, LPWSTR*, LPSTR*);

BOOLEAN __stdcall ExtractSyscallNumber(LPBYTE, DWORD*);

BOOLEAN __stdcall RedirectSystcallStubByName(LPCWSTR, LPCSTR, LPCSTR, STUB_HANDLE*);
BOOLEAN __stdcall RedirectSystcallStub(LPCWSTR, LPCSTR, DWORD, STUB_HANDLE*);
BOOLEAN __stdcall RestoreSyscallStub(STUB_HANDLE);

LPSTR __stdcall AllocateLowerCaseStr(LPCSTR, INT);
LPWSTR __stdcall AllocateLowerCaseStr(LPCWSTR, INT);
INT __stdcall GetNameComponentOffset(LPCWSTR, INT);

// ===================================================================

LIST_ENTRY redirected_syscall_stubs_list_head = { 0x0 };
CRITICAL_SECTION gLock = { 0x0 };

// ===================================================================

INT main() {
	InitializeCriticalSection(&gLock);
	InitializeListHead(&redirected_syscall_stubs_list_head);

	STUB_HANDLE reserved = 0x0;
	if (!RedirectSystcallStubByName(L"ntdll.dll", "NtContinue", "NtCreateFile", &reserved)) return 0x0;

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	LPBYTE lpNtCreateFile = (LPBYTE)GetProcAddress(ntdll, "NtContinue");
	
	UNICODE_STRING file_path = { 0x0 };
	file_path.Buffer = (LPWSTR)L"\\??\\{______FILE_PATH_______}";
	file_path.Length = 0x0;
	file_path.MaximumLength = 0x0;

	OBJECT_ATTRIBUTES oa = { 0x0 };
	oa.Length = sizeof OBJECT_ATTRIBUTES;
	oa.ObjectName = &file_path;

	HANDLE file = INVALID_HANDLE_VALUE;
	IO_STATUS_BLOCK status_block = { 0x0 };

	NTSTATUS status = ((NTSTATUS(__stdcall*)(HANDLE*, ACCESS_MASK, POBJECT_ATTRIBUTES, IO_STATUS_BLOCK*, LARGE_INTEGER*, ULONG, ULONG, ULONG, ULONG, PVOID,
		ULONG))lpNtCreateFile)(&file, GENERIC_READ, &oa, &status_block, 0x0, FILE_ATTRIBUTE_NORMAL, 0x0, FILE_OPEN_IF, FILE_SEQUENTIAL_ONLY, 0x0, 0x0);
	if (!NT_SUCCESS(status) || !NT_SUCCESS(status_block.Status)) return 0x0;

	printf_s("file created successfully ... .. .\n");

	CloseHandle(file);

	if (!RestoreSyscallStub(reserved)) return 0x0;

	return 0x0;
}

// ===================================================================

void __stdcall InitializeListHead(PLIST_ENTRY list_head) {
	if (!list_head) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return;
	}

	list_head->Flink = list_head->Blink = list_head;
}

void __stdcall InsertTailList(PLIST_ENTRY list_head, PLIST_ENTRY new_entry) {
	if (!list_head || !new_entry || !list_head->Blink || !list_head->Flink) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return;
	}

	new_entry->Flink = list_head;
	new_entry->Blink = list_head->Blink;
	list_head->Blink->Flink = new_entry;
	list_head->Blink = new_entry;
}

void __stdcall RemoveFromList(PLIST_ENTRY entry_to_remove) {
	if (!entry_to_remove || !entry_to_remove->Flink || !entry_to_remove->Blink) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return;
	}

	entry_to_remove->Blink->Flink = entry_to_remove->Flink;
	entry_to_remove->Flink->Blink = entry_to_remove->Blink;

	entry_to_remove->Flink = entry_to_remove->Blink = 0x0;
}

BOOLEAN __stdcall LookupLoadedExeModule(LPCWSTR module_name, INT name_length, HMODULE* module_base) {
	INT real_length = lstrlenW(module_name);
	if (!module_name || !name_length || name_length > real_length || !module_base) return 0x0;

	TEB* teb = NtCurrentTeb();
	if (!teb || !teb->ProcessEnvironmentBlock || !teb->ProcessEnvironmentBlock->Ldr) return 0x0;

	LPWSTR lc_module_name = AllocateLowerCaseStr(module_name, name_length);

	PEB_LDR_DATA* ldr_data = teb->ProcessEnvironmentBlock->Ldr;

	LIST_ENTRY* module_list_head = &ldr_data->InMemoryOrderModuleList;
	LIST_ENTRY* module_iterator = module_list_head->Flink;

	while (module_iterator != module_list_head) {
		LDR_DATA_TABLE_ENTRY* module_info = CONTAINING_RECORD(module_iterator, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (module_info && module_info->FullDllName.Buffer) {
			LPWSTR name_buffer = AllocateLowerCaseStr(module_info->FullDllName.Buffer, module_info->FullDllName.Length / 0x2);
			if (name_buffer) {
				INT cmp_result = lstrcmpW(name_buffer + GetNameComponentOffset(name_buffer, module_info->FullDllName.Length / 0x2), 
					lc_module_name);
				HeapFree(GetProcessHeap(), 0x8, name_buffer);
				if (!cmp_result){
					*module_base = (HMODULE)module_info->DllBase;
					break;
				}
			}
		}
		module_iterator = module_iterator->Flink;
	}

	HeapFree(GetProcessHeap(), 0x8, lc_module_name);
	return *module_base ? 0x1 : 0x0;
}

BOOLEAN __stdcall LookupExportItemByName(HMODULE module_base, LPCSTR export_name, INT name_length, LPBYTE* export_address) {
	INT real_length = lstrlenA(export_name);
	if (!module_base || !export_name || !name_length || name_length > real_length || !export_address) return 0x0;

	IMAGE_DOS_HEADER* dos_hdr = (IMAGE_DOS_HEADER*)module_base;
	IMAGE_NT_HEADERS64* nt_hdr = (IMAGE_NT_HEADERS64*)((UINT_PTR)dos_hdr + dos_hdr->e_lfanew);
	if (nt_hdr->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT ||
		!nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress ||
		!nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) return 0x0;

	IMAGE_EXPORT_DIRECTORY* export_info = (IMAGE_EXPORT_DIRECTORY*)((UINT_PTR)module_base +
		nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (!export_info->NumberOfFunctions || !export_info->NumberOfNames || !export_info->AddressOfFunctions ||
		!export_info->AddressOfNameOrdinals || !export_info->AddressOfNames) return 0x0;

	LPSTR lc_export_name = AllocateLowerCaseStr(export_name, name_length);
	if (!lc_export_name) return 0x0;

	DWORD32* export_rvas = (DWORD32*)((UINT_PTR)module_base + export_info->AddressOfFunctions);
	DWORD32* export_name_rvas = (DWORD32*)((UINT_PTR)module_base + export_info->AddressOfNames);
	WORD* export_ordinals = (WORD*)((UINT_PTR)module_base + export_info->AddressOfNameOrdinals);

	for (UINT i = 0x0; i < export_info->NumberOfNames; i++) {
		LPSTR name_buffer = AllocateLowerCaseStr((LPSTR)((UINT_PTR)module_base + export_name_rvas[i]), 
			lstrlenA((LPSTR)((UINT_PTR)module_base + export_name_rvas[i])));
		if (name_buffer) {
			INT cmp_result = lstrcmpA(lc_export_name, name_buffer);
			HeapFree(GetProcessHeap(), 0x8, name_buffer);
			if (!cmp_result) {
				UINT_PTR __export_address = (UINT_PTR)module_base + export_rvas[export_ordinals[i]];
				if (__export_address >= (UINT_PTR)((UINT_PTR)module_base +
					nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) &&
					__export_address < (UINT_PTR)((UINT_PTR)module_base +
						nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress +
						nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)) {
					
					LPWSTR module_name = 0x0;
					LPSTR __export_name = 0x0;
					if (!CrackExportForwarder((LPSTR)__export_address, lstrlenA((LPSTR)__export_address), &module_name,
						&__export_name)) goto BREAK;
					else {
						HMODULE __module_base = 0x0;
						if (LookupLoadedExeModule(module_name, lstrlenW(module_name), &__module_base))
							LookupExportItemByName(__module_base, __export_name, lstrlenA(__export_name), export_address);
						HeapFree(GetProcessHeap(), 0x8, module_name);
						HeapFree(GetProcessHeap(), 0x8, __export_name);
					}
				}
				else *export_address = (LPBYTE)__export_address;
			BREAK:
				break;
			}
		}

	}

	HeapFree(GetProcessHeap(), 0x8, lc_export_name);
	return *export_address ? 0x1 : 0x0;
}

BOOLEAN __stdcall CrackExportForwarder(LPSTR forwarder, INT forwarder_length, LPWSTR* module_name, LPSTR* export_name) {
	INT real_length = lstrlenA(forwarder);
	if (!forwarder || !forwarder_length || forwarder_length > real_length || !module_name || !export_name) return 0x0;

	INT delimiter_offset = -1;
	for (UINT i = 0x0; i < forwarder_length; i++) if (forwarder[i] == '.') {
		delimiter_offset = i;
		break;
	}
	if (delimiter_offset == -1) return 0x0;

	INT module_name_length = delimiter_offset, export_name_length = forwarder_length - (delimiter_offset + 0x1);
	if (!module_name_length || !export_name_length) return 0x0;

	*module_name = (LPWSTR)HeapAlloc(GetProcessHeap(), 0x8, module_name_length * 0x2 + 0xA);
	if (!*module_name) return 0x0;

	*export_name = (LPSTR)HeapAlloc(GetProcessHeap(), 0x8, export_name_length);
	if (!*export_name) goto FREE_MODULE_NAME_BUFFER;
	else {
		if (!MultiByteToWideChar(CP_ACP, 0x0, forwarder, module_name_length, *module_name, module_name_length) ||
			FAILED(StringCchCopyA(*export_name, export_name_length + 0x1, forwarder + delimiter_offset + 0x1))) goto FREE_EXPORT_NAME_BUFFER;
		else {
			if(FAILED(StringCchCopyW(*module_name + module_name_length, 0x5, L".dll"))) goto FREE_EXPORT_NAME_BUFFER;
			else goto EPILOGUE;
		}
	}

FREE_EXPORT_NAME_BUFFER:
	HeapFree(GetProcessHeap(), 0x8, *export_name);
	*export_name = 0x0;
FREE_MODULE_NAME_BUFFER:
	HeapFree(GetProcessHeap(), 0x8, *module_name);
	*module_name = 0x0;
EPILOGUE:
	return *module_name && *export_name;
}

LPSTR __stdcall AllocateLowerCaseStr(LPCSTR str, INT str_length) {
	INT real_length = lstrlenA(str);
	if (!str || !str_length || str_length > real_length) return 0x0;

	LPSTR lc_str = (LPSTR)HeapAlloc(GetProcessHeap(), 0x8, str_length + 0x1);
	if (!lc_str) return 0x0;

	for (UINT i = 0x0; i < str_length; i++) lc_str[i] = tolower(str[i]);

	return lc_str;
}

LPWSTR __stdcall AllocateLowerCaseStr(LPCWSTR str, INT str_length) {
	INT real_length = lstrlenW(str);
	if (!str || !str_length || str_length > real_length) return 0x0;

	LPWSTR lc_str = (LPWSTR)HeapAlloc(GetProcessHeap(), 0x8, str_length * 0x2 + 0x2);
	if (!lc_str) return 0x0;

	for (UINT i = 0x0; i < str_length; i++) lc_str[i] = towlower(str[i]);

	return lc_str;
}

INT __stdcall GetNameComponentOffset(LPCWSTR full_path, INT path_length) {
	INT real_length = lstrlenW(full_path);
	if (!full_path || !path_length || path_length > real_length) return -1;

	INT offset = -1;
	for (INT i = path_length - 0x2; i != 0x0; i--) if (full_path[i] == L'\\') {
		offset = i;
		break;
	}

	return offset + 0x1;
}

BOOLEAN __stdcall ExtractSyscallNumber(LPBYTE syscall_stub, DWORD* syscall_num) {
	if (!syscall_stub || !syscall_num) return 0x0;
	*syscall_num = *(DWORD*)(syscall_stub + 0x4);
	return *syscall_stub ? 0x1 : 0x0;
}

BOOLEAN __stdcall RedirectSystcallStub(LPCWSTR module_name, LPCSTR syscall_stub_name, DWORD new_syscall_num, STUB_HANDLE* stub_handle) {
	if (!new_syscall_num || !stub_handle) return 0x0;
	
	INT module_name_length = lstrlenW(module_name), syscall_stub_name_length = lstrlenA(syscall_stub_name);
	HMODULE module_base = 0x0;
	if (!LookupLoadedExeModule(module_name, module_name_length, &module_base)) return 0x0;

	LPBYTE syscall_stub = 0x0;
	if (!LookupExportItemByName(module_base, syscall_stub_name, syscall_stub_name_length, &syscall_stub)) return 0x0;

	DWORD original_ssn = 0x0;
	if (!ExtractSyscallNumber(syscall_stub, &original_ssn)) return 0x0;

	LPSYSCALL_STUB redirected_syscall_stub_info = (LPSYSCALL_STUB)HeapAlloc(GetProcessHeap(), 0x8, sizeof SYSCALL_STUB);
	if (!redirected_syscall_stub_info) return 0x0;

	redirected_syscall_stub_info->original_ssn = original_ssn;
	redirected_syscall_stub_info->stub_address = syscall_stub;
	InitializeCriticalSection(&redirected_syscall_stub_info->lock);

	EnterCriticalSection(&gLock);
	InsertTailList(&redirected_syscall_stubs_list_head, &redirected_syscall_stub_info->link);
	LeaveCriticalSection(&gLock);

	DWORD original_mem_protection[0x2] = { 0x0 };
	if (!VirtualProtect(syscall_stub + 0x4, 0x4, PAGE_EXECUTE_READWRITE, &original_mem_protection[0x0])) goto FREE_REDIRECTED_SYSCALL_STUB;
	else {
		if (_InterlockedExchange((LONG*)(syscall_stub + 0x4), new_syscall_num) == original_ssn) 
			*stub_handle = (STUB_HANDLE)(~((UINT_PTR)(&redirected_syscall_stub_info->link)));
		VirtualProtect(syscall_stub + 0x4, 0x4, original_mem_protection[0x0], &original_mem_protection[0x1]);
		if (*stub_handle) goto EPILOGUE;
	}

FREE_REDIRECTED_SYSCALL_STUB:
	HeapFree(GetProcessHeap(), 0x8, redirected_syscall_stub_info);
	redirected_syscall_stub_info = 0x0;
EPILOGUE:
	return *stub_handle ? 0x1 : 0x0;
}

BOOLEAN __stdcall RestoreSyscallStub(STUB_HANDLE stub_handle) {
	if (!stub_handle) return 0x0;

	LIST_ENTRY* link = (LIST_ENTRY*)(~((UINT_PTR)stub_handle));
	if (!link) return 0x0;

	SYSCALL_STUB* syscall_stub_info = CONTAINING_RECORD(link, SYSCALL_STUB, link);
	if (!syscall_stub_info) return 0x0;

	EnterCriticalSection(&syscall_stub_info->lock);
	DWORD original_snn = syscall_stub_info->original_ssn;
	LeaveCriticalSection(&syscall_stub_info->lock);

	if (!original_snn) return 0x0;

	EnterCriticalSection(&gLock);
	RemoveFromList(&syscall_stub_info->link);
	LeaveCriticalSection(&gLock);

	BOOLEAN return_val = 0x0;

	DWORD original_mem_protection[0x2] = { 0x0 };
	if (!VirtualProtect(syscall_stub_info->stub_address + 0x4, 0x4, PAGE_EXECUTE_READWRITE, &original_mem_protection[0x0])) goto FREE_SYSCALL_STUB_INFO;
	else {
		_InterlockedExchange((LONG*)(syscall_stub_info->stub_address + 0x4), original_snn);
		VirtualProtect(syscall_stub_info->stub_address + 0x4, 0x4, original_mem_protection[0x0], &original_mem_protection[0x1]);
		return_val = 0x1;
	}

FREE_SYSCALL_STUB_INFO:
	HeapFree(GetProcessHeap(), 0x8, syscall_stub_info);
	return return_val;
}

// ===========================================================================

BOOLEAN __stdcall RedirectSystcallStubByName(LPCWSTR module_name, LPCSTR syscall_stub_name, LPCSTR target_syscall_stub_name, STUB_HANDLE* stub_handle) {
	if (!target_syscall_stub_name) return 0x0;

	INT module_name_length = lstrlenW(module_name), syscall_stub_name_length = lstrlenA(target_syscall_stub_name);
	HMODULE module_base = 0x0;
	if (!LookupLoadedExeModule(module_name, module_name_length, &module_base)) return 0x0;

	LPBYTE target_syscall_stub = 0x0;
	if (!LookupExportItemByName(module_base, target_syscall_stub_name, syscall_stub_name_length, &target_syscall_stub)) return 0x0;

	DWORD syscall_num = 0x0;
	if (!ExtractSyscallNumber(target_syscall_stub, &syscall_num)) return 0x0;

	return RedirectSystcallStub(module_name, syscall_stub_name, syscall_num, stub_handle);
}

// ===========================================================================