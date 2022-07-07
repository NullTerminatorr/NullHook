#include "memory.h"

PVOID get_system_module_base(const char* module_name)
{
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

	if (!bytes)
		return NULL;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x4e554c4c); 

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status))
		return NULL;

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	PVOID module_base = 0, module_size = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		if (strcmp((char*)module[i].FullPathName, module_name) == NULL)
		{
			module_base = module[i].ImageBase;
			module_size = (PVOID)module[i].ImageSize;
			break;
		}
	}

	if (modules)
		ExFreePoolWithTag(modules, NULL);

	if (module_base <= NULL)
		return NULL;

	return module_base;
}

PVOID get_system_module_export(const char* module_name, LPCSTR routine_name)
{
	PVOID lpModule = get_system_module_base(module_name);

	if (!lpModule)
		return NULL;
	
	return RtlFindExportedRoutineByName(lpModule, routine_name);
}

PVOID get_system_routine_address(PCWSTR routine_name)
{
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, routine_name);
	return MmGetSystemRoutineAddress(&name);
}

PVOID get_system_module_export(LPCWSTR module_name, LPCSTR routine_name)
{
	PLIST_ENTRY module_list = reinterpret_cast<PLIST_ENTRY>(get_system_routine_address(L"PsLoadedModuleList"));

	if (!module_list)
		return NULL;

	for (PLIST_ENTRY link = module_list; link != module_list->Blink; link = link->Flink)
	{
		LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

		UNICODE_STRING name;
		RtlInitUnicodeString(&name, module_name);

		if (RtlEqualUnicodeString(&entry->BaseDllName, &name, TRUE))
		{
			return (entry->DllBase) ? RtlFindExportedRoutineByName(entry->DllBase, routine_name) : NULL;
		}
	}
}

bool write_memory(void* address, void* buffer, size_t size)
{
	if (!RtlCopyMemory(address, buffer, size))
	{
		return false;
	}
	else
	{
		return true;
	}
}

bool write_to_read_only_memory(void* address, void* buffer, size_t size)
{
	PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

	if (!Mdl)
		return false;

	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

	write_memory(Mapping, buffer, size);

	MmUnmapLockedPages(Mapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return true;
}

ULONG64 get_module_base_x64(PEPROCESS proc, UNICODE_STRING module_name)
{
	PPEB pPeb = PsGetProcessPeb(proc);

	if (!pPeb)
	{
		return NULL;
	}

	KAPC_STATE state;

	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	if (!pLdr)
	{
		KeUnstackDetachProcess(&state);
		return NULL;
	}

	for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink; list != &pLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink)
	{
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

		if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) == NULL)
		{
			ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return baseAddr;
		}
	}

	KeUnstackDetachProcess(&state);
	return NULL;
}

bool read_kernel_memory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size)
{
	if (!address || !buffer || !size)
		return false;

	SIZE_T bytes = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	PsLookupProcessByProcessId((HANDLE)pid, &process);

	status = MmCopyVirtualMemory(process, (void*)address, (PEPROCESS)PsGetCurrentProcess(), (void*)buffer, size, KernelMode, &bytes);

	if (!NT_SUCCESS(status))
	{
		return false;
	}
	else
	{
		return true;
	}
}

bool write_kernel_memory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size)
{
	if (!address || !buffer || !size)
		return false;

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	PsLookupProcessByProcessId((HANDLE)pid, &process);

	KAPC_STATE state;
	KeStackAttachProcess((PEPROCESS)process, &state);

	MEMORY_BASIC_INFORMATION info;

	status = ZwQueryVirtualMemory(ZwCurrentProcess(), (PVOID)address, MemoryBasicInformation, &info, sizeof(info), NULL);
	if (!NT_SUCCESS(status))
	{
		KeUnstackDetachProcess(&state);
		return false;
	}

	if (((uintptr_t)info.BaseAddress + info.RegionSize) < (address + size))
	{
		KeUnstackDetachProcess(&state);
		return false;
	}

	if (!(info.State & MEM_COMMIT) || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
	{
		KeUnstackDetachProcess(&state);
		return false;
	}

	if ((info.Protect & PAGE_EXECUTE_READWRITE) || (info.Protect & PAGE_EXECUTE_WRITECOPY) 
		|| (info.Protect & PAGE_READWRITE) || (info.Protect & PAGE_WRITECOPY))
	{
		RtlCopyMemory((void*)address, buffer, size);
	}
	KeUnstackDetachProcess(&state);
	return true;
}