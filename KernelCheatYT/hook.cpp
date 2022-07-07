#include "hook.h"
#include <wingdi.h>

GdiSelectBrush_t GdiSelectBrush = NULL;
PatBlt_t NtGdiPatBlt = NULL;
NtUserGetDC_t NtUserGetDC = NULL;
NtGdiCreateSolidBrush_t NtGdiCreateSolidBrush = NULL;
ReleaseDC_t NtUserReleaseDC = NULL;
DeleteObjectApp_t NtGdiDeleteObjectApp = NULL;

bool nullhook::call_kernel_function(void* kernel_function_address)
{
	if (!kernel_function_address)
		return false;
	//NtQueryCompositionSurfaceStatistics
	PVOID* function = reinterpret_cast<PVOID*>(get_system_module_export("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys",
																		"NtDxgkGetTrackedWorkloadStatistics"));

	if (!function)
		return false;

	BYTE orig[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	BYTE shell_code[] = { 0x48, 0xB8 }; // mov rax, xxx
	BYTE shell_code_end[] = { 0xFF, 0xE0 }; //jmp rax

	RtlSecureZeroMemory(&orig, sizeof(orig));
	memcpy((PVOID)((ULONG_PTR)orig), &shell_code, sizeof(shell_code));
	uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_function_address);
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &hook_address, sizeof(void*));
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));

	write_to_read_only_memory(function, &orig, sizeof(orig));
	
	GdiSelectBrush = (GdiSelectBrush_t)get_system_module_export(L"win32kfull.sys", "NtGdiSelectBrush");
	NtGdiCreateSolidBrush = (NtGdiCreateSolidBrush_t)get_system_module_export(L"win32kfull.sys", "NtGdiCreateSolidBrush");
	NtGdiPatBlt = (PatBlt_t)get_system_module_export(L"win32kfull.sys", "NtGdiPatBlt");
	NtUserGetDC = (NtUserGetDC_t)get_system_module_export(L"win32kbase.sys", "NtUserGetDC");
	NtUserReleaseDC = (ReleaseDC_t)get_system_module_export(L"win32kbase.sys", "NtUserReleaseDC");
	NtGdiDeleteObjectApp = (DeleteObjectApp_t)get_system_module_export(L"win32kbase.sys", "NtGdiDeleteObjectApp");

	return true;
}

NTSTATUS nullhook::hook_handler(PVOID called_param)
{
	NULL_MEMORY* instructions = (NULL_MEMORY*)called_param;

	if (instructions->req_base == TRUE)
	{
		ANSI_STRING AS;
		UNICODE_STRING ModuleName;

		RtlInitAnsiString(&AS, instructions->module_name);
		RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);

		PEPROCESS process;
		PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
		ULONG64 base_address64 = NULL;
		base_address64 = get_module_base_x64(process, ModuleName);
		instructions->base_address = base_address64;
		RtlFreeUnicodeString(&ModuleName);
	}

	else if (instructions->write == TRUE)
	{
		if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0)
		{
			PVOID kernelBuff = ExAllocatePool(NonPagedPool, instructions->size);

			if (!kernelBuff)
			{
				return STATUS_UNSUCCESSFUL;
			}

			if (!memcpy(kernelBuff, instructions->buffer_address, instructions->size))
			{
				return STATUS_UNSUCCESSFUL;
			}

			PEPROCESS process;
			PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
			write_kernel_memory((HANDLE)instructions->pid, instructions->address, kernelBuff, instructions->size);
			ExFreePool(kernelBuff);
		}
	}

	else if (instructions->read == TRUE)
	{
		if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0)
		{
			read_kernel_memory((HANDLE)instructions->pid, instructions->address, instructions->output, instructions->size);
		}
	}

	else if (instructions->draw_box == TRUE)
	{
		HDC hdc = NtUserGetDC(NULL);
		if (!hdc)
			return STATUS_UNSUCCESSFUL;

		HBRUSH brush = NtGdiCreateSolidBrush(RGB(instructions->r, instructions->g, instructions->b), NULL);
		if (!brush)
			return STATUS_UNSUCCESSFUL;

		RECT rect = { instructions->x, instructions->y, instructions->x + instructions->w, instructions->y + instructions->h };
		FrameRect(hdc, &rect, brush, instructions->t);
		NtUserReleaseDC(hdc);
		NtGdiDeleteObjectApp(brush);
	}

	return STATUS_SUCCESS;
}

INT nullhook::FrameRect(HDC hDC, CONST RECT* lprc, HBRUSH hbr, int thickness)
{
	HBRUSH oldbrush;
	RECT r = *lprc;

	if (!(oldbrush = GdiSelectBrush(hDC, hbr))) return 0;

	NtGdiPatBlt(hDC, r.left, r.top, thickness, r.bottom - r.top, PATCOPY);
	NtGdiPatBlt(hDC, r.right - thickness, r.top, thickness, r.bottom - r.top, PATCOPY);
	NtGdiPatBlt(hDC, r.left, r.top, r.right - r.left, thickness, PATCOPY);
	NtGdiPatBlt(hDC, r.left, r.bottom - thickness, r.right - r.left, thickness, PATCOPY);

	GdiSelectBrush(hDC, oldbrush);
	return TRUE;
}