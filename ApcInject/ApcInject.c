#include "Unrevealed.h"
#include "ApcInject.h"
#include "utils.h"
#define INJECT_PROCESS_NAME L"msedge.exe"
#define INJECT_DLL64_PATH L"C:\\Dll2.dll"
#define INJECT_DLL86_PATH L"C:\\Dll2_86.dll"

CHAR InjectShellCodeX64[] = {
	0x40,0x57,												// push rdi
	0x48,0x83,0xEC,0x60,									// sub rsp,60
	0x48,0xBF,0x89,0x67,0x45,0x23,0x01,0x00,0x00,0x00,		// mov rdi,punicode_string
	0x48,0x89,0x7C,0x24,0x08,
	0x48,0xC7,0x44,0x24,0x10,0x00,0x00,0x00,0x00,
	0x48,0x33,0xC9,
	0x48,0x33,0xD2,
	0x4C,0x8D,0x4C,0x24,0x10,
	0x4C,0x8B,0x44,0x24,0x08,
	0x48,0xB8,0x89,0x67,0x45,0x23,0x01,0x00,0x00,0x00,		// mov rax,ldrloaddll
	0xFF,0xD0,
	0x48,0xBF,0x89,0x67,0x45,0x23,0x01,0x00,0x00,0x00,		// mov rdi,shellcodeExeedFlag
	0xC7,0x07,0x01,0x00,0x00,0x00,							// mov dword ptr ds:[rdi],1  
	0x48,0x83,0xC4,0x60,
	0x5F,
	0xC3
};

CHAR InjectShellCodeX86[] = {
	0x55,
	0x8B,0xEC,
	0x83,0xEC,0x30,
	0x60,													// pushad
	0xBA,0xAA,0xAA,0xAA,0xAA,								// mov rdx,punicode_string
	0xC7,0x44,0x24,0x18,0x00,0x00,0x00,0x00,
	0x8D,0x4C,0x24,0x18,
	0x51,
	0x52,
	0x6A,0x00,
	0x6A,0x00,
	0xB8,0xAA,0xAA,0xAA,0xAA,								// mov rax,ldrloaddll
	0xFF,0xD0,
	0xBA,0xAA,0xAA,0xAA,0xAA,								// mov rdx,shellcodeExeedFlag
	0xC7,0x02,0x01,0x00,0x00,0x00,	
	0x61,													// popad
	0x8B,0xE5,
	0x5D,
	0xC3
};

/*
NTSTATUS GrantAccessToFile(PUNICODE_STRING filePath, ACCESS_MASK accessMask)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE fileHandle = NULL;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK ioStatus;
	PSECURITY_DESCRIPTOR securityDescriptor = NULL;
	PACL acl = NULL;

	// 打开文件
	InitializeObjectAttributes(&objAttr, filePath, OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwCreateFile(&fileHandle, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &objAttr, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
	if (!NT_SUCCESS(status))
	{
		goto end;
	}

	// 获取文件的安全描述符
	ULONG bufferSize = 0;
	status = ZwQuerySecurityObject(fileHandle, DACL_SECURITY_INFORMATION, NULL, 0, &bufferSize);
	if (status == STATUS_BUFFER_TOO_SMALL)
	{
		goto end;
	}

	securityDescriptor = ExAllocatePool(NonPagedPool, bufferSize);
	if (!securityDescriptor)
	{
		goto end;
	}

	status = ZwQuerySecurityObject(fileHandle, DACL_SECURITY_INFORMATION, securityDescriptor, bufferSize, &bufferSize);
	if (!NT_SUCCESS(status))
	{
		goto end;
	}

	// 获取 DACL
	PACL daclPresent = NULL;
	BOOLEAN daclDefaulted = FALSE;
	status = RtlGetDaclSecurityDescriptor(securityDescriptor, &daclPresent, &acl, &daclDefaulted);
	if (!NT_SUCCESS(status) || !daclPresent || !acl)
	{
		goto end;
	}

	// 分配 SID
	PSID sid;
	SID_IDENTIFIER_AUTHORITY authority = SECURITY_WORLD_SID_AUTHORITY;
	status = RtlAllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID, 0, 15, 2, 0, 0, 0, 0, &sid);
	if (!NT_SUCCESS(status))
	{
		goto end;
	}

	// 在 DACL 中为 SID 添加 ACE
	status = RtlAddAccessAllowedAce(acl, ACL_REVISION, accessMask, sid);
	if (!NT_SUCCESS(status))
	{
		goto end;
	}

	// 更新文件的安全描述符
	status = ZwSetSecurityObject(fileHandle, DACL_SECURITY_INFORMATION, securityDescriptor);
	if (!NT_SUCCESS(status))
	{
		goto end;
	}

end:
	// 清理资源
	if (securityDescriptor)
	{
		ExFreePool(securityDescriptor);
	}
	if (fileHandle)
	{
		ZwClose(fileHandle);
	}
	return status;
}
*/

BOOLEAN Is3DProcessInRegistryConfig(WCHAR* processName)
{
	BOOLEAN isChecked = FALSE;
	NTSTATUS status;
	HANDLE serviceKeyHandle;
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING serviceKeyName, valueName;
	ULONG disposition;
	ULONG dataSize = 0;
	KEY_VALUE_PARTIAL_INFORMATION* dataBuffer = NULL;

	RtlInitUnicodeString(&valueName, L"ProcessConfig");
	RtlInitUnicodeString(&serviceKeyName, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\GdvProcess");
	InitializeObjectAttributes(&objectAttributes, &serviceKeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenKey(&serviceKeyHandle, KEY_READ, &objectAttributes);
	if (!NT_SUCCESS(status))
	{
		status = ZwCreateKey(&serviceKeyHandle, KEY_ALL_ACCESS, &objectAttributes, 0, NULL, REG_OPTION_NON_VOLATILE, &disposition);
		if (NT_SUCCESS(status) && (disposition == REG_CREATED_NEW_KEY))
		{
			WCHAR defaultData[] = L"";
			status = ZwSetValueKey(serviceKeyHandle, &valueName, 0, REG_MULTI_SZ, defaultData, sizeof(defaultData));
		}
	}
	else
	{
		status = ZwQueryValueKey(serviceKeyHandle, &valueName, KeyValuePartialInformation, NULL, 0, &dataSize);
		if (status == STATUS_BUFFER_TOO_SMALL)
		{
			dataBuffer = ExAllocatePool(PagedPool, dataSize);
			if (dataBuffer != NULL)
			{
				// 查询
				status = ZwQueryValueKey(serviceKeyHandle, &valueName, KeyValuePartialInformation, dataBuffer, dataSize, &dataSize);
				if (NT_SUCCESS(status))
				{
					WCHAR* value = (WCHAR*)dataBuffer->Data;
					while (*value)
					{
						ULONG offset = wcslen(value);
						if (_wcsicmp(value, processName) == 0)
						{
							KdPrint(("datalen:%u -- data:%ls\r\n", offset, value));
							isChecked = TRUE;
							break;
						}
						value = value + offset + 1;
					}
				}
				ExFreePool(dataBuffer);
			}
		}
	}

	if (serviceKeyHandle)
	{
		ZwClose(serviceKeyHandle);
	}
	return NT_SUCCESS(status) && isChecked;
}

VOID InJectApcKernelRoutine(PRKAPC apc, PKNORMAL_ROUTINE* routine, PVOID* normalContext, PVOID* systemArgument1, PVOID* systemArgument2)
{
	if (apc) ExFreePool(apc);
}

// APC 注入
NTSTATUS DLLInjectByApc(HANDLE pid, PWCHAR dllPath, PVOID ldrLoadDllPfn, BOOLEAN isWow64)
{
	if (pid == NULL || dllPath == NULL || ldrLoadDllPfn == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	LPVOID shellcodeParam = NULL;
	PVOID normalContext = NULL;
	PKNORMAL_ROUTINE normalRoutine = NULL;
	SIZE_T codeParamSize = PAGE_SIZE;
	SIZE_T shellcodeSize = isWow64 == FALSE ? sizeof(InjectShellCodeX64) : sizeof(InjectShellCodeX86);

	NTSTATUS stat1 = CT_ZwAllocateVirtualMemory(NtCurrentProcess(), &normalRoutine, &shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READ);
	NTSTATUS stat2 = CT_ZwAllocateVirtualMemory(NtCurrentProcess(), &shellcodeParam, &codeParamSize, MEM_COMMIT, PAGE_READWRITE);
	if (NT_SUCCESS(stat1) && NT_SUCCESS(stat2) && normalRoutine && shellcodeParam)
	{
		if (!isWow64)
		{
			// 构造shellcode所需参数,主要是ldrloaddll参数
			UNICODE_STRING64 tmpParam = { 0 };
			tmpParam.Length = wcslen(dllPath) * 2;
			tmpParam.MaximumLength = (tmpParam.Length / 2 + 1) * 2;
			tmpParam.Buffer = (ULONG64)shellcodeParam + sizeof(UNICODE_STRING64);
			wcscpy((PWCHAR)((ULONG64)shellcodeParam + sizeof(UNICODE_STRING64)), dllPath);
			RtlCopyMemory(shellcodeParam, &tmpParam, sizeof(UNICODE_STRING64));

			ULONG64 shellcodeExeedFlag = (ULONG64)shellcodeParam + sizeof(UNICODE_STRING64) + 512;

			// 构造shellcode,mdl写
			PMDL mdl = NULL;
			PCHAR mapBase = MdlMapMemory(&mdl, normalRoutine, shellcodeSize, UserMode);
			if (mapBase)
			{
				*((PULONG64)&InjectShellCodeX64[8]) = shellcodeParam;
				*((PULONG64)&InjectShellCodeX64[48]) = ldrLoadDllPfn;
				*((PULONG64)&InjectShellCodeX64[60]) = shellcodeExeedFlag;

				RtlZeroMemory(mapBase, shellcodeSize);
				RtlCopyMemory(mapBase, InjectShellCodeX64, shellcodeSize);

				MdlUnMapMemory(mdl, mapBase);
			}
		}
		else
		{
			// 构造shellcode所需参数,主要是ldrloaddll参数
			UNICODE_STRING32 tmpParam = { 0 };
			tmpParam.Length = wcslen(dllPath) * 2;
			tmpParam.MaximumLength = (tmpParam.Length / 2 + 1) * 2;
			tmpParam.Buffer = (ULONG32)shellcodeParam + sizeof(UNICODE_STRING32);

			wcscpy((PWCHAR)((ULONG32)shellcodeParam + sizeof(UNICODE_STRING32)), dllPath);
			RtlCopyMemory(shellcodeParam, &tmpParam, sizeof(UNICODE_STRING32));

			ULONG32 shellcodeExeedFlag = (ULONG32)shellcodeParam + sizeof(UNICODE_STRING32) + 512;

			// 构造shellcode,mdl写
			PMDL mdl = NULL;
			PCHAR mapBase = MdlMapMemory(&mdl, normalRoutine, shellcodeSize, UserMode);
			if (mapBase)
			{
				*((PULONG32)&InjectShellCodeX86[8]) = (ULONG32)shellcodeParam;
				*((PULONG32)&InjectShellCodeX86[31]) = (ULONG32)ldrLoadDllPfn;
				*((PULONG32)&InjectShellCodeX86[38]) = (ULONG32)shellcodeExeedFlag;

				RtlZeroMemory(mapBase, shellcodeSize);
				RtlCopyMemory(mapBase, InjectShellCodeX86, shellcodeSize);

				MdlUnMapMemory(mdl, mapBase);
			}

			// 将apc封装成能在wow64线程上下文执行（地址转换,将apc排入运行在Wow64进程内的32位线程队列）
			PsWrapApcWow64Thread(&normalContext, &normalRoutine);
		}
	}

	PETHREAD ethread = NULL;
	NTSTATUS stat = STATUS_UNSUCCESSFUL;
	ethread = PsGetCurrentThread();
	if (ethread != NULL && normalRoutine != NULL)
	{
		PRKAPC kApc = (PRKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
		if (!kApc)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		KeInitializeApc(kApc, ethread, OriginalApcEnvironment, InJectApcKernelRoutine, NULL, normalRoutine, UserMode, normalContext);
		if (KeInsertQueueApc(kApc, NULL, NULL, IO_NO_INCREMENT))
		{
			stat = STATUS_SUCCESS;
		}
	}
	return stat;
}

VOID CbLoadImage(_In_opt_ PUNICODE_STRING fullImageName, _In_ HANDLE processId, _In_ PIMAGE_INFO imageInfo)
{
	if (processId == (HANDLE)4 || processId == (HANDLE)0 || KeGetCurrentIrql() != PASSIVE_LEVEL || imageInfo->SystemModeImage == TRUE)
	{
		return;
	}

	if (fullImageName == NULL || fullImageName->Buffer == NULL)
	{
		return;
	}

	BOOLEAN isWow64Context = FALSE;
	WCHAR strNtdllx86[] = L"\\Windows\\SysWOW64\\ntdll.dll";
	WCHAR strNtdllx64[] = L"\\Windows\\System32\\ntdll.dll";
	if (wcsstr(fullImageName->Buffer, strNtdllx86) != NULL && PsGetProcessWow64Process(PsGetCurrentProcess()) != NULL)
	{
		isWow64Context = TRUE;
	}
	else if(wcsstr(fullImageName->Buffer, strNtdllx64) != NULL && PsGetProcessWow64Process(PsGetCurrentProcess()) == NULL)
	{
		isWow64Context = FALSE;
	}
	else
	{
		return;
	}

	BOOLEAN isMatching = FALSE;
	PEPROCESS eprocess = NULL;
	PVOID filePointer = NULL;
	POBJECT_NAME_INFORMATION processImageName = NULL;

	if (NT_SUCCESS(PsLookupProcessByProcessId(processId, &eprocess)))
	{
		if (NT_SUCCESS(PsReferenceProcessFilePointer(eprocess, &filePointer)))
		{
			IoQueryFileDosDeviceName(filePointer, &processImageName);
			ObDereferenceObject(filePointer);
		}
		if (processImageName)
		{
			KdPrint(("process:%wZ\r\n", processImageName->Name));
			int pos = RtlStringLastIndexOf(&processImageName->Name, L'\\');
			if (pos != -1)
			{
				WCHAR* fileName = &processImageName->Name.Buffer[pos + 1];
				if (Is3DProcessInRegistryConfig(fileName) /*wcscmp(fileName, INJECT_PROCESS_NAME) == 0*/)
				{
					isMatching = TRUE;
				}
			}
			ExFreePool(processImageName);
		}
		ObDereferenceObject(eprocess);
	}
	
	if (isMatching)
	{
		LPVOID ldrLoadDllPfn = MmGetSystemRoutineAddressEx((ULONG64)imageInfo->ImageBase, "LdrLoadDll");
		if (isWow64Context)
		{
			NTSTATUS stat = DLLInjectByApc(processId, INJECT_DLL86_PATH, ldrLoadDllPfn, TRUE);
		}
		else
		{
			NTSTATUS stat = DLLInjectByApc(processId, INJECT_DLL64_PATH, ldrLoadDllPfn, FALSE);
		}
	}
}

VOID UninitApcStartupInject()
{
	PsRemoveLoadImageNotifyRoutine(CbLoadImage);
}

NTSTATUS InitApcStartupInject()
{
	NTSTATUS stat = STATUS_SUCCESS;
	stat = PsSetLoadImageNotifyRoutine(CbLoadImage);
	return stat;
}