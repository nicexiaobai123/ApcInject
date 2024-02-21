#include "utils.h"
#include "Unrevealed.h"

// 64\32位版本,根据基址和名称得到函数地址,导出表解析
PVOID MmGetSystemRoutineAddressEx(ULONG64 modBase, CHAR* searchFnName)
{
	if (modBase == 0 || searchFnName == NULL)  return NULL;
	SIZE_T funcAddr = 0;

	do
	{
		PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)modBase;
		PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(modBase + pDosHdr->e_lfanew);
		PIMAGE_FILE_HEADER pFileHdr = &pNtHdr->FileHeader;
		PIMAGE_OPTIONAL_HEADER64 pOphtHdr64 = NULL;
		PIMAGE_OPTIONAL_HEADER32 pOphtHdr32 = NULL;

		if (pFileHdr->Machine == IMAGE_FILE_MACHINE_I386) pOphtHdr32 = (PIMAGE_OPTIONAL_HEADER32)&pNtHdr->OptionalHeader;
		else pOphtHdr64 = (PIMAGE_OPTIONAL_HEADER64)&pNtHdr->OptionalHeader;

		ULONG VirtualAddress = 0;
		if (pOphtHdr64 != NULL) VirtualAddress = pOphtHdr64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		else VirtualAddress = pOphtHdr32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

		// 根据 PE 64位/32位 得到导出表
		PIMAGE_EXPORT_DIRECTORY pExportTable = (IMAGE_EXPORT_DIRECTORY*)(modBase + VirtualAddress);
		if (NULL == pExportTable) break;

		PULONG pAddrFns = (PULONG)(modBase + pExportTable->AddressOfFunctions);
		PULONG pAddrNames = (PULONG)(modBase + pExportTable->AddressOfNames);
		PUSHORT pAddrNameOrdinals = (PUSHORT)(modBase + pExportTable->AddressOfNameOrdinals);

		ULONG funcOrdinal, i;
		char* funcName;
		for (ULONG i = 0; i < pExportTable->NumberOfNames; ++i)
		{
			funcName = (char*)(modBase + pAddrNames[i]);
			if (modBase < MmUserProbeAddress)
			{
				__try
				{
					if (!_strnicmp(searchFnName, funcName, strlen(searchFnName)))
					{
						if (funcName[strlen(searchFnName)] == 0)
						{
							funcAddr = modBase + pAddrFns[pAddrNameOrdinals[i]];
							break;
						}
					}
				}
				__except (1) { continue; }
			}
			else
			{
				if (MmIsAddressValid(funcName) && MmIsAddressValid(funcName + strlen(searchFnName)))
				{
					if (!_strnicmp(searchFnName, funcName, strlen(searchFnName)))
					{
						if (funcName[strlen(searchFnName)] == 0)
						{
							funcOrdinal = pExportTable->Base + pAddrNameOrdinals[i] - 1;
							funcAddr = modBase + pAddrFns[funcOrdinal];
							break;
						}
					}
				}
			}
		}
	} while (0);
	return (PVOID)funcAddr;
}

int RtlStringLastIndexOf(PUNICODE_STRING fullPath, WCHAR ch)
{
	if (fullPath == NULL || fullPath->Buffer == NULL) return -1;

	PWCHAR pathBuffer = fullPath->Buffer;
	int len = wcslen(pathBuffer) - 1;
	for (int j = len; j > 0; j--)
	{
		if (pathBuffer[j] == ch)
		{
			return j;
		}
	}
	return -1;
}

// 分割字符串
VOID RtlSplitString(IN PUNICODE_STRING fullPath, OUT PWCHAR filePath, OUT PWCHAR fileName)
{
	PWCHAR pathBuffer = fullPath->Buffer;
	int len = wcslen(pathBuffer) - 1;
	int start = 0;
	int i = start, j = len;

	while (pathBuffer[i] != '\\')
	{
		fileName[j] = pathBuffer[i];
		i++;
		j--;
	}

	WCHAR tmp;
	int k = 0;
	int lenght = wcslen(fileName);
	for (j = lenght - 1; k < j; k++, j--)
	{
		tmp = fileName[k];
		fileName[k] = fileName[j];
		fileName[j] = tmp;
	}

	// 文件夹路径
	j = 0;
	for (i = 0; i < len - lenght; i++)
	{
		filePath[j] = pathBuffer[i];
		j++;
	}
}

// 过回调验证
ULONG RtlByPassCallBackVerify(PVOID ldr)
{
	if (ldr == NULL || MmIsAddressValid(ldr))
	{
		return 0;
	}
	ULONG originFlags = ((PKLDR_DATA_TABLE_ENTRY64)ldr)->Flags;
	((PKLDR_DATA_TABLE_ENTRY64)ldr)->Flags |= 0x20;
	return originFlags;
}

// 恢复回调验证
VOID RtlResetCallBackVerify(PVOID ldr, ULONG oldFlags)
{
	if (ldr == NULL || MmIsAddressValid(ldr)) return;
	((PKLDR_DATA_TABLE_ENTRY64)ldr)->Flags = oldFlags;
}

// 线程延迟  Sleep
NTSTATUS KeSleep(ULONG64 TimeOut)
{
	LARGE_INTEGER delayTime = { 0 };
	delayTime.QuadPart = -10 * 1000;
	delayTime.QuadPart *= TimeOut;
	return KeDelayExecutionThread(KernelMode, FALSE, &delayTime);
}

// 通过pid判断是否是32位进程
BOOLEAN PsIsWow64Process(HANDLE processId)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS eProcess = NULL;
	status = PsLookupProcessByProcessId(processId, &eProcess);
	if (NT_SUCCESS(status))
	{
		if (PsGetProcessWow64Process(eProcess) == NULL)
		{
			return FALSE;
		}
		ObDereferenceObject(eProcess);
	}
	return TRUE;
}

// 关写保护
ULONG64 wpoff()
{
	_disable();
	ULONG64 mcr0 = __readcr0();
	__writecr0(mcr0 & (~0x10000));
	_enable();
	return  mcr0;
}

// 开写保护
VOID wpon(ULONG64 mcr0)
{
	_disable();
	__writecr0(mcr0);
	_enable();
}

// mdl映射地址
PVOID MdlMapMemory(OUT PMDL* mdl, IN PVOID tagAddress, IN ULONG mapSize, IN MODE preMode)
{
	PMDL pMdl = IoAllocateMdl(tagAddress, mapSize, FALSE, FALSE, NULL);
	if (pMdl == NULL)
	{
		return NULL;
	}
	PVOID mapAddr = NULL;
	BOOLEAN isLock = FALSE;
	__try
	{
		MmProbeAndLockPages(pMdl, preMode, IoReadAccess);
		isLock = TRUE;
		mapAddr = MmMapLockedPagesSpecifyCache(pMdl, preMode, MmCached, NULL, FALSE, NormalPagePriority);
	}
	__except(1)
	{
		if (isLock)
		{
			MmUnlockPages(pMdl);
		}
		IoFreeMdl(pMdl);
		return NULL;
	}
	*mdl = pMdl;
	return mapAddr;
}

// mdl取消映射
VOID MdlUnMapMemory(IN PMDL mdl, IN PVOID mapBase)
{
	if (mdl == NULL) return;
	__try
	{
		MmUnmapLockedPages(mapBase, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
	}
	__except (1)
	{
		return;
	}
}

// 通过驱动名得到驱动对象
NTSTATUS GetDriverObjectByName(IN PWCH driverName, OUT PDRIVER_OBJECT* driver)
{
	if (driverName == NULL || driver == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	UNICODE_STRING drvNameUnStr = { 0 };
	RtlInitUnicodeString(&drvNameUnStr, driverName);
	PDRIVER_OBJECT drv = NULL;
	NTSTATUS stat = ObReferenceObjectByName(&drvNameUnStr, FILE_ALL_ACCESS, 0, 0, *IoDriverObjectType, KernelMode, NULL, &drv);
	if (NT_SUCCESS(stat))
	{
		*driver = drv;
		ObDereferenceObject(drv);
	}
	return STATUS_SUCCESS;
}

// 得到进程的主线程
NTSTATUS GetMainThreadByEprocess(IN PEPROCESS eprocess, OUT PETHREAD* pEthread)
{
	if (eprocess == NULL || pEthread == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS stat = STATUS_UNSUCCESSFUL;
	KAPC_STATE apcStat = { 0 };
	HANDLE thread = NULL;
	PETHREAD ethread = NULL;

	KeStackAttachProcess(eprocess, &apcStat);
	stat = CT_ZwGetNextThread(NtCurrentProcess(), NULL, THREAD_ALL_ACCESS, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, &thread);
	if (NT_SUCCESS(stat))
	{
		// 获取线程对象
		stat = ObReferenceObjectByHandle(thread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &ethread, NULL);
		NtClose(thread);
	}
	KeUnstackDetachProcess(&apcStat);

	*pEthread = ethread;
	return stat;
}

//  ---------------------  接口设计  --------------------- 
// 过签名验证的回调注册
NTSTATUS CT_ObRegisterCallbacks(IN POB_CALLBACK_REGISTRATION CallbackRegistration, OUT PVOID* RegistrationHandle)
{
	PCHAR MmVerifyPfn = NULL;
	RTL_OSVERSIONINFOW version = { 0 };
	NTSTATUS stat = RtlGetVersion(&version);
	if (!NT_SUCCESS(stat))
	{
		return stat;
	}
	stat = STATUS_UNSUCCESSFUL;

	// 找到对应系统的MmVerifyFun地址
	PUCHAR ObRegisterPfn = (PUCHAR)ObRegisterCallbacks;
	if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601)
	{
		for (int i = 0; i < 0x500; i++)
		{
			if (ObRegisterPfn[i] == 0x74 && ObRegisterPfn[i + 2] == 0xe8 && ObRegisterPfn[i + 7] == 0x3b && ObRegisterPfn[i + 8] == 0xc3)
			{
				LARGE_INTEGER larger;
				larger.QuadPart = ObRegisterPfn + i + 7;
				larger.LowPart += *(PULONG)(ObRegisterPfn + i + 3);
				MmVerifyPfn = larger.QuadPart;
				break;
			}
		}
	}
	else
	{
		for (int i = 0; i < 0x500; i++)
		{
			// 其他win10系统基本通用,找不到再去ida对应系统找
			// mov xxxx   call xxxx   test eax,eax
			if (ObRegisterPfn[i] == 0xBA && ObRegisterPfn[i + 5] == 0xe8 && ObRegisterPfn[i + 10] == 0x85 && ObRegisterPfn[i + 11] == 0xc0)
			{
				LARGE_INTEGER larger;
				larger.QuadPart = ObRegisterPfn + i + 10;			// 下一行地址
				larger.LowPart += *(PULONG)(ObRegisterPfn + i + 6);	// offset
				MmVerifyPfn = larger.QuadPart;						// 函数地址
				break;
			}
		}
	}

	// 直接修改硬编码打补丁过验证并注册回调
	if (MmVerifyPfn)
	{
		// 直接映射一份物理地址再写
		// (PS：内核中代码段只读,映射一份地址默认可读写)
		PHYSICAL_ADDRESS phyAddress = MmGetPhysicalAddress(MmVerifyPfn);
		PVOID memMap = MmMapIoSpace(phyAddress, 10, MmNonCached);
		if (memMap)
		{
			UCHAR oldCode[10] = { 0 };
			UCHAR patch[] = { 0xb0,0x1,0xc3 };
			memcpy(oldCode, memMap, 10);
			memcpy(memMap, patch, sizeof(patch));
			stat = ObRegisterCallbacks(CallbackRegistration, RegistrationHandle);
			memcpy(memMap, oldCode, 10);
		}
	}
	return stat;
}

// 获取当前线程的下一线程,如果当前线程为NULL则获取主线程
NTSTATUS CT_ZwGetNextThread(IN HANDLE ProcessHandle, IN HANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN ULONG HandleAttributes, IN ULONG Flags, OUT PHANDLE NewThreadHandle)
{
	NTSTATUS stat = STATUS_UNSUCCESSFUL;
	typedef NTSTATUS(NTAPI* ZwGetNextThreadPfn)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
	static ZwGetNextThreadPfn ZwGetNextThreadFunc = NULL;
	if (!ZwGetNextThreadFunc)
	{
		WCHAR zwGetNextThread[] = { 'Z','w','G','e','t','N','e','x','t','T','h','r','e','a', 'd', 0, 0 };
		UNICODE_STRING unZeGetNextThread = { 0 };
		RtlInitUnicodeString(&unZeGetNextThread, zwGetNextThread);
		ZwGetNextThreadFunc = MmGetSystemRoutineAddress(&unZeGetNextThread);
		if(ZwGetNextThreadFunc == NULL)
		{
			// Win7未导出,其他函数定位
			UNICODE_STRING unName = { 0 };
			RtlInitUnicodeString(&unName, L"ZwGetNotificationResourceManager");
			PUCHAR ZwGetNotificationResourceManagerAddr = (PUCHAR)MmGetSystemRoutineAddress(&unName);
			ZwGetNotificationResourceManagerAddr -= 0x50;
			for (int i = 0; i < 0x30; i++)
			{
				if (ZwGetNotificationResourceManagerAddr[i] == 0x48
					&& ZwGetNotificationResourceManagerAddr[i + 1] == 0x8B
					&& ZwGetNotificationResourceManagerAddr[i + 2] == 0xC4)
				{
					ZwGetNextThreadFunc = ZwGetNotificationResourceManagerAddr + i;
					break;
				}
			}
		}
	}
	if (ZwGetNextThreadFunc)
	{
		stat = ZwGetNextThreadFunc(ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags, NewThreadHandle);
	}
	return stat;
}

// 申请用户空间内存
NTSTATUS CT_ZwAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T AllocSize, ULONG AllcType, ULONG Protect)
{
	NTSTATUS Result = STATUS_SUCCESS;
	NTSTATUS(NTAPI * RtlAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
	if (ExGetPreviousMode() == KernelMode)
	{
		// 不走SSDT表
		(*(PVOID*)(&RtlAllocateVirtualMemory)) = ((PVOID)(NtAllocateVirtualMemory));
	}
	else
	{
		(*(PVOID*)(&RtlAllocateVirtualMemory)) = ((PVOID)(ZwAllocateVirtualMemory));
	}
	__try
	{
		Result = RtlAllocateVirtualMemory(ProcessHandle, BaseAddress, 0, AllocSize, AllcType, Protect);
	}
	__except (1) 
	{ 
		Result = STATUS_UNSUCCESSFUL; 
	}
	return Result;
}

// 释放用户空间内存
NTSTATUS CT_ZwFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress)
{
	SIZE_T size = 0;
	NTSTATUS(NTAPI * RtlFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
	if (ExGetPreviousMode() == KernelMode)
	{
		(*(PVOID*)(&RtlFreeVirtualMemory)) = ((PVOID)(NtFreeVirtualMemory));
	}
	else
	{
		(*(PVOID*)(&RtlFreeVirtualMemory)) = ((PVOID)(ZwFreeVirtualMemory));
	}
	__try
	{
		RtlFreeVirtualMemory(ProcessHandle, BaseAddress, &size, MEM_RELEASE);
	}
	__except (1) { return STATUS_ACCESS_VIOLATION; }
	return STATUS_SUCCESS;
}