#include <ntifs.h>
#include "utils.h"
#include "ApcInject.h"

void PcreateProcessNotifyRoutineEx(
 PEPROCESS Process,
 HANDLE ProcessId,
 PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	if (CreateInfo)
	{
		DbgPrint("有进程创建了\r\n");
	}
	else
	{
		DbgPrint("有进程销毁了\r\n");
	}
}

VOID Unload(PDRIVER_OBJECT pDriver)
{
	KdPrint(("[info]:Unload~\r\n"));

	UninitApcStartupInject();
	
	PsSetCreateProcessNotifyRoutineEx(PcreateProcessNotifyRoutineEx, TRUE);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	status = InitApcStartupInject();

	// 连接器命令行已设置 /INTEGRITYCHECK
	status = PsSetCreateProcessNotifyRoutineEx(PcreateProcessNotifyRoutineEx, FALSE);

	pDriver->DriverUnload = Unload;

	// 驱动一定返回成功
	// 模块回调成功驱动加载失败则会出现驱动模块卸载了,但是回调没卸载
	return STATUS_SUCCESS;
}