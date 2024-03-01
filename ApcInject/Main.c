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
		DbgPrint("�н��̴�����\r\n");
	}
	else
	{
		DbgPrint("�н���������\r\n");
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

	// ������������������ /INTEGRITYCHECK
	status = PsSetCreateProcessNotifyRoutineEx(PcreateProcessNotifyRoutineEx, FALSE);

	pDriver->DriverUnload = Unload;

	// ����һ�����سɹ�
	// ģ��ص��ɹ���������ʧ������������ģ��ж����,���ǻص�ûж��
	return STATUS_SUCCESS;
}