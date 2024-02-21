#include <ntifs.h>
#include "utils.h"
#include "ApcInject.h"

VOID Unload(PDRIVER_OBJECT pDriver)
{
	KdPrint(("[info]:Unload~\r\n"));

	UninitApcStartupInject();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	status = InitApcStartupInject();

	pDriver->DriverUnload = Unload;
	return status;
}