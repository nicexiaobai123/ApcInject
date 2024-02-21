#pragma once
#include <ntifs.h>
#include <ntdef.h>
#include <minwindef.h>

VOID UninitApcStartupInject();

NTSTATUS InitApcStartupInject();