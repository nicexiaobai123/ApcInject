#pragma once
#include <ntifs.h>
#include <intrin.h>
#include <ntimage.h>
#include <ntddstor.h>
#include <fltKernel.h>
#include <minwindef.h>

// 64\32位版本,根据基址和名称得到函数地址,导出表解析
PVOID MmGetSystemRoutineAddressEx(ULONG64 modBase, CHAR* searchFnName);

// 分割字符串
VOID RtlSplitString(IN PUNICODE_STRING fullPath, OUT PWCHAR filePath, OUT PWCHAR fileName);

// 字符出现最后下标
int RtlStringLastIndexOf(PUNICODE_STRING fullPath, WCHAR ch);

// 过签名验证
ULONG RtlByPassCallBackVerify(PVOID pDrv);
VOID RtlResetCallBackVerify(PVOID ldr, ULONG oldFlags);

// 内核Sleep
NTSTATUS KeSleep(ULONG64 timeOut);

// 通过pid判断是否是32位进程
BOOLEAN PsIsWow64Process(HANDLE processId);

// 关写保护
ULONG64 wpoff();

// 开写保护
VOID wpon(ULONG64 mcr0);

// mdl映射地址
PVOID MdlMapMemory(OUT PMDL* mdl, IN PVOID tagAddress, IN ULONG mapSize, IN MODE preMode);

// mdl取消映射
VOID MdlUnMapMemory(IN PMDL mdl, IN PVOID mapBase);

// 通过驱动名得到驱动对象
NTSTATUS GetDriverObjectByName(IN PWCH driverName, OUT PDRIVER_OBJECT* driver);

// 得到进程的主线程
NTSTATUS GetMainThreadByEprocess(IN PEPROCESS eprocess, OUT PETHREAD* pEthread);

// -------  接口设计  -------
// ObRegisterCallbacks接口封装一层,过签名验证(直接修改硬编码)
NTSTATUS NTAPI CT_ObRegisterCallbacks(IN POB_CALLBACK_REGISTRATION CallbackRegistration, OUT PVOID* RegistrationHandle);

// ZwGetNextThread接口封装一层,获取当前线程的下一线程,如果当前线程为NULL则获取主线程
NTSTATUS NTAPI CT_ZwGetNextThread(IN HANDLE ProcessHandle, IN HANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN ULONG HandleAttributes, IN ULONG Flags, OUT PHANDLE NewThreadHandle);

// 申请用户空间内存
NTSTATUS CT_ZwAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T AllocSize, ULONG AllcType, ULONG Protect);

// 释放用户空间内存
NTSTATUS CT_ZwFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress);