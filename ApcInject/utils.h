#pragma once
#include <ntifs.h>
#include <intrin.h>
#include <ntimage.h>
#include <ntddstor.h>
#include <fltKernel.h>
#include <minwindef.h>

// 64\32λ�汾,���ݻ�ַ�����Ƶõ�������ַ,���������
PVOID MmGetSystemRoutineAddressEx(ULONG64 modBase, CHAR* searchFnName);

// �ָ��ַ���
VOID RtlSplitString(IN PUNICODE_STRING fullPath, OUT PWCHAR filePath, OUT PWCHAR fileName);

// �ַ���������±�
int RtlStringLastIndexOf(PUNICODE_STRING fullPath, WCHAR ch);

// ��ǩ����֤
ULONG RtlByPassCallBackVerify(PVOID pDrv);
VOID RtlResetCallBackVerify(PVOID ldr, ULONG oldFlags);

// �ں�Sleep
NTSTATUS KeSleep(ULONG64 timeOut);

// ͨ��pid�ж��Ƿ���32λ����
BOOLEAN PsIsWow64Process(HANDLE processId);

// ��д����
ULONG64 wpoff();

// ��д����
VOID wpon(ULONG64 mcr0);

// mdlӳ���ַ
PVOID MdlMapMemory(OUT PMDL* mdl, IN PVOID tagAddress, IN ULONG mapSize, IN MODE preMode);

// mdlȡ��ӳ��
VOID MdlUnMapMemory(IN PMDL mdl, IN PVOID mapBase);

// ͨ���������õ���������
NTSTATUS GetDriverObjectByName(IN PWCH driverName, OUT PDRIVER_OBJECT* driver);

// �õ����̵����߳�
NTSTATUS GetMainThreadByEprocess(IN PEPROCESS eprocess, OUT PETHREAD* pEthread);

// -------  �ӿ����  -------
// ObRegisterCallbacks�ӿڷ�װһ��,��ǩ����֤(ֱ���޸�Ӳ����)
NTSTATUS NTAPI CT_ObRegisterCallbacks(IN POB_CALLBACK_REGISTRATION CallbackRegistration, OUT PVOID* RegistrationHandle);

// ZwGetNextThread�ӿڷ�װһ��,��ȡ��ǰ�̵߳���һ�߳�,�����ǰ�߳�ΪNULL���ȡ���߳�
NTSTATUS NTAPI CT_ZwGetNextThread(IN HANDLE ProcessHandle, IN HANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN ULONG HandleAttributes, IN ULONG Flags, OUT PHANDLE NewThreadHandle);

// �����û��ռ��ڴ�
NTSTATUS CT_ZwAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T AllocSize, ULONG AllcType, ULONG Protect);

// �ͷ��û��ռ��ڴ�
NTSTATUS CT_ZwFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress);