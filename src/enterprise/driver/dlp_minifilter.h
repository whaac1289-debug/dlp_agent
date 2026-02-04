#pragma once

#include <fltKernel.h>

// Device and port names
#define DLP_FILTER_NAME L"DlpMinifilter"
#define DLP_PORT_NAME L"\\DlpMinifilterPort"

// Policy actions
typedef enum _DLP_POLICY_ACTION {
    DlpActionAllow = 0,
    DlpActionBlock = 1,
    DlpActionAlert = 2,
    DlpActionQuarantine = 3
} DLP_POLICY_ACTION;

// Message from kernel to user mode
typedef struct _DLP_POLICY_QUERY {
    ULONG ProcessId;
    ULONG ParentProcessId;
    ULONG SessionId;
    ULONG DesiredAccess;
    ULONG CreateOptions;
    ULONG FileAttributes;
    WCHAR FilePath[512];
} DLP_POLICY_QUERY;

// Response from user mode to kernel
typedef struct _DLP_POLICY_DECISION {
    DLP_POLICY_ACTION Action;
    ULONG RuleId;
    ULONG Severity;
} DLP_POLICY_DECISION;

// Globals
extern PFLT_FILTER gDlpFilter;
extern PFLT_PORT gDlpServerPort;
extern PFLT_PORT gDlpClientPort;

// Driver entry points
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DlpFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

// Communication
NTSTATUS DlpPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie);

VOID DlpPortDisconnect(_In_opt_ PVOID ConnectionCookie);

NTSTATUS DlpPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength);

// Callbacks
FLT_PREOP_CALLBACK_STATUS DlpPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_PREOP_CALLBACK_STATUS DlpPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_PREOP_CALLBACK_STATUS DlpPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

// Policy evaluation
NTSTATUS DlpQueryUserModePolicy(
    _In_ const DLP_POLICY_QUERY *Query,
    _Out_ DLP_POLICY_DECISION *Decision);

BOOLEAN DlpShouldBlock(
    _In_ const DLP_POLICY_DECISION *Decision);
