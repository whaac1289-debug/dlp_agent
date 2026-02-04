#include "dlp_minifilter.h"

PFLT_FILTER gDlpFilter = NULL;
PFLT_PORT gDlpServerPort = NULL;
PFLT_PORT gDlpClientPort = NULL;

static const FLT_OPERATION_REGISTRATION kCallbacks[] = {
    { IRP_MJ_CREATE, 0, DlpPreCreate, NULL },
    { IRP_MJ_WRITE, 0, DlpPreWrite, NULL },
    { IRP_MJ_SET_INFORMATION, 0, DlpPreSetInfo, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION kFilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    kCallbacks,
    DlpFilterUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status = FltRegisterFilter(DriverObject, &kFilterRegistration, &gDlpFilter);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UNICODE_STRING portName;
    RtlInitUnicodeString(&portName, DLP_PORT_NAME);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = FltCreateCommunicationPort(
        gDlpFilter,
        &gDlpServerPort,
        &oa,
        NULL,
        DlpPortConnect,
        DlpPortDisconnect,
        DlpPortMessage,
        1);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gDlpFilter);
        gDlpFilter = NULL;
        return status;
    }

    status = FltStartFiltering(gDlpFilter);
    if (!NT_SUCCESS(status)) {
        if (gDlpServerPort) {
            FltCloseCommunicationPort(gDlpServerPort);
            gDlpServerPort = NULL;
        }
        FltUnregisterFilter(gDlpFilter);
        gDlpFilter = NULL;
    }
    return status;
}

NTSTATUS DlpFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    if (gDlpServerPort) {
        FltCloseCommunicationPort(gDlpServerPort);
        gDlpServerPort = NULL;
    }
    if (gDlpFilter) {
        FltUnregisterFilter(gDlpFilter);
        gDlpFilter = NULL;
    }
    return STATUS_SUCCESS;
}

NTSTATUS DlpPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie) {
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);
    gDlpClientPort = ClientPort;
    return STATUS_SUCCESS;
}

VOID DlpPortDisconnect(_In_opt_ PVOID ConnectionCookie) {
    UNREFERENCED_PARAMETER(ConnectionCookie);
    if (gDlpClientPort) {
        FltCloseClientPort(gDlpFilter, &gDlpClientPort);
        gDlpClientPort = NULL;
    }
}

NTSTATUS DlpPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength) {
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (ReturnOutputBufferLength) {
        *ReturnOutputBufferLength = 0;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS DlpBuildQuery(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _Out_ DLP_POLICY_QUERY *Query) {
    RtlZeroMemory(Query, sizeof(*Query));
    Query->ProcessId = (ULONG)PsGetCurrentProcessId();
    Query->ParentProcessId = (ULONG)PsGetProcessInheritedFromUniqueProcessId(PsGetCurrentProcess());
    Query->DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    Query->CreateOptions = Data->Iopb->Parameters.Create.Options;
    Query->FileAttributes = Data->Iopb->Parameters.Create.FileAttributes;
    return STATUS_SUCCESS;
}

NTSTATUS DlpQueryUserModePolicy(
    _In_ const DLP_POLICY_QUERY *Query,
    _Out_ DLP_POLICY_DECISION *Decision) {
    RtlZeroMemory(Decision, sizeof(*Decision));
    Decision->Action = DlpActionAllow;
    if (!gDlpClientPort) {
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    ULONG replyLength = sizeof(*Decision);
    NTSTATUS status = FltSendMessage(
        gDlpFilter,
        &gDlpClientPort,
        (PVOID)Query,
        sizeof(*Query),
        Decision,
        &replyLength,
        NULL);

    return status;
}

BOOLEAN DlpShouldBlock(_In_ const DLP_POLICY_DECISION *Decision) {
    return (Decision->Action == DlpActionBlock || Decision->Action == DlpActionQuarantine);
}

static FLT_PREOP_CALLBACK_STATUS DlpPreOperationCommon(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects) {
    UNREFERENCED_PARAMETER(FltObjects);

    DLP_POLICY_QUERY query;
    DLP_POLICY_DECISION decision;
    NTSTATUS status = DlpBuildQuery(Data, &query);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = DlpQueryUserModePolicy(&query, &decision);
    if (NT_SUCCESS(status) && DlpShouldBlock(&decision)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS DlpPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);
    return DlpPreOperationCommon(Data, FltObjects);
}

FLT_PREOP_CALLBACK_STATUS DlpPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);
    return DlpPreOperationCommon(Data, FltObjects);
}

FLT_PREOP_CALLBACK_STATUS DlpPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);
    return DlpPreOperationCommon(Data, FltObjects);
}
