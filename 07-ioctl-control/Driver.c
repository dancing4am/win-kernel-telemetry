#include <ntddk.h>
#include <wdf.h>
#include <wdmsec.h> // SDDL_DEVOBJ_SYS_ALL_ADM_ALL
#include "ioctl_shared.h"

#define IOCTLCTL_VERSION 0x00010000u // 1.0, returned by IOCTL_GET_VERSION

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD IoctlCtlEvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL IoctlCtlEvtIoDeviceControl;

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver;
    PWDFDEVICE_INIT deviceInit;
    WDFDEVICE controlDevice;
    WDF_IO_QUEUE_CONFIG queueConfig;

    DECLARE_CONST_UNICODE_STRING(deviceName, IOCTLCTL_DEVICE_NAME);
    DECLARE_CONST_UNICODE_STRING(symLink, IOCTLCTL_SYMLINK);

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = IoctlCtlEvtDriverUnload;

    status =
        WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
    if(!NT_SUCCESS(status)) {
        return status;
    }

    // SDDL limits who can open it: SYSTEM and Administrators only.
    deviceInit = WdfControlDeviceInitAllocate(driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if(deviceInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if(!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit); // only valid before WdfDeviceCreate
        return status;
    }

    // IOCTL buffering comes from each control code's METHOD_* (METHOD_BUFFERED).
    WdfDeviceInitSetIoType(deviceInit, WdfDeviceIoBuffered);

    status = WdfDeviceCreate(&deviceInit, WDF_NO_OBJECT_ATTRIBUTES, &controlDevice);
    if(!NT_SUCCESS(status)) {
        return status; // WdfDeviceCreate frees deviceInit on failure
    }

    // Expose \\.\IoctlCtl to user mode.
    status = WdfDeviceCreateSymbolicLink(controlDevice, &symLink);
    if(!NT_SUCCESS(status)) {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = IoctlCtlEvtIoDeviceControl;

    status =
        WdfIoQueueCreate(controlDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if(!NT_SUCCESS(status)) {
        return status;
    }

    WdfControlFinishInitializing(controlDevice);
    return STATUS_SUCCESS;
}

VOID IoctlCtlEvtDriverUnload(_In_ WDFDRIVER Driver) {
    UNREFERENCED_PARAMETER(Driver);
    // The framework tears down the control device and symbolic link.
}

VOID IoctlCtlEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode) {
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    switch(IoControlCode) {
    case IOCTL_GET_VERSION: {
        PULONG outBuf = NULL;
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(ULONG), (PVOID*)&outBuf, NULL);
        if(NT_SUCCESS(status)) {
            *outBuf = IOCTLCTL_VERSION;
            info = sizeof(ULONG);
        }
        break;
    }
    case IOCTL_SET_CONFIG: {
        PIOCTLCTL_CONFIG cfg = NULL;
        status =
            WdfRequestRetrieveInputBuffer(Request, sizeof(IOCTLCTL_CONFIG), (PVOID*)&cfg, NULL);
        if(NT_SUCCESS(status)) {
            KdPrintEx(
                (DPFLTR_IHVDRIVER_ID,
                 DPFLTR_INFO_LEVEL,
                 "IoctlCtl: SET_CONFIG Enabled=%lu TargetPid=%lu\n",
                 cfg->Enabled,
                 cfg->TargetPid));
        }
        break;
    }
    default:
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, info);
}
