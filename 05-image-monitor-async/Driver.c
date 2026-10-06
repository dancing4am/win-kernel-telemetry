#include <ntifs.h>
#include <ntddk.h>

//
// 05-image-monitor-async : image-load monitor with OFF-THREAD logging.
//
// Same idea as 03, but the notify callback does the minimum: it copies a
// small record and drops it on a queue, then returns immediately. A separate
// system thread drains the queue and does the (slow) logging. This is the
// producer/consumer pattern real EDR uses so the callback never blocks the
// system.
//

#define MAX_PATH_CHARS 256 // truncate long paths; keeps each record small
#define POOL_TAG       'AMgI' // 'IgMA' shown in tools; for pool tracking

// One queued event. LIST_ENTRY links it into the shared list.
typedef struct _IMAGE_EVENT {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    BOOLEAN IsKernel;
    USHORT PathChars; // number of WCHARs actually stored
    WCHAR Path[MAX_PATH_CHARS]; // copied image path (not NUL-terminated guaranteed)
} IMAGE_EVENT, *PIMAGE_EVENT;

// Shared state between the callback (producer) and the worker (consumer).
static LIST_ENTRY g_EventList; // the queue
static KSPIN_LOCK g_ListLock; // guards g_EventList
static KEVENT g_WakeEvent; // signals the worker "something arrived"
static PETHREAD g_WorkerThread; // the worker thread object
static BOOLEAN g_Stopping = FALSE; // tells the worker to exit

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD ImageMonUnload;

// ---- Producer: the image-load callback -------------------------------------

VOID ImageMonLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo) {
    // Allocate a record. NonPagedPool because we touch it under a spin lock
    // and at raised IRQL, where paged memory is illegal.
    PIMAGE_EVENT evt =
        (PIMAGE_EVENT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(IMAGE_EVENT), POOL_TAG);
    if(evt == NULL) {
        return; // out of memory: just drop this event, never block
    }

    evt->ProcessId = ProcessId;
    evt->IsKernel = (ImageInfo->SystemModeImage != 0);
    evt->PathChars = 0;

    if(FullImageName != NULL && FullImageName->Buffer != NULL) {
        USHORT chars = FullImageName->Length / sizeof(WCHAR);
        if(chars > MAX_PATH_CHARS) {
            chars = MAX_PATH_CHARS; // truncate
        }
        RtlCopyMemory(evt->Path, FullImageName->Buffer, chars * sizeof(WCHAR));
        evt->PathChars = chars;
    }

    // Push onto the queue under the spin lock, then wake the worker.
    ExInterlockedInsertTailList(&g_EventList, &evt->ListEntry, &g_ListLock);
    KeSetEvent(&g_WakeEvent, IO_NO_INCREMENT, FALSE);
}

// ---- Consumer: the worker thread -------------------------------------------

VOID ImageMonWorker(_In_ PVOID StartContext) {
    UNREFERENCED_PARAMETER(StartContext);

    for(;;) {
        // Sleep until the callback signals us (or we're told to stop).
        KeWaitForSingleObject(&g_WakeEvent, Executive, KernelMode, FALSE, NULL);

        // Drain everything currently queued.
        for(;;) {
            PLIST_ENTRY node = ExInterlockedRemoveHeadList(&g_EventList, &g_ListLock);
            if(node == NULL) {
                break; // queue empty
            }

            PIMAGE_EVENT evt = CONTAINING_RECORD(node, IMAGE_EVENT, ListEntry);

            // The slow part now runs OFF the callback path.
            UNICODE_STRING path;
            path.Buffer = evt->Path;
            path.Length = evt->PathChars * sizeof(WCHAR);
            path.MaximumLength = evt->PathChars * sizeof(WCHAR);

            KdPrintEx(
                (DPFLTR_IHVDRIVER_ID,
                 DPFLTR_INFO_LEVEL,
                 "ImageMonAsync: [%s] pid=%llu  %wZ\n",
                 evt->IsKernel ? "KERNEL" : "user ",
                 (ULONG64)(ULONG_PTR)evt->ProcessId,
                 &path));

            ExFreePool(evt);
        }

        // If we were asked to stop AND the queue is drained, exit.
        if(g_Stopping) {
            break;
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ---- Load / unload ----------------------------------------------------------

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ImageMonAsync: DriverEntry\n"));

    DriverObject->DriverUnload = ImageMonUnload;

    // Init the shared state.
    InitializeListHead(&g_EventList);
    KeInitializeSpinLock(&g_ListLock);
    KeInitializeEvent(&g_WakeEvent, SynchronizationEvent, FALSE);
    g_Stopping = FALSE;

    // Start the worker thread.
    HANDLE hThread;
    status =
        PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, ImageMonWorker, NULL);
    if(!NT_SUCCESS(status)) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "ImageMonAsync: thread create failed 0x%08X\n",
             status));
        return status;
    }

    // Keep a referenced pointer to the thread so we can wait on it at unload.
    ObReferenceObjectByHandle(
        hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&g_WorkerThread, NULL);
    ZwClose(hThread);

    // Register the image-load callback last, once the worker is ready.
    status = PsSetLoadImageNotifyRoutine(ImageMonLoadImageNotify);
    if(!NT_SUCCESS(status)) {
        KdPrintEx(
            (DPFLTR_IHVDRIVER_ID,
             DPFLTR_INFO_LEVEL,
             "ImageMonAsync: register failed 0x%08X\n",
             status));
        // Tell the worker to stop and wait for it before failing.
        g_Stopping = TRUE;
        KeSetEvent(&g_WakeEvent, IO_NO_INCREMENT, FALSE);
        KeWaitForSingleObject(g_WorkerThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_WorkerThread);
        return status;
    }

    return STATUS_SUCCESS;
}

VOID ImageMonUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    // 1. Stop new events arriving.
    PsRemoveLoadImageNotifyRoutine(ImageMonLoadImageNotify);

    // 2. Ask the worker to finish and wait for it.
    g_Stopping = TRUE;
    KeSetEvent(&g_WakeEvent, IO_NO_INCREMENT, FALSE);
    KeWaitForSingleObject(g_WorkerThread, Executive, KernelMode, FALSE, NULL);
    ObDereferenceObject(g_WorkerThread);

    // 3. Free anything still left on the queue (shouldn't be, but be safe).
    PLIST_ENTRY node;
    while((node = ExInterlockedRemoveHeadList(&g_EventList, &g_ListLock)) != NULL) {
        ExFreePool(CONTAINING_RECORD(node, IMAGE_EVENT, ListEntry));
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ImageMonAsync: Unload\n"));
}
