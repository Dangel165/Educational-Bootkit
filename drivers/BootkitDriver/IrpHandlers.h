// IrpHandlers.h: IRP handler declarations

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// IRP handler initialization and cleanup
NTSTATUS InitializeIrpHandlers();
VOID CleanupIrpHandlers();

// IRP_MJ_CREATE handler
NTSTATUS IrpCreateHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

// IRP_MJ_CLOSE handler
NTSTATUS IrpCloseHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

// IRP_MJ_READ handler
NTSTATUS IrpReadHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

// IRP_MJ_WRITE handler
NTSTATUS IrpWriteHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

// IRP_MJ_DEVICE_CONTROL handler
NTSTATUS IrpDeviceControlHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

// IRP_MJ_CLEANUP handler
NTSTATUS IrpCleanupHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

// IRP_MJ_PNP handler
NTSTATUS IrpPnpHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

// IRP_MJ_POWER handler
NTSTATUS IrpPowerHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

// IRP_MJ_SHUTDOWN handler
NTSTATUS IrpShutdownHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

// IRP completion routine
NTSTATUS CompleteIrp(
    _In_ PIRP Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information
);

// Helper function
NTSTATUS ForwardIrpToNextDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

#ifdef __cplusplus
}
#endif