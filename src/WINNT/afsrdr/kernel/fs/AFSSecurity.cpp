/*
 * Copyright (c) 2008, 2009, 2010, 2011 Kernel Drivers, LLC.
 * Copyright (c) 2009, 2010, 2011 Your File System, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice,
 *   this list of conditions and the following disclaimer in the
 *   documentation
 *   and/or other materials provided with the distribution.
 * - Neither the names of Kernel Drivers, LLC and Your File System, Inc.
 *   nor the names of their contributors may be used to endorse or promote
 *   products derived from this software without specific prior written
 *   permission from Kernel Drivers, LLC and Your File System, Inc.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

//
// File: AFSSecurity.cpp
//

#include "AFSCommon.h"

NTSTATUS
AFSSetSecurity( IN PDEVICE_OBJECT DeviceObject,
                IN PIRP Irp)
{

    NTSTATUS ntStatus = STATUS_NOT_SUPPORTED;
    IO_STACK_LOCATION *pIrpSp;
    AFSDeviceExt *pControlDeviceExt = (AFSDeviceExt *)AFSDeviceObject->DeviceExtension;
    AFSFcb* pFcb = NULL;

    pIrpSp = IoGetCurrentIrpStackLocation( Irp);

    __try
    {

        AFSDbgLogMsg( AFS_SUBSYSTEM_FILE_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSSetSecurity Entry for FO %08lX\n",
                      pIrpSp->FileObject);

        if( DeviceObject == AFSDeviceObject)
        {

            ntStatus = STATUS_INVALID_DEVICE_REQUEST;

            AFSCompleteRequest( Irp,
                                ntStatus);

            try_return( ntStatus);
        }

        pFcb = (AFSFcb*) pIrpSp->FileObject->FsContext;

        if( pFcb == NULL ||
            pFcb->Header.NodeTypeCode == AFS_REDIRECTOR_FCB)
        {

            //
            // Root open
            //

            ntStatus = STATUS_INVALID_DEVICE_REQUEST;

            AFSCompleteRequest( Irp,
                                ntStatus);

            try_return( ntStatus);
        }

        //
        // Check the state of the library
        //

        ntStatus = AFSCheckLibraryState( Irp);

        if( !NT_SUCCESS( ntStatus) ||
            ntStatus == STATUS_PENDING)
        {

            if( ntStatus != STATUS_PENDING)
            {
                AFSCompleteRequest( Irp, ntStatus);
            }

            try_return( ntStatus);
        }

        IoSkipCurrentIrpStackLocation( Irp);

        ntStatus = IoCallDriver( pControlDeviceExt->Specific.Control.LibraryDeviceObject,
                                 Irp);

        //
        // Indicate the library is done with the request
        //

        AFSClearLibraryRequest();

try_exit:

        NOTHING;
    }
    __except( AFSExceptionFilter( __FUNCTION__, GetExceptionCode(), GetExceptionInformation()) )
    {

        AFSDbgLogMsg( 0,
                      0,
                      "EXCEPTION - AFSSetSecurity\n");

        AFSDumpTraceFilesFnc();
    }

    return ntStatus;
}

NTSTATUS
AFSQuerySecurity( IN PDEVICE_OBJECT DeviceObject,
                  IN PIRP Irp)
{

    NTSTATUS ntStatus = STATUS_NOT_SUPPORTED;
    IO_STACK_LOCATION *pIrpSp;
    AFSDeviceExt *pControlDeviceExt = (AFSDeviceExt *)AFSDeviceObject->DeviceExtension;
    AFSFcb* pFcb = NULL;

    pIrpSp = IoGetCurrentIrpStackLocation( Irp);

    __try
    {

        AFSDbgLogMsg( AFS_SUBSYSTEM_FILE_PROCESSING,
                      AFS_TRACE_LEVEL_VERBOSE,
                      "AFSQuerySecurity Entry for FO %08lX\n",
                      pIrpSp->FileObject);

        if( DeviceObject == AFSDeviceObject)
        {

            ntStatus = STATUS_INVALID_DEVICE_REQUEST;

            AFSCompleteRequest( Irp,
                                ntStatus);

            try_return( ntStatus);
        }

        pFcb = (AFSFcb*) pIrpSp->FileObject->FsContext;

        if( pFcb == NULL ||
            pFcb->Header.NodeTypeCode == AFS_REDIRECTOR_FCB)
        {

            //
            // Root open
            //

            ntStatus = STATUS_INVALID_DEVICE_REQUEST;

            AFSCompleteRequest( Irp,
                                ntStatus);

            try_return( ntStatus);
        }

        //
        // Check the state of the library
        //

        ntStatus = AFSCheckLibraryState( Irp);

        if( !NT_SUCCESS( ntStatus) ||
            ntStatus == STATUS_PENDING)
        {

            if( ntStatus != STATUS_PENDING)
            {
                AFSCompleteRequest( Irp, ntStatus);
            }

            try_return( ntStatus);
        }

        IoSkipCurrentIrpStackLocation( Irp);

        ntStatus = IoCallDriver( pControlDeviceExt->Specific.Control.LibraryDeviceObject,
                                 Irp);

        //
        // Indicate the library is done with the request
        //

        AFSClearLibraryRequest();

try_exit:

        NOTHING;
    }
    __except( AFSExceptionFilter( __FUNCTION__, GetExceptionCode(), GetExceptionInformation()) )
    {

        AFSDbgLogMsg( 0,
                      0,
                      "EXCEPTION - AFSQuerySecurity\n");

        AFSDumpTraceFilesFnc();
    }

    return ntStatus;
}
