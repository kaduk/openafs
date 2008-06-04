#ifndef _AFS_PROVIDER_H
#define _AFS_PROVIDER_H


//
// Network provider interface header
//


//
// Redirector device name
//

#define AFS_RDR_DEVICE_NAME         L"\\Device\\AFSRedirector"

//
// Provider specific IOCtl requests
//

#define IOCTL_AFS_ADD_CONNECTION      CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x2001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AFS_CANCEL_CONNECTION   CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x2002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AFS_GET_CONNECTION      CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x2003, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AFS_LIST_CONNECTIONS    CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x2004, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _REDIRFS_CONNECTION_CB
{

    WCHAR       LocalName;

    USHORT      RemoteNameLength;

    WCHAR       RemoteName[ 1];

} RedirConnectionCB;



#endif