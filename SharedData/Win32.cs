// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;

namespace DInvoke.Data
{
    /// <summary>
    /// Win32 is a library of enums and structures for Win32 API functions.
    /// </summary>
    /// <remarks>
    /// A majority of this library is adapted from signatures found at www.pinvoke.net.
    /// </remarks>
    public static class Win32
    {

        public class WinNT
        {
            public const UInt32 PAGE_NOACCESS = 0x01;
            public const UInt32 PAGE_READONLY = 0x02;
            public const UInt32 PAGE_READWRITE = 0x04;
            public const UInt32 PAGE_WRITECOPY = 0x08;
            public const UInt32 PAGE_EXECUTE = 0x10;
            public const UInt32 PAGE_EXECUTE_READ = 0x20;
            public const UInt32 PAGE_EXECUTE_READWRITE = 0x40;
            public const UInt32 PAGE_EXECUTE_WRITECOPY = 0x80;
            public const UInt32 PAGE_GUARD = 0x100;
            public const UInt32 PAGE_NOCACHE = 0x200;
            public const UInt32 PAGE_WRITECOMBINE = 0x400;
            public const UInt32 PAGE_TARGETS_INVALID = 0x40000000;
            public const UInt32 PAGE_TARGETS_NO_UPDATE = 0x40000000;

            public const UInt32 SEC_COMMIT = 0x08000000;
            public const UInt32 SEC_IMAGE = 0x1000000;
            public const UInt32 SEC_IMAGE_NO_EXECUTE = 0x11000000;
            public const UInt32 SEC_LARGE_PAGES = 0x80000000;
            public const UInt32 SEC_NOCACHE = 0x10000000;
            public const UInt32 SEC_RESERVE = 0x4000000;
            public const UInt32 SEC_WRITECOMBINE = 0x40000000;

            public const UInt32 SE_PRIVILEGE_ENABLED = 0x2;
            public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1;
            public const UInt32 SE_PRIVILEGE_REMOVED = 0x4;
            public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x3;

            public const UInt64 SE_GROUP_ENABLED = 0x00000004L;
            public const UInt64 SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002L;
            public const UInt64 SE_GROUP_INTEGRITY = 0x00000020L;
            public const UInt32 SE_GROUP_INTEGRITY_32 = 0x00000020;
            public const UInt64 SE_GROUP_INTEGRITY_ENABLED = 0x00000040L;
            public const UInt64 SE_GROUP_LOGON_ID = 0xC0000000L;
            public const UInt64 SE_GROUP_MANDATORY = 0x00000001L;
            public const UInt64 SE_GROUP_OWNER = 0x00000008L;
            public const UInt64 SE_GROUP_RESOURCE = 0x20000000L;
            public const UInt64 SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010L;


        }
    }
}