// Author: Ryan Cobb (@cobbr_io), The Wover (@TheRealWover)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

namespace DInvoke.DynamicInvoke
{
    /// <summary>
    /// Contains function prototypes and wrapper functions for dynamically invoking Win32 API Calls.
    /// </summary>
    public static class Win32
    {

        public static IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            ref IntPtr lpThreadId)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId
            };

            IntPtr retValue = (IntPtr)Generic.DynamicAPIInvoke(@"kernel32.dll", @"CreateRemoteThread",
                typeof(Delegates.CreateRemoteThread), ref funcargs);

            // Update the modified variables
            lpThreadId = (IntPtr)funcargs[6];

            return retValue;
        }

        public static void TerminateThread(IntPtr threadHandle)
        {
            object[] terminateThreadParams = { threadHandle };
            Generic.DynamicAPIInvoke("kernel32.dll", "TerminateThread", typeof(Delegates.TerminateThread), ref terminateThreadParams);
        }

        public static class Delegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr CreateRemoteThread(IntPtr hProcess,
                IntPtr lpThreadAttributes,
                uint dwStackSize,
                IntPtr lpStartAddress,
                IntPtr lpParameter,
                uint dwCreationFlags,
                out IntPtr lpThreadId);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 TerminateThread(IntPtr hThread);
        }
    }
}
