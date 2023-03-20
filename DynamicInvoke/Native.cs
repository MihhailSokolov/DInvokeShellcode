// Author: Ryan Cobb (@cobbr_io), The Wover (@TheRealWover)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

namespace DInvoke.DynamicInvoke
{
    /// <summary>
    /// Contains function prototypes and wrapper functions for dynamically invoking NT API Calls.
    /// </summary>
    public class Native
    {
        public static Data.Native.NTSTATUS NtCreateSection(
            ref IntPtr SectionHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            ref ulong MaximumSize,
            uint SectionPageProtection,
            uint AllocationAttributes,
            IntPtr FileHandle)
        {

            // Craft an array for the arguments
            object[] funcargs =
            {
                SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle
            };

            Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtCreateSection", typeof(DELEGATES.NtCreateSection), ref funcargs);
            if (retValue != Data.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Unable to create section, " + retValue);
            }

            // Update the modified variables
            SectionHandle = (IntPtr) funcargs[0];
            MaximumSize = (ulong) funcargs[3];

            return retValue;
        }

        public static Data.Native.NTSTATUS NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                hProc, baseAddr
            };

            Data.Native.NTSTATUS result = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtUnmapViewOfSection",
                typeof(DELEGATES.NtUnmapViewOfSection), ref funcargs);

            return result;
        }

        public static Data.Native.NTSTATUS NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            IntPtr SectionOffset,
            ref ulong ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect)
        {

            // Craft an array for the arguments
            object[] funcargs =
            {
                SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType,
                Win32Protect
            };

            Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtMapViewOfSection", typeof(DELEGATES.NtMapViewOfSection), ref funcargs);
            if (retValue != Data.Native.NTSTATUS.Success && retValue != Data.Native.NTSTATUS.ImageNotAtBase)
            {
                throw new InvalidOperationException("Unable to map view of section, " + retValue);
            }

            // Update the modified variables.
            BaseAddress = (IntPtr) funcargs[2];
            ViewSize = (ulong) funcargs[6];

            return retValue;
        }

        public static void RtlZeroMemory(IntPtr Destination, int Length)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                Destination, Length
            };

            Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlZeroMemory", typeof(DELEGATES.RtlZeroMemory), ref funcargs);
        }

        public static Data.Native.NTSTATUS NtQueryInformationProcess(IntPtr hProcess, Data.Native.PROCESSINFOCLASS processInfoClass, out IntPtr pProcInfo)
        {
            int processInformationLength;
            UInt32 RetLen = 0;

            switch (processInfoClass)
            {
                case Data.Native.PROCESSINFOCLASS.ProcessWow64Information:
                    pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
                    RtlZeroMemory(pProcInfo, IntPtr.Size);
                    processInformationLength = IntPtr.Size;
                    break;
                case Data.Native.PROCESSINFOCLASS.ProcessBasicInformation:
                    Data.Native.PROCESS_BASIC_INFORMATION PBI = new Data.Native.PROCESS_BASIC_INFORMATION();
                    pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(PBI));
                    RtlZeroMemory(pProcInfo, Marshal.SizeOf(PBI));
                    Marshal.StructureToPtr(PBI, pProcInfo, true);
                    processInformationLength = Marshal.SizeOf(PBI);
                    break;
                default:
                    throw new InvalidOperationException($"Invalid ProcessInfoClass: {processInfoClass}");
            }

            object[] funcargs =
            {
                hProcess, processInfoClass, pProcInfo, processInformationLength, RetLen
            };

            Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtQueryInformationProcess", typeof(DELEGATES.NtQueryInformationProcess), ref funcargs);
            if (retValue != Data.Native.NTSTATUS.Success)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            // Update the modified variables
            pProcInfo = (IntPtr)funcargs[2];

            return retValue;
        }

        public static Data.Native.PROCESS_BASIC_INFORMATION NtQueryInformationProcessBasicInformation(IntPtr hProcess)
        {
            Data.Native.NTSTATUS retValue = NtQueryInformationProcess(hProcess, Data.Native.PROCESSINFOCLASS.ProcessBasicInformation, out IntPtr pProcInfo);
            if (retValue != Data.Native.NTSTATUS.Success)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            return (Data.Native.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pProcInfo, typeof(Data.Native.PROCESS_BASIC_INFORMATION));
        }

        public static IntPtr LdrGetProcedureAddress(IntPtr hModule, IntPtr FunctionName, IntPtr Ordinal, ref IntPtr FunctionAddress)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                hModule, FunctionName, Ordinal, FunctionAddress
            };

            Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"LdrGetProcedureAddress", typeof(DELEGATES.LdrGetProcedureAddress), ref funcargs);
            if (retValue != Data.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Failed get procedure address, " + retValue);
            }

            FunctionAddress = (IntPtr)funcargs[3];
            return FunctionAddress;
        }


        /// <summary>
        /// Holds delegates for API calls in the NT Layer.
        /// Must be public so that they may be used with SharpSploit.Execution.DynamicInvoke.Generic.DynamicFunctionInvoke
        /// </summary>
        /// <example>
        /// 
        /// // These delegates may also be used directly.
        ///
        /// // Get a pointer to the NtCreateThreadEx function.
        /// IntPtr pFunction = Execution.DynamicInvoke.Generic.GetLibraryAddress(@"ntdll.dll", "NtCreateThreadEx");
        /// 
        /// //  Create an instance of a NtCreateThreadEx delegate from our function pointer.
        /// DELEGATES.NtCreateThreadEx createThread = (NATIVE_DELEGATES.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(
        ///    pFunction, typeof(NATIVE_DELEGATES.NtCreateThreadEx));
        ///
        /// //  Invoke NtCreateThreadEx using the delegate
        /// createThread(ref threadHandle, Data.Win32.WinNT.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Data.Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL, IntPtr.Zero,
        ///     procHandle, startAddress, IntPtr.Zero, Data.Native.NT_CREATION_FLAGS.HIDE_FROM_DEBUGGER, 0, 0, 0, IntPtr.Zero);
        /// 
        /// </example>
        public struct DELEGATES
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Data.Native.NTSTATUS NtCreateSection(
                ref IntPtr SectionHandle,
                uint DesiredAccess,
                IntPtr ObjectAttributes,
                ref ulong MaximumSize,
                uint SectionPageProtection,
                uint AllocationAttributes,
                IntPtr FileHandle);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Data.Native.NTSTATUS NtUnmapViewOfSection(
                IntPtr hProc,
                IntPtr baseAddr);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Data.Native.NTSTATUS NtMapViewOfSection(
                IntPtr SectionHandle,
                IntPtr ProcessHandle,
                out IntPtr BaseAddress,
                IntPtr ZeroBits,
                IntPtr CommitSize,
                IntPtr SectionOffset,
                out ulong ViewSize,
                uint InheritDisposition,
                uint AllocationType,
                uint Win32Protect);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlInitUnicodeString(
                ref Data.Native.UNICODE_STRING DestinationString,
                [MarshalAs(UnmanagedType.LPWStr)]
                string SourceString);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlZeroMemory(
                IntPtr Destination,
                int length);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtQueryInformationProcess(
                IntPtr processHandle,
                Data.Native.PROCESSINFOCLASS processInformationClass,
                IntPtr processInformation,
                int processInformationLength,
                ref UInt32 returnLength);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 RtlUnicodeStringToAnsiString(
                ref Data.Native.ANSI_STRING DestinationString,
                ref Data.Native.UNICODE_STRING SourceString,
                bool AllocateDestinationString);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 LdrGetProcedureAddress(
                IntPtr hModule,
                IntPtr FunctionName,
                IntPtr Ordinal,
                ref IntPtr FunctionAddress);
        }
    }
}
