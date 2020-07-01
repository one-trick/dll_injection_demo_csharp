using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;



namespace dll_injection_demo_csharp
{
    class Program
    {
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }


        [DllImport("kernel32.dll", SetLastError = true)]

        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);

        // Memory allocation constants
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 4;

        public static bool is64Bit(Process process)
        {
            ushort processMachine;
            ushort nativeMachine;
            IsWow64Process2(process.Handle, out processMachine, out nativeMachine);

            if(processMachine == 0)
            {
                // 64 bit application
                Console.WriteLine("Target process was 64-bit");
                return true;
            }

            return false;
        }

        static void Main(string[] args)
        {
            // Classic DLL Injection
            // Technique #1 from https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process 

            UIntPtr bytesWritten;

            // Path of the dll we want to inject
            string dllName = args[0];
            // Name of the process we want to inject into
            string targetProcess = args[1];

            // Return an array of Processes found
            Console.WriteLine("Attempting to find target process with the following name: " + targetProcess);
            Process[] localByName = Process.GetProcessesByName(targetProcess);

            if(is64Bit(localByName[0]))
            {
                Console.WriteLine("Can't inject a 32-bit DLL into a 64-bit process. Exiting.");
                System.Environment.Exit(1);
            }

            Console.WriteLine("Found process with PID: " + localByName[0].Id);
            // OpenProcess - grab target process handle
            IntPtr hProcess = OpenProcess(ProcessAccessFlags.All, false, localByName[0].Id);

            // Storing the address of LoadLibraryA
            IntPtr loadLibAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            // Allocating enough memory to store the location of the DLL
            IntPtr allocatedMemoryAddr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            // Writing the location of the DLL to memory
            WriteProcessMemory(hProcess, allocatedMemoryAddr, Encoding.Default.GetBytes(dllName), (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

            // Creates a thread in the target process, which will execute LoadLibraryA with an arg of allocatedMemAddr (location where we stored our DLL string)
            // loadLibraryAddr = Pointer to the application-defined function to be executed by the thread and represents the starting address of the thread in the remote process
            CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibAddr, allocatedMemoryAddr, 0, IntPtr.Zero);
        }
    }
}
