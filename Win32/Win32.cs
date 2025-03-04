using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

namespace pi
{
    class Win32
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateFileW(
            [MarshalAs(UnmanagedType.LPWStr)] string filename,
            [MarshalAs(UnmanagedType.U4)] FileAccess access,
            [MarshalAs(UnmanagedType.U4)] FileShare share,
            IntPtr securityAttributes,
            [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
            [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes,
            IntPtr templateFile
        );

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr CreateFileMapping(
            IntPtr hFile,
            IntPtr lpFileMappingAttributes,
            PageProtection flProtect,
            uint dwMaximumSizeHigh,
            uint dwMaximumSizeLow,
            string lpName
        );

        [DllImport("kernel32.dll")]
        public static extern IntPtr MapViewOfFileEx(
            IntPtr hFileMappingObject,
            FileMapAccessType dwDesiredAccess,
            uint dwFileOffsetHigh,
            uint dwFileOffsetLow,
            UIntPtr dwNumberOfBytesToMap,
            IntPtr lpBaseAddress
        );

        [DllImport("kernel32.dll")]
        public static extern bool GetFileSizeEx(IntPtr hFile, out long lpFileSize);

        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            uint dwSize,
            AllocationType flAllocationType,
            MemoryProtection flProtect
        );

        [DllImport("msvcrt.dll", EntryPoint = "memcpy", CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public static extern IntPtr memcpy(IntPtr dest, IntPtr src, UIntPtr count);

        [DllImport("kernel32.dll")]
        public static extern uint GetTempPath(
            uint nBufferLength,
            [Out] StringBuilder lpBuffer
        );

        [DllImport("kernel32.dll")]
        public static extern uint GetTempFileName(
            StringBuilder lpPathName,
            string lpPrefixString,
            uint uUnique,
            [Out] StringBuilder lpTempFileName
        );

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS RtlInitUnicodeString(
        	out UNICODE_STRING DestinationString,
        	[MarshalAs(UnmanagedType.LPWStr)] string SourceString
		);
		
		[DllImport("ntdll.dll", ExactSpelling = true)]
		public static extern NTSTATUS NtOpenFile(
			out IntPtr FileHandle,
			FileAccessRights DesiredAccess,
			ref OBJECT_ATTRIBUTES ObjectAttributes,
			out IO_STATUS_BLOCK IoStatusBlock,
			FileShare ShareAccess,
			uint OpenOptions
		);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtSetInformationFile(
            IntPtr FileHandle,
            out IO_STATUS_BLOCK IoStatusBlock,
            IntPtr FileInformation,
            int Length,
            FILE_INFORMATION_CLASS FileInformationClass
		);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtWriteFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr ApcRoutine, // Reserved parameter. Should be null.
            IntPtr ApcContext, // Reserved parameter. Should be null.
            out IO_STATUS_BLOCK IoStatusBlock,
            IntPtr Buffer,
            long Length,
            IntPtr ByteOffset,
            IntPtr Key
		);

		[DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
		public static extern NTSTATUS NtCreateSection(
			out IntPtr SectionHandle,
			SECTION_ACCESS DesiredAccess,
			IntPtr ObjectAttributes,
			ref UInt32 MaximumSize,
			PageProtection SectionPageProtection,
			UInt32 AllocationAttributes,
			IntPtr FileHandle
		);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateProcessEx(
        	out IntPtr ProcessHandle,
        	PROCESS_ACCESS_FLAGS DesiredAccess,
			IntPtr ObjectAttributes,
			IntPtr hInheritFromProcess,
			RTL_CLONE_PROCESS_FLAGS Flags,
			IntPtr SectionHandle,
			IntPtr DebugPort,
			IntPtr ExceptionPort,
			bool InJob
		);
	
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr GetCurrentProcess();

		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern uint GetProcessId(IntPtr handle);
	
		[DllImport("NTDLL.DLL", SetLastError=true)]
		public static extern NTSTATUS NtQueryInformationProcess(
			IntPtr hProcess,
			int pic,
			out PROCESS_BASIC_INFORMATION pbi,
			int cb,
			out int pSize
		);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool ReadProcessMemory(
			IntPtr hProcess,
			IntPtr lpBaseAddress,
			[Out] byte[] lpBuffer,
			int dwSize,
			IntPtr lpNumberOfBytesRead
		);

		[DllImport("userenv.dll", SetLastError=true)]
		public static extern bool CreateEnvironmentBlock(
			out IntPtr lpEnvironment,
			IntPtr hToken,
			bool bInherit
		);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS RtlCreateProcessParametersEx(
            out IntPtr pProcessParameters,
            IntPtr ImagePathName,
            IntPtr DllPath,
            IntPtr CurrentDirectory,
            IntPtr CommandLine,
            IntPtr Environment,
            IntPtr WindowTitle,
            IntPtr DesktopInfo,
            IntPtr pShellInfo,
            IntPtr pRuntimeData,
            RTL_USER_PROC_FLAGS Flags
		);

	    [DllImport("kernel32.dll", SetLastError = true)]
	    public static extern IntPtr VirtualAllocEx(
			IntPtr hProcess,
			IntPtr lpAddress,
			IntPtr dwSize,
			AllocationType flAllocationType,
			MemoryProtection flProtect
		);

	    [DllImport("kernel32.dll", SetLastError = true)]
	    public static extern bool WriteProcessMemory(
			IntPtr hProcess,
			IntPtr lpBaseAddress,
			IntPtr lpBuffer,
			int nSize,
			IntPtr lpNumberOfBytesWritten
		);

		[DllImport("ntdll.dll", SetLastError=true)]
		public static extern NTSTATUS NtCreateThreadEx(
			out IntPtr threadHandle,
			THREAD_ACCESS_FLAGS desiredAccess,
			IntPtr objectAttributes,
			IntPtr processHandle,
			IntPtr startAddress,
			IntPtr parameter,
			bool inCreateSuspended,
			Int32 stackZeroBits,
			Int32 sizeOfStack,
			Int32 maximumStackSize,
			IntPtr attributeList
		);

		[DllImport("ntdll.dll", ExactSpelling=true, SetLastError=false)]
		public static extern int NtClose(IntPtr hObject);

		public struct PROCESS_BASIC_INFORMATION
		{
		public NTSTATUS ExitStatus;
		public IntPtr PebBaseAddress;
		public UIntPtr AffinityMask;
		public int BasePriority;
		public UIntPtr UniqueProcessId;
		public UIntPtr InheritedFromUniqueProcessId;
		}

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public Int32 Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public UInt32 Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FILE_DISPOSITION_INFO
        {
            public bool DeleteFile;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IO_STATUS_BLOCK
        {
        public NTSTATUS status;
        public IntPtr information;
        }

		public enum THREAD_ACCESS_FLAGS : uint
		{
			THREAD_ALL_ACCESS = 0x001FFFFF,
			THREAD_TERMINATE = 0x00000001,
			THREAD_SUSPEND_RESUME = 0x00000002,
			THREAD_ALERT = 0x00000004,
			THREAD_GET_CONTEXT = 0x00000008,
			THREAD_SET_CONTEXT = 0x00000010,
			THREAD_SET_INFORMATION = 0x00000020,
			THREAD_SET_LIMITED_INFORMATION = 0x00000400,
			THREAD_QUERY_LIMITED_INFORMATION = 0x00000800
		}

		[Flags]
		public enum RTL_USER_PROC_FLAGS : uint
		{
			PARAMS_NORMALIZED = 0x00000001,
			PROFILE_USER = 0x00000002,
			PROFILE_KERNEL = 0x00000004,
			PROFILE_SERVER = 0x00000008,
			RESERVE_1MB = 0x00000020,
			RESERVE_16MB = 0x00000040,
			CASE_SENSITIVE = 0x00000080,
			DISABLE_HEAP_DECOMMIT = 0x00000100,
			DLL_REDIRECTION_LOCAL = 0x00001000,
			APP_MANIFEST_PRESENT = 0x00002000,
			IMAGE_KEY_MISSING = 0x00004000,
			OPTIN_PROCESS = 0x00020000
		}

        public enum RTL_CLONE_PROCESS_FLAGS : uint
        {
        	CREATE_SUSPENDED = 0x00000001,
        	INHERIT_HANDLES  = 0x00000002,
        	NO_SYNCHRONIZE = 0x00000004,
        }
	    [Flags]
	    public enum PROCESS_ACCESS_FLAGS : uint
	    {
	        PROCESS_ALL_ACCESS = 0x001F0FFF,
	        PROCESS_CREATE_PROCESS = 0x0080,
	        PROCESS_CREATE_THREAD = 0x0002,
	        PROCESS_DUP_HANDLE = 0x0040,
	        PROCESS_QUERY_INFORMATION = 0x0400,
	        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
	        PROCESS_SET_INFORMATION = 0x0200,
	        PROCESS_SET_QUOTA = 0x0100,
	        PROCESS_SUSPEND_RESUME = 0x0800,
	        PROCESS_TERMINATE = 0x0001,
	        PROCESS_VM_OPERATION = 0x0008,
	        PROCESS_VM_READ = 0x0010,
	        PROCESS_VM_WRITE = 0x0020,
	        SYNCHRONIZE = 0x00100000
	    }
		public enum SECTION_ACCESS : uint
		{
			// DesiredAccess
			SECTION_QUERY = 1,
			SECTION_MAP_WRITE = 2,
			SECTION_MAP_READ = 4,
			SECTION_MAP_EXECUTE = 8,
			SECTION_EXTEND_SIZE = 16,
			SECTION_MAP_EXECUTE_EXPLICIT = 32,
			SECTION_ALL_ACCESS = 0xF0000 | SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE
		}
		public enum FILE_INFORMATION_CLASS
		{
			FileDirectoryInformation = 1,     // 1
			FileFullDirectoryInformation,     // 2
			FileBothDirectoryInformation,     // 3
			FileBasicInformation,         // 4
			FileStandardInformation,      // 5
			FileInternalInformation,      // 6
			FileEaInformation,        // 7
			FileAccessInformation,        // 8
			FileNameInformation,          // 9
			FileRenameInformation,        // 10
			FileLinkInformation,          // 11
			FileNamesInformation,         // 12
			FileDispositionInformation,       // 13
			FilePositionInformation,      // 14
			FileFullEaInformation,        // 15
			FileModeInformation = 16,     // 16
			FileAlignmentInformation,     // 17
			FileAllInformation,           // 18
			FileAllocationInformation,    // 19
			FileEndOfFileInformation,     // 20
			FileAlternateNameInformation,     // 21
			FileStreamInformation,        // 22
			FilePipeInformation,          // 23
			FilePipeLocalInformation,     // 24
			FilePipeRemoteInformation,    // 25
			FileMailslotQueryInformation,     // 26
			FileMailslotSetInformation,       // 27
			FileCompressionInformation,       // 28
			FileObjectIdInformation,      // 29
			FileCompletionInformation,    // 30
			FileMoveClusterInformation,       // 31
			FileQuotaInformation,         // 32
			FileReparsePointInformation,      // 33
			FileNetworkOpenInformation,       // 34
			FileAttributeTagInformation,      // 35
			FileTrackingInformation,      // 36
			FileIdBothDirectoryInformation,   // 37
			FileIdFullDirectoryInformation,   // 38
			FileValidDataLengthInformation,   // 39
			FileShortNameInformation,     // 40
			FileHardLinkInformation=46    // 46    
		}

		[Flags]
		public enum GenericAccessRights : uint
		{
			None = 0,
			Access0 = 0x00000001,
			Access1 = 0x00000002,
			Access2 = 0x00000004,
			Access3 = 0x00000008,
			Access4 = 0x00000010,
			Access5 = 0x00000020,
			Access6 = 0x00000040,
			Access7 = 0x00000080,
			Access8 = 0x00000100,
			Access9 = 0x00000200,
			Access10 = 0x00000400,
			Access11 = 0x00000800,
			Access12 = 0x00001000,
			Access13 = 0x00002000,
			Access14 = 0x00004000,
			Access15 = 0x00008000,
			Delete = 0x00010000,
			ReadControl = 0x00020000,
			WriteDac = 0x00040000,
			WriteOwner = 0x00080000,
			Synchronize = 0x00100000,
			AccessSystemSecurity = 0x01000000,
			MaximumAllowed = 0x02000000,
			GenericAll = 0x10000000,
			GenericExecute = 0x20000000,
			GenericWrite = 0x40000000,
			GenericRead = 0x80000000,
		};

		[Flags]
		public enum FileAccessRights : uint
		{
			None = 0,
			ReadData = 0x0001,
			WriteData = 0x0002,
			AppendData = 0x0004,
			ReadEa = 0x0008,
			WriteEa = 0x0010,
			Execute = 0x0020,
			DeleteChild = 0x0040,
			ReadAttributes = 0x0080,
			WriteAttributes = 0x0100,
			GenericRead = GenericAccessRights.GenericRead,
			GenericWrite = GenericAccessRights.GenericWrite,
			GenericExecute = GenericAccessRights.GenericExecute,
			GenericAll = GenericAccessRights.GenericAll,
			Delete = GenericAccessRights.Delete,
			ReadControl = GenericAccessRights.ReadControl,
			WriteDac = GenericAccessRights.WriteDac,
			WriteOwner = GenericAccessRights.WriteOwner,
			Synchronize = GenericAccessRights.Synchronize,
			MaximumAllowed = GenericAccessRights.MaximumAllowed,
			AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity

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
        [Flags]
        public enum PageProtection : uint
        {
        NoAccess =     0x01,
        Readonly =     0x02,
        ReadWrite =    0x04,
        WriteCopy =    0x08,
        Execute =      0x10,
        ExecuteRead =      0x20,
        ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80,
        Guard =        0x100,
        NoCache =      0x200,
        WriteCombine =     0x400,
        }
        public enum FileMapAccessType : uint
        {
            Copy =      0x01,
            Write =     0x02,
            Read =      0x04,
            AllAccess = 0x08,
            Execute =   0x20,
        }

		public enum NTSTATUS : uint
		{
		    // Success
		    Success = 0x00000000,
		    Wait1 = 0x00000001,
		    Wait2 = 0x00000002,
		    Wait3 = 0x00000003,
		    Wait63 = 0x0000003f,
		    Abandoned = 0x00000080,
		    AbandonedWait0 = 0x00000080,
		    AbandonedWait1 = 0x00000081,
		    AbandonedWait2 = 0x00000082,
		    AbandonedWait3 = 0x00000083,
		    AbandonedWait63 = 0x000000bf,
		    UserApc = 0x000000c0,
		    KernelApc = 0x00000100,
		    Alerted = 0x00000101,
		    Timeout = 0x00000102,
		    Pending = 0x00000103,
		    Reparse = 0x00000104,
		    MoreEntries = 0x00000105,
		    NotAllAssigned = 0x00000106,
		    SomeNotMapped = 0x00000107,
		    OpLockBreakInProgress = 0x00000108,
		    VolumeMounted = 0x00000109,
		    RxActCommitted = 0x0000010a,
		    NotifyCleanup = 0x0000010b,
		    NotifyEnumDir = 0x0000010c,
		    NoQuotasForAccount = 0x0000010d,
		    PrimaryTransportConnectFailed = 0x0000010e,
		    PageFaultTransition = 0x00000110,
		    PageFaultDemandZero = 0x00000111,
		    PageFaultCopyOnWrite = 0x00000112,
		    PageFaultGuardPage = 0x00000113,
		    PageFaultPagingFile = 0x00000114,
		    CrashDump = 0x00000116,
		    ReparseObject = 0x00000118,
		    NothingToTerminate = 0x00000122,
		    ProcessNotInJob = 0x00000123,
		    ProcessInJob = 0x00000124,
		    ProcessCloned = 0x00000129,
		    FileLockedWithOnlyReaders = 0x0000012a,
		    FileLockedWithWriters = 0x0000012b,

		    // Informational
		    Informational = 0x40000000,
		    ObjectNameExists = 0x40000000,
		    ThreadWasSuspended = 0x40000001,
		    WorkingSetLimitRange = 0x40000002,
		    ImageNotAtBase = 0x40000003,
		    RegistryRecovered = 0x40000009,

		    // Warning
		    Warning = 0x80000000,
		    GuardPageViolation = 0x80000001,
		    DatatypeMisalignment = 0x80000002,
		    Breakpoint = 0x80000003,
		    SingleStep = 0x80000004,
		    BufferOverflow = 0x80000005,
		    NoMoreFiles = 0x80000006,
		    HandlesClosed = 0x8000000a,
		    PartialCopy = 0x8000000d,
		    DeviceBusy = 0x80000011,
		    InvalidEaName = 0x80000013,
		    EaListInconsistent = 0x80000014,
		    NoMoreEntries = 0x8000001a,
		    LongJump = 0x80000026,
		    DllMightBeInsecure = 0x8000002b,

		    // Error
		    Error = 0xc0000000,
		    Unsuccessful = 0xc0000001,
		    NotImplemented = 0xc0000002,
		    InvalidInfoClass = 0xc0000003,
		    InfoLengthMismatch = 0xc0000004,
		    AccessViolation = 0xc0000005,
		    InPageError = 0xc0000006,
		    PagefileQuota = 0xc0000007,
		    InvalidHandle = 0xc0000008,
		    BadInitialStack = 0xc0000009,
		    BadInitialPc = 0xc000000a,
		    InvalidCid = 0xc000000b,
		    TimerNotCanceled = 0xc000000c,
		    InvalidParameter = 0xc000000d,
		    NoSuchDevice = 0xc000000e,
		    NoSuchFile = 0xc000000f,
		    InvalidDeviceRequest = 0xc0000010,
		    EndOfFile = 0xc0000011,
		    WrongVolume = 0xc0000012,
		    NoMediaInDevice = 0xc0000013,
		    NoMemory = 0xc0000017,
		    NotMappedView = 0xc0000019,
		    UnableToFreeVm = 0xc000001a,
		    UnableToDeleteSection = 0xc000001b,
		    IllegalInstruction = 0xc000001d,
		    AlreadyCommitted = 0xc0000021,
		    AccessDenied = 0xc0000022,
		    BufferTooSmall = 0xc0000023,
		    ObjectTypeMismatch = 0xc0000024,
		    NonContinuableException = 0xc0000025,
		    BadStack = 0xc0000028,
		    NotLocked = 0xc000002a,
		    NotCommitted = 0xc000002d,
		    InvalidParameterMix = 0xc0000030,
		    ObjectNameInvalid = 0xc0000033,
		    ObjectNameNotFound = 0xc0000034,
		    ObjectNameCollision = 0xc0000035,
		    ObjectPathInvalid = 0xc0000039,
		    ObjectPathNotFound = 0xc000003a,
		    ObjectPathSyntaxBad = 0xc000003b,
		    DataOverrun = 0xc000003c,
		    DataLate = 0xc000003d,
		    DataError = 0xc000003e,
		    CrcError = 0xc000003f,
		    SectionTooBig = 0xc0000040,
		    PortConnectionRefused = 0xc0000041,
		    InvalidPortHandle = 0xc0000042,
		    SharingViolation = 0xc0000043,
		    QuotaExceeded = 0xc0000044,
		    InvalidPageProtection = 0xc0000045,
		    MutantNotOwned = 0xc0000046,
		    SemaphoreLimitExceeded = 0xc0000047,
		    PortAlreadySet = 0xc0000048,
		    SectionNotImage = 0xc0000049,
		    SuspendCountExceeded = 0xc000004a,
		    ThreadIsTerminating = 0xc000004b,
		    BadWorkingSetLimit = 0xc000004c,
		    IncompatibleFileMap = 0xc000004d,
		    SectionProtection = 0xc000004e,
		    EasNotSupported = 0xc000004f,
		    EaTooLarge = 0xc0000050,
		    NonExistentEaEntry = 0xc0000051,
		    NoEasOnFile = 0xc0000052,
		    EaCorruptError = 0xc0000053,
		    FileLockConflict = 0xc0000054,
		    LockNotGranted = 0xc0000055,
		    DeletePending = 0xc0000056,
		    CtlFileNotSupported = 0xc0000057,
		    UnknownRevision = 0xc0000058,
		    RevisionMismatch = 0xc0000059,
		    InvalidOwner = 0xc000005a,
		    InvalidPrimaryGroup = 0xc000005b,
		    NoImpersonationToken = 0xc000005c,
		    CantDisableMandatory = 0xc000005d,
		    NoLogonServers = 0xc000005e,
		    NoSuchLogonSession = 0xc000005f,
		    NoSuchPrivilege = 0xc0000060,
		    PrivilegeNotHeld = 0xc0000061,
		    InvalidAccountName = 0xc0000062,
		    UserExists = 0xc0000063,
		    NoSuchUser = 0xc0000064,
		    GroupExists = 0xc0000065,
		    NoSuchGroup = 0xc0000066,
		    MemberInGroup = 0xc0000067,
		    MemberNotInGroup = 0xc0000068,
		    LastAdmin = 0xc0000069,
		    WrongPassword = 0xc000006a,
		    IllFormedPassword = 0xc000006b,
		    PasswordRestriction = 0xc000006c,
		    LogonFailure = 0xc000006d,
		    AccountRestriction = 0xc000006e,
		    InvalidLogonHours = 0xc000006f,
		    InvalidWorkstation = 0xc0000070,
		    PasswordExpired = 0xc0000071,
		    AccountDisabled = 0xc0000072,
		    NoneMapped = 0xc0000073,
		    TooManyLuidsRequested = 0xc0000074,
		    LuidsExhausted = 0xc0000075,
		    InvalidSubAuthority = 0xc0000076,
		    InvalidAcl = 0xc0000077,
		    InvalidSid = 0xc0000078,
		    InvalidSecurityDescr = 0xc0000079,
		    ProcedureNotFound = 0xc000007a,
		    InvalidImageFormat = 0xc000007b,
		    NoToken = 0xc000007c,
		    BadInheritanceAcl = 0xc000007d,
		    RangeNotLocked = 0xc000007e,
		    DiskFull = 0xc000007f,
		    ServerDisabled = 0xc0000080,
		    ServerNotDisabled = 0xc0000081,
		    TooManyGuidsRequested = 0xc0000082,
		    GuidsExhausted = 0xc0000083,
		    InvalidIdAuthority = 0xc0000084,
		    AgentsExhausted = 0xc0000085,
		    InvalidVolumeLabel = 0xc0000086,
		    SectionNotExtended = 0xc0000087,
		    NotMappedData = 0xc0000088,
		    ResourceDataNotFound = 0xc0000089,
		    ResourceTypeNotFound = 0xc000008a,
		    ResourceNameNotFound = 0xc000008b,
		    ArrayBoundsExceeded = 0xc000008c,
		    FloatDenormalOperand = 0xc000008d,
		    FloatDivideByZero = 0xc000008e,
		    FloatInexactResult = 0xc000008f,
		    FloatInvalidOperation = 0xc0000090,
		    FloatOverflow = 0xc0000091,
		    FloatStackCheck = 0xc0000092,
		    FloatUnderflow = 0xc0000093,
		    IntegerDivideByZero = 0xc0000094,
		    IntegerOverflow = 0xc0000095,
		    PrivilegedInstruction = 0xc0000096,
		    TooManyPagingFiles = 0xc0000097,
		    FileInvalid = 0xc0000098,
		    InstanceNotAvailable = 0xc00000ab,
		    PipeNotAvailable = 0xc00000ac,
		    InvalidPipeState = 0xc00000ad,
		    PipeBusy = 0xc00000ae,
		    IllegalFunction = 0xc00000af,
		    PipeDisconnected = 0xc00000b0,
		    PipeClosing = 0xc00000b1,
		    PipeConnected = 0xc00000b2,
		    PipeListening = 0xc00000b3,
		    InvalidReadMode = 0xc00000b4,
		    IoTimeout = 0xc00000b5,
		    FileForcedClosed = 0xc00000b6,
		    ProfilingNotStarted = 0xc00000b7,
		    ProfilingNotStopped = 0xc00000b8,
		    NotSameDevice = 0xc00000d4,
		    FileRenamed = 0xc00000d5,
		    CantWait = 0xc00000d8,
		    PipeEmpty = 0xc00000d9,
		    CantTerminateSelf = 0xc00000db,
		    InternalError = 0xc00000e5,
		    InvalidParameter1 = 0xc00000ef,
		    InvalidParameter2 = 0xc00000f0,
		    InvalidParameter3 = 0xc00000f1,
		    InvalidParameter4 = 0xc00000f2,
		    InvalidParameter5 = 0xc00000f3,
		    InvalidParameter6 = 0xc00000f4,
		    InvalidParameter7 = 0xc00000f5,
		    InvalidParameter8 = 0xc00000f6,
		    InvalidParameter9 = 0xc00000f7,
		    InvalidParameter10 = 0xc00000f8,
		    InvalidParameter11 = 0xc00000f9,
		    InvalidParameter12 = 0xc00000fa,
		    MappedFileSizeZero = 0xc000011e,
		    TooManyOpenedFiles = 0xc000011f,
		    Cancelled = 0xc0000120,
		    CannotDelete = 0xc0000121,
		    InvalidComputerName = 0xc0000122,
		    FileDeleted = 0xc0000123,
		    SpecialAccount = 0xc0000124,
		    SpecialGroup = 0xc0000125,
		    SpecialUser = 0xc0000126,
		    MembersPrimaryGroup = 0xc0000127,
		    FileClosed = 0xc0000128,
		    TooManyThreads = 0xc0000129,
		    ThreadNotInProcess = 0xc000012a,
		    TokenAlreadyInUse = 0xc000012b,
		    PagefileQuotaExceeded = 0xc000012c,
		    CommitmentLimit = 0xc000012d,
		    InvalidImageLeFormat = 0xc000012e,
		    InvalidImageNotMz = 0xc000012f,
		    InvalidImageProtect = 0xc0000130,
		    InvalidImageWin16 = 0xc0000131,
		    LogonServer = 0xc0000132,
		    DifferenceAtDc = 0xc0000133,
		    SynchronizationRequired = 0xc0000134,
		    DllNotFound = 0xc0000135,
		    IoPrivilegeFailed = 0xc0000137,
		    OrdinalNotFound = 0xc0000138,
		    EntryPointNotFound = 0xc0000139,
		    ControlCExit = 0xc000013a,
		    PortNotSet = 0xc0000353,
		    DebuggerInactive = 0xc0000354,
		    CallbackBypass = 0xc0000503,
		    PortClosed = 0xc0000700,
		    MessageLost = 0xc0000701,
		    InvalidMessage = 0xc0000702,
		    RequestCanceled = 0xc0000703,
		    RecursiveDispatch = 0xc0000704,
		    LpcReceiveBufferExpected = 0xc0000705,
		    LpcInvalidConnectionUsage = 0xc0000706,
		    LpcRequestsNotAllowed = 0xc0000707,
		    ResourceInUse = 0xc0000708,
		    ProcessIsProtected = 0xc0000712,
		    VolumeDirty = 0xc0000806,
		    FileCheckedOut = 0xc0000901,
		    CheckOutRequired = 0xc0000902,
		    BadFileType = 0xc0000903,
		    FileTooLarge = 0xc0000904,
		    FormsAuthRequired = 0xc0000905,
		    VirusInfected = 0xc0000906,
		    VirusDeleted = 0xc0000907,
		    TransactionalConflict = 0xc0190001,
		    InvalidTransaction = 0xc0190002,
		    TransactionNotActive = 0xc0190003,
		    TmInitializationFailed = 0xc0190004,
		    RmNotActive = 0xc0190005,
		    RmMetadataCorrupt = 0xc0190006,
		    TransactionNotJoined = 0xc0190007,
		    DirectoryNotRm = 0xc0190008,
		    CouldNotResizeLog = 0xc0190009,
		    TransactionsUnsupportedRemote = 0xc019000a,
		    LogResizeInvalidSize = 0xc019000b,
		    RemoteFileVersionMismatch = 0xc019000c,
		    CrmProtocolAlreadyExists = 0xc019000f,
		    TransactionPropagationFailed = 0xc0190010,
		    CrmProtocolNotFound = 0xc0190011,
		    TransactionSuperiorExists = 0xc0190012,
		    TransactionRequestNotValid = 0xc0190013,
		    TransactionNotRequested = 0xc0190014,
		    TransactionAlreadyAborted = 0xc0190015,
		    TransactionAlreadyCommitted = 0xc0190016,
		    TransactionInvalidMarshallBuffer = 0xc0190017,
		    CurrentTransactionNotValid = 0xc0190018,
		    LogGrowthFailed = 0xc0190019,
		    ObjectNoLongerExists = 0xc0190021,
		    StreamMiniversionNotFound = 0xc0190022,
		    StreamMiniversionNotValid = 0xc0190023,
		    MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
		    CantOpenMiniversionWithModifyIntent = 0xc0190025,
		    CantCreateMoreStreamMiniversions = 0xc0190026,
		    HandleNoLongerValid = 0xc0190028,
		    NoTxfMetadata = 0xc0190029,
		    LogCorruptionDetected = 0xc0190030,
		    CantRecoverWithHandleOpen = 0xc0190031,
		    RmDisconnected = 0xc0190032,
		    EnlistmentNotSuperior = 0xc0190033,
		    RecoveryNotNeeded = 0xc0190034,
		    RmAlreadyStarted = 0xc0190035,
		    FileIdentityNotPersistent = 0xc0190036,
		    CantBreakTransactionalDependency = 0xc0190037,
		    CantCrossRmBoundary = 0xc0190038,
		    TxfDirNotEmpty = 0xc0190039,
		    IndoubtTransactionsExist = 0xc019003a,
		    TmVolatile = 0xc019003b,
		    RollbackTimerExpired = 0xc019003c,
		    TxfAttributeCorrupt = 0xc019003d,
		    EfsNotAllowedInTransaction = 0xc019003e,
		    TransactionalOpenNotAllowed = 0xc019003f,
		    TransactedMappingUnsupportedRemote = 0xc0190040,
		    TxfMetadataAlreadyPresent = 0xc0190041,
		    TransactionScopeCallbacksNotSet = 0xc0190042,
		    TransactionRequiredPromotion = 0xc0190043,
		    CannotExecuteFileInTransaction = 0xc0190044,
		    TransactionsNotFrozen = 0xc0190045,

		    MaximumNtStatus = 0xffffffff
		}
    }
}
