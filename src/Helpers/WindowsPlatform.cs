namespace Loupedeck.AntigravityControllerPlugin.Helpers
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Runtime.Versioning;
    using System.Text;
    using System.Threading;
    using Microsoft.Win32;

    // Windows counterparts of the macOS tools the plugin uses (ps, lsof, open -a, osascript keystrokes, sqlite3)
    [SupportedOSPlatform("windows")]
    internal static class WindowsPlatform
    {
        // Command lines never change for a running process, so only new pids are read
        private static readonly Dictionary<Int32, String> CommandLineCache = new();
        private static readonly Object CacheLock = new();

        // ---------------------------------------------------------------- Processes (ps)

        // "pid commandline" lines of the running Antigravity language servers, like `ps -ax -o pid,command`
        public static String ListLanguageServers()
        {
            var running = new HashSet<Int32>();
            foreach (var p in Process.GetProcesses())
            {
                using (p)
                {
                    if (p.ProcessName.StartsWith("language_server", StringComparison.OrdinalIgnoreCase))
                    {
                        running.Add(p.Id);
                    }
                }
            }

            lock (CacheLock)
            {
                foreach (var gone in CommandLineCache.Keys.Where(pid => !running.Contains(pid)).ToList())
                {
                    CommandLineCache.Remove(gone);
                }

                foreach (var pid in running.Where(pid => !CommandLineCache.ContainsKey(pid)))
                {
                    var commandLine = GetCommandLine(pid);
                    if (commandLine != null)
                    {
                        CommandLineCache[pid] = commandLine;
                    }
                }

                return String.Join('\n', CommandLineCache
                    .Where(kv => running.Contains(kv.Key))
                    .Select(kv => $"{kv.Key} {kv.Value}"));
            }
        }

        private const UInt32 ProcessQueryLimitedInformation = 0x1000;
        private const Int32 ProcessCommandLineInformation = 60;

        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeString
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(UInt32 access, Boolean inherit, Int32 pid);

        [DllImport("kernel32.dll")]
        private static extern Boolean CloseHandle(IntPtr handle);

        [DllImport("ntdll.dll")]
        private static extern Int32 NtQueryInformationProcess(IntPtr process, Int32 infoClass, IntPtr info, Int32 size, out Int32 returnLength);

        // Command line of another process of the same user (Windows 8.1 and later)
        private static String GetCommandLine(Int32 pid)
        {
            var process = OpenProcess(ProcessQueryLimitedInformation, false, pid);
            if (process == IntPtr.Zero)
            {
                return null;
            }

            try
            {
                NtQueryInformationProcess(process, ProcessCommandLineInformation, IntPtr.Zero, 0, out var size);
                if (size <= 0)
                {
                    return null;
                }

                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    if (NtQueryInformationProcess(process, ProcessCommandLineInformation, buffer, size, out _) != 0)
                    {
                        return null;
                    }
                    var str = Marshal.PtrToStructure<UnicodeString>(buffer);
                    return Marshal.PtrToStringUni(str.Buffer, str.Length / 2);
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            finally
            {
                CloseHandle(process);
            }
        }

        // ---------------------------------------------------------------- Listening ports (lsof)

        private const Int32 AfInet = 2;
        private const Int32 AfInet6 = 23;
        private const Int32 TcpTableOwnerPidListener = 3;

        [StructLayout(LayoutKind.Sequential)]
        private struct MibTcpRowOwnerPid
        {
            public UInt32 State;
            public UInt32 LocalAddr;
            public UInt32 LocalPort;
            public UInt32 RemoteAddr;
            public UInt32 RemotePort;
            public UInt32 OwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MibTcp6RowOwnerPid
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public Byte[] LocalAddr;
            public UInt32 LocalScopeId;
            public UInt32 LocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public Byte[] RemoteAddr;
            public UInt32 RemoteScopeId;
            public UInt32 RemotePort;
            public UInt32 State;
            public UInt32 OwningPid;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern UInt32 GetExtendedTcpTable(IntPtr pTcpTable, ref Int32 dwOutBufLen, Boolean sort,
            Int32 ipVersion, Int32 tblClass, UInt32 reserved);

        // TCP ports (IPv4 and IPv6) the process listens on
        public static List<Int32> GetListeningPorts(Int32 pid)
        {
            var ports = new HashSet<Int32>();

            // IPv4
            var size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidListener, 0);
            if (size > 0)
            {
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    if (GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidListener, 0) == 0)
                    {
                        var count = Marshal.ReadInt32(buffer);
                        var rowPtr = buffer + 4;
                        var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
                        for (var i = 0; i < count; i++, rowPtr += rowSize)
                        {
                            var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
                            if (row.OwningPid == pid)
                            {
                                // Port is in network byte order in the low 16 bits
                                ports.Add((Int32)(((row.LocalPort & 0xFF) << 8) | ((row.LocalPort >> 8) & 0xFF)));
                            }
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            // IPv6
            size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet6, TcpTableOwnerPidListener, 0);
            if (size > 0)
            {
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    if (GetExtendedTcpTable(buffer, ref size, false, AfInet6, TcpTableOwnerPidListener, 0) == 0)
                    {
                        var count = Marshal.ReadInt32(buffer);
                        var rowPtr = buffer + 4;
                        var rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();
                        for (var i = 0; i < count; i++, rowPtr += rowSize)
                        {
                            var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(rowPtr);
                            if (row.OwningPid == pid)
                            {
                                ports.Add((Int32)(((row.LocalPort & 0xFF) << 8) | ((row.LocalPort >> 8) & 0xFF)));
                            }
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            return ports.OrderBy(p => p).ToList();
        }

        // ---------------------------------------------------------------- Windows (open -a, lsappinfo)

        private const Int32 SwShow = 5;
        private const Int32 SwRestore = 9;
        private const Byte VkMenu = 0x12;
        private const UInt32 KeyEventFKeyUp = 0x0002;
        private const UInt32 GaRoot = 2;

        [DllImport("user32.dll")]
        private static extern Boolean SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern Boolean ShowWindow(IntPtr hWnd, Int32 nCmdShow);

        [DllImport("user32.dll")]
        private static extern Boolean BringWindowToTop(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern Boolean IsIconic(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern Boolean IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern void keybd_event(Byte bVk, Byte bScan, UInt32 dwFlags, UIntPtr dwExtraInfo);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern IntPtr GetAncestor(IntPtr hWnd, UInt32 gaFlags);

        [DllImport("user32.dll")]
        private static extern UInt32 GetWindowThreadProcessId(IntPtr hWnd, out UInt32 lpdwProcessId);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern Int32 GetClassName(IntPtr hWnd, StringBuilder lpClassName, Int32 nMaxCount);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern Boolean GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public Int32 Left;
            public Int32 Top;
            public Int32 Right;
            public Int32 Bottom;
        }

        private delegate Boolean EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern Boolean EnumWindows(EnumWindowsProc enumProc, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr OpenInputDesktop(UInt32 dwFlags, Boolean fInherit, UInt32 dwDesiredAccess);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern Boolean SetThreadDesktop(IntPtr hDesktop);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern Boolean CloseDesktop(IntPtr hDesktop);

        [DllImport("user32.dll")]
        private static extern IntPtr GetThreadDesktop(UInt32 dwThreadId);

        [DllImport("kernel32.dll")]
        private static extern UInt32 GetCurrentThreadId();

        // appName is both the process name and the install folder, e.g. %LOCALAPPDATA%\Programs\Antigravity IDE\Antigravity IDE.exe
        public static Boolean HasOpenWindow(String appName) => FindMainWindow(appName) != IntPtr.Zero;

        // Brings the app's main window to the front, or starts the app when it is not running.
        // Returns the window, or IntPtr.Zero when the app had to be started (no window yet)
        public static IntPtr ActivateApp(String appName)
        {
            var hWnd = FindMainWindow(appName);
            if (hWnd == IntPtr.Zero)
            {
                StartApp(appName);
                return IntPtr.Zero;
            }

            if (IsIconic(hWnd))
            {
                ShowWindow(hWnd, SwRestore);
            }
            else
            {
                ShowWindow(hWnd, SwShow);
            }

            BringWindowToTop(hWnd);

            // Windows only lets the process that received the last input change the foreground window;
            // a synthetic Alt press lifts that restriction for the Logi Plugin Service
            keybd_event(VkMenu, 0, 0, UIntPtr.Zero);
            keybd_event(VkMenu, 0, KeyEventFKeyUp, UIntPtr.Zero);
            SetForegroundWindow(hWnd);
            return hWnd;
        }

        public static IntPtr FindMainWindow(String appName)
        {
            var origDesk = GetThreadDesktop(GetCurrentThreadId());
            var inputDesk = OpenInputDesktop(0, false, 0x01FF);
            var switched = false;
            if (inputDesk != IntPtr.Zero && inputDesk != origDesk)
            {
                switched = SetThreadDesktop(inputDesk);
            }

            try
            {
                var pids = new HashSet<Int32>();
                foreach (var p in Process.GetProcessesByName(appName))
                {
                    using (p)
                    {
                        if (p.MainWindowHandle != IntPtr.Zero && (IsWindowVisible(p.MainWindowHandle) || IsIconic(p.MainWindowHandle)))
                        {
                            GetWindowRect(p.MainWindowHandle, out var rect);
                            if (rect.Right - rect.Left > 100 && rect.Bottom - rect.Top > 100)
                            {
                                return p.MainWindowHandle;
                            }
                        }
                        pids.Add(p.Id);
                    }
                }

                if (pids.Count == 0)
                {
                    return IntPtr.Zero;
                }

                // Electron / Chromium apps often have MainWindowHandle == 0 on the parent process
                // while an active Chrome_WidgetWin_1 window exists on one of its child processes or threads.
                IntPtr best = IntPtr.Zero;
                EnumWindows((hWnd, lParam) =>
                {
                    GetWindowThreadProcessId(hWnd, out var pid);
                    if (pids.Contains((Int32)pid))
                    {
                        var sbClass = new StringBuilder(256);
                        GetClassName(hWnd, sbClass, 256);
                        var className = sbClass.ToString();

                        if (className == "Chrome_WidgetWin_0" || className == "Electron_NotifyIconHostWindow" ||
                            className.Contains("IME") || className.Contains("PowerMessage"))
                        {
                            return true;
                        }

                        if (IsWindowVisible(hWnd) || IsIconic(hWnd))
                        {
                            GetWindowRect(hWnd, out var rect);
                            var w = rect.Right - rect.Left;
                            var h = rect.Bottom - rect.Top;
                            if (w > 100 && h > 100)
                            {
                                best = hWnd;
                                return false; // Found main window
                            }
                        }
                    }
                    return true;
                }, IntPtr.Zero);

                return best;
            }
            finally
            {
                if (switched && origDesk != IntPtr.Zero)
                {
                    SetThreadDesktop(origDesk);
                }
                if (inputDesk != IntPtr.Zero)
                {
                    CloseDesktop(inputDesk);
                }
            }
        }

        private static void StartApp(String appName)
        {
            var exe = ResolveAppExecutable(appName);
            if (exe == null)
            {
                PluginLog.Warning($"[Windows] {appName} is not running and executable was not found");
                return;
            }
            try
            {
                Process.Start(new ProcessStartInfo { FileName = exe, UseShellExecute = true })?.Dispose();
            }
            catch (Exception ex)
            {
                PluginLog.Warning($"[Windows] Failed to start {exe}: {ex.Message}");
            }
        }

        private static String ResolveAppExecutable(String appName)
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

            var candidates = new List<String>
            {
                Path.Combine(localAppData, "Programs", appName, appName + ".exe"),
                Path.Combine(localAppData, "Programs", appName.ToLowerInvariant(), appName + ".exe"),
                Path.Combine(programFiles, appName, appName + ".exe"),
                Path.Combine(programFilesX86, appName, appName + ".exe"),
                Path.Combine(programFiles, "Google", appName, appName + ".exe"),
                Path.Combine(localAppData, "Google", appName, appName + ".exe")
            };

            foreach (var candidate in candidates)
            {
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }

            // Check Windows Registry App Paths
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey($@"Software\Microsoft\Windows\CurrentVersion\App Paths\{appName}.exe")
                             ?? Registry.LocalMachine.OpenSubKey($@"Software\Microsoft\Windows\CurrentVersion\App Paths\{appName}.exe");
                var path = key?.GetValue("") as String;
                if (!String.IsNullOrEmpty(path) && File.Exists(path))
                {
                    return path;
                }
            }
            catch
            {
            }

            return null;
        }

        // ---------------------------------------------------------------- Keystrokes (osascript keystroke)

        private const UInt32 InputKeyboard = 1;
        private const UInt16 VkControl = 0x11;
        private const UInt16 VkShift = 0x10;

        [StructLayout(LayoutKind.Sequential)]
        private struct KeybdInput
        {
            public UInt16 Vk;
            public UInt16 Scan;
            public UInt32 Flags;
            public UInt32 Time;
            public IntPtr ExtraInfo;
        }

        // INPUT is a union; 40 bytes on 64-bit Windows, 28 bytes on 32-bit Windows
        [StructLayout(LayoutKind.Explicit, Size = 40)]
        private struct Input
        {
            [FieldOffset(0)] public UInt32 Type;
            [FieldOffset(8)] public KeybdInput Ki;
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern UInt32 SendInput(UInt32 nInputs, Input[] pInputs, Int32 cbSize);

        // Activates the app, waits for it to take focus and sends Ctrl+Shift+<key>. Sends nothing when the
        // app had to be started or its window did not come to the front, so the shortcut never lands in
        // another app. Returns whether it was sent
        public static Boolean SendCtrlShiftShortcut(String appName, Char key)
        {
            var hWnd = ActivateApp(appName);
            if (hWnd == IntPtr.Zero)
            {
                return false;
            }

            var waited = 0;
            while (waited < 1000)
            {
                var fg = GetForegroundWindow();
                if (fg == hWnd || (fg != IntPtr.Zero && GetAncestor(fg, GaRoot) == hWnd))
                {
                    break;
                }
                Thread.Sleep(50);
                waited += 50;
            }

            var currentFg = GetForegroundWindow();
            if (currentFg != hWnd && (currentFg == IntPtr.Zero || GetAncestor(currentFg, GaRoot) != hWnd))
            {
                return false;
            }
            Thread.Sleep(150); // let the window take keyboard focus

            var vk = (UInt16)Char.ToUpperInvariant(key);
            var inputs = new[]
            {
                KeyInput(VkControl, false), KeyInput(VkShift, false), KeyInput(vk, false),
                KeyInput(vk, true), KeyInput(VkShift, true), KeyInput(VkControl, true)
            };

            var sent = SendInput((UInt32)inputs.Length, inputs, Marshal.SizeOf<Input>());
            if (sent == 0)
            {
                // UIPI fallback via keybd_event
                keybd_event((Byte)VkControl, 0, 0, UIntPtr.Zero);
                keybd_event((Byte)VkShift, 0, 0, UIntPtr.Zero);
                keybd_event((Byte)vk, 0, 0, UIntPtr.Zero);
                keybd_event((Byte)vk, 0, KeyEventFKeyUp, UIntPtr.Zero);
                keybd_event((Byte)VkShift, 0, KeyEventFKeyUp, UIntPtr.Zero);
                keybd_event((Byte)VkControl, 0, KeyEventFKeyUp, UIntPtr.Zero);
            }
            return true;
        }

        private static Input KeyInput(UInt16 vk, Boolean up) =>
            new() { Type = InputKeyboard, Ki = new KeybdInput { Vk = vk, Flags = up ? KeyEventFKeyUp : 0 } };

        // ---------------------------------------------------------------- SQLite (sqlite3 CLI)

        // winsqlite3.dll ships with Windows 10 and later, so no SQLite library has to be bundled
        private const String WinSqlite = "winsqlite3.dll";
        private const Int32 SqliteOk = 0;
        private const Int32 SqliteRow = 100;
        private const Int32 SqliteOpenReadOnly = 0x00000001;

        [DllImport(WinSqlite, CallingConvention = CallingConvention.StdCall)]
        private static extern Int32 sqlite3_open_v2([MarshalAs(UnmanagedType.LPUTF8Str)] String filename, out IntPtr db, Int32 flags, IntPtr vfs);

        [DllImport(WinSqlite, CallingConvention = CallingConvention.StdCall)]
        private static extern Int32 sqlite3_busy_timeout(IntPtr db, Int32 ms);

        [DllImport(WinSqlite, CallingConvention = CallingConvention.StdCall)]
        private static extern Int32 sqlite3_close(IntPtr db);

        [DllImport(WinSqlite, CallingConvention = CallingConvention.StdCall)]
        private static extern Int32 sqlite3_prepare_v2(IntPtr db, [MarshalAs(UnmanagedType.LPUTF8Str)] String sql, Int32 nByte, out IntPtr stmt, IntPtr tail);

        [DllImport(WinSqlite, CallingConvention = CallingConvention.StdCall)]
        private static extern Int32 sqlite3_step(IntPtr stmt);

        [DllImport(WinSqlite, CallingConvention = CallingConvention.StdCall)]
        private static extern Int32 sqlite3_column_count(IntPtr stmt);

        [DllImport(WinSqlite, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr sqlite3_column_text(IntPtr stmt, Int32 col);

        [DllImport(WinSqlite, CallingConvention = CallingConvention.StdCall)]
        private static extern Int32 sqlite3_finalize(IntPtr stmt);

        // Rows of a read-only query, every column as text
        public static List<String[]> QuerySqlite(String path, String sql)
        {
            var rows = new List<String[]>();
            if (sqlite3_open_v2(path, out var db, SqliteOpenReadOnly, IntPtr.Zero) != SqliteOk)
            {
                sqlite3_close(db);
                return rows;
            }

            try
            {
                sqlite3_busy_timeout(db, 2000);

                if (sqlite3_prepare_v2(db, sql, -1, out var stmt, IntPtr.Zero) != SqliteOk)
                {
                    return rows;
                }

                try
                {
                    var columns = sqlite3_column_count(stmt);
                    while (sqlite3_step(stmt) == SqliteRow)
                    {
                        var row = new String[columns];
                        for (var i = 0; i < columns; i++)
                        {
                            row[i] = Marshal.PtrToStringUTF8(sqlite3_column_text(stmt, i)) ?? "";
                        }
                        rows.Add(row);
                    }
                }
                finally
                {
                    sqlite3_finalize(stmt);
                }
            }
            finally
            {
                sqlite3_close(db);
            }

            return rows;
        }
    }
}
