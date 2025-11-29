using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ByteGuard.FileValidator.Scanners.Amsi.Integration;

/// <summary>
/// Dynamically loaded Antimalware Scan Interface from System32. Will only work on Windows clients and servers.
/// </summary>
#if NET5_0_OR_GREATER
[SupportedOSPlatform("windows")]
#endif
internal static class Amsi
{
    /// <summary>
    /// Initialize the AMSI API.
    /// </summary>
    /// <param name="appName">The name, version, or GUID string of the app calling the AMSI API.</param>
    /// <param name="amsiContext">Out generated AMSI context that must be passed to all subsequent calls to the AMSI API.</param>
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("Amsi.dll", EntryPoint = "AmsiInitialize", CallingConvention = CallingConvention.StdCall)]
    internal static extern int AmsiInitialize([MarshalAs(UnmanagedType.LPWStr)] string appName, out AmsiContextSafeHandle amsiContext);

    /// <summary>
    /// Remove the instance of the AMSI API that was originally opened by <see cref="AmsiInitialize"/>.
    /// </summary>
    /// <param name="amsiContext">The context handle that was initially received from <see cref="AmsiInitialize"/>.</param>
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("Amsi.dll", EntryPoint = "AmsiUninitialize", CallingConvention = CallingConvention.StdCall)]
    internal static extern void AmsiUninitialize(IntPtr amsiContext);

    /// <summary>
    /// Opens a session within which multiple scan requests can be correlated.
    /// </summary>
    /// <param name="amsiContext">The context handle that was initially received from <see cref="AmsiInitialize"/>.</param>
    /// <param name="session">Out generated AMSI session that must be passed to all subsequent calls to the AMSI API within the session.</param>
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("Amsi.dll", EntryPoint = "AmsiOpenSession", CallingConvention = CallingConvention.StdCall)]
    internal static extern int AmsiOpenSession(AmsiContextSafeHandle amsiContext, out AmsiSessionSafeHandle session);

    /// <summary>
    /// Close a session that was opened by <see cref="AmsiOpenSession"/>.
    /// </summary>
    /// <param name="amsiContext">The context handle that was initially received from <see cref="AmsiInitialize"/>.</param>
    /// <param name="session">The session handle that was initially received from <see cref="AmsiOpenSession"/>.</param>
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("Amsi.dll", EntryPoint = "AmsiCloseSession", CallingConvention = CallingConvention.StdCall)]
    internal static extern void AmsiCloseSession(AmsiContextSafeHandle amsiContext, IntPtr session);

    /// <summary>
    /// Scans a string for malware.
    /// </summary>
    /// <remarks>
    /// It's recommended to use <see cref="AmsiResultIsMalware"/> to interpret the returning result.
    /// </remarks>
    /// <param name="amsiContext">The context handle that was initially received from <see cref="AmsiInitialize"/>.</param>
    /// <param name="payload">The string to be scanned.</param>
    /// <param name="contentName">The filename, URL, unique script ID, or similar of the content being scanned.</param>
    /// <param name="session">If multiple scan requests are to be correlated within a session, set session to the session handle that was initially received from <see cref="AmsiOpenSession"/>. Otherwise, set session to <c>null</c>.</param>
    /// <param name="result">Out result of the scan (see <see cref="AmsiResult"/>).</param>
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("Amsi.dll", EntryPoint = "AmsiScanString", CallingConvention = CallingConvention.StdCall)]
    internal static extern int AmsiScanString(AmsiContextSafeHandle amsiContext, [In, MarshalAs(UnmanagedType.LPWStr)] string payload, [In, MarshalAs(UnmanagedType.LPWStr)] string contentName, AmsiSessionSafeHandle session, out AmsiResult result);

    /// <summary>
    /// Scans a buffer-full of content for malware.
    /// </summary>
    /// <remarks>
    /// It's recommended to use <see cref="AmsiResultIsMalware"/> to interpret the returning result.
    /// </remarks>
    /// <param name="amsiContext">The context handle that was initially received from <see cref="AmsiInitialize"/>.</param>
    /// <param name="buffer">The buffer from which to read the data to be scanned.</param>
    /// <param name="length">The length, in bytes, of the data to be read from buffer.</param>
    /// <param name="contentName">The filename, URL, unique script ID, or similar of the content being scanned.</param>
    /// <param name="session">If multiple scan requests are to be correlated within a session, set session to the session handle that was initially received from <see cref="AmsiOpenSession"/>. Otherwise, set session to <c>null</c>.</param>
    /// <param name="result">Out result of the scan (see <see cref="AmsiResult"/>).</param>
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("Amsi.dll", EntryPoint = "AmsiScanBuffer", CallingConvention = CallingConvention.StdCall)]
    internal static extern int AmsiScanBuffer(AmsiContextSafeHandle amsiContext, byte[] buffer, uint length, [In, MarshalAs(UnmanagedType.LPWStr)] string contentName, AmsiSessionSafeHandle session, out AmsiResult result);

    /// <summary>
    /// Determines if the result of a scan indicates that the content should be blocked.
    /// </summary>
    /// <param name="result">Result of a scan from either <see cref="AmsiScanString"/> or <see cref="AmsiScanBuffer"/>.</param>
    /// <returns><c>true</c> if the result is considered a malware detection, <c>false</c> otherwise.</returns>
    internal static bool AmsiResultIsMalware(AmsiResult result) => result >= AmsiResult.AMSI_RESULT_DETECTED;
}
