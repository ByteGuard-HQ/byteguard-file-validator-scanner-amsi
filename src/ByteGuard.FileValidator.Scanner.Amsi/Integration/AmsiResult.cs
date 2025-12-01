namespace ByteGuard.FileValidator.Scanner.Amsi.Integration;

/// <summary>
/// Result returned by AMSI.
/// </summary>
/// <remarks>
/// <see href="https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result">Documentation</see>
/// </remarks>
internal enum AmsiResult
{
    /// <summary>
    /// Known good. No detection found, and the result is likely not going to change after a future definition update.
    /// </summary>
    AMSI_RESULT_CLEAN = 0,

    /// <summary>
    /// No detection found, but the result might change after a future definition update.
    /// </summary>
    AMSI_RESULT_NOT_DETECTED = 1,

    /// <summary>
    /// Administrator policy blocked this content on this machine (beginning of range).
    /// </summary>
    AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384,

    /// <summary>
    /// Administrator policy blocked this content on this machine (end of range).
    /// </summary>
    AMSI_RESULT_BLOCKED_BY_ADMIN_END = 20479,

    /// <summary>
    /// Detection found. The content is considered malware and should be blocked.
    /// </summary>
    AMSI_RESULT_DETECTED = 32768
}
