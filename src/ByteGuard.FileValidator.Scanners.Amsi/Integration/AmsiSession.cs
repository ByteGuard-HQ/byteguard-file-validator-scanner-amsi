using System.ComponentModel;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace ByteGuard.FileValidator.Scanners.Amsi.Integration;

/// <summary>
/// Safe handle for the AMSI session handle.
/// </summary>
#if NET5_0_OR_GREATER
[SupportedOSPlatform("windows")]
#endif
internal class AmsiSessionSafeHandle : SafeHandleMinusOneIsInvalid
{
    internal AmsiContextSafeHandle Context { get; set; }

    internal AmsiSessionSafeHandle(AmsiContextSafeHandle context)
        : base(ownsHandle: true)
    {
        Context = context;
    }

    protected override bool ReleaseHandle()
    {
        Amsi.AmsiCloseSession(Context, handle);
        return true;
    }
}

#if NET5_0_OR_GREATER
[SupportedOSPlatform("windows")]
#endif
internal sealed class AmsiSession : IDisposable
{
    private readonly AmsiContext context;
    private readonly AmsiSessionSafeHandle sessionHandle;

    internal AmsiSession(AmsiContext context, AmsiSessionSafeHandle sessionHandle)
    {
        this.context = context;
        this.sessionHandle = sessionHandle;
    }

    /// <summary>
    /// Scan a string for malware using Windows Antimalware Scan Interface (AMSI).
    /// </summary>
    /// <param name="payload">String content to scan.</param>
    /// <param name="contentName">Name or identifier of the content being scanned.</param>
    /// <returns><c>true</c> if the content is detected as malware, <c>false</c> otherwise.</returns>
    /// <exception cref="Win32Exception">Thrown if the scan resulted in an internal AMSI error.</exception>
    public bool IsMalware(string payload, string contentName)
    {
        var returnValue = Amsi.AmsiScanString(context.handle, payload, contentName, sessionHandle, out var result);

        if (returnValue != 0)
            throw new Win32Exception(returnValue);

        return Amsi.AmsiResultIsMalware(result);
    }

    /// <summary>
    /// Scan a byte buffer for malware using Windows Antimalware Scan Interface (AMSI).
    /// </summary>
    /// <param name="payload">Byte buffer payload to scan.</param>
    /// <param name="contentName">Name or identifier of the content being scanned.</param>
    /// <returns><c>true</c> if the content is detected as malware, <c>false</c> otherwise.</returns>
    /// <exception cref="Win32Exception">Thrown if the scan resulted in an internal AMSI error.</exception>
    public bool IsMalware(byte[] payload, string contentName)
    {
        var returnValue = Amsi.AmsiScanBuffer(context.handle, payload, (uint)payload.Length, contentName, sessionHandle, out var result);

        if (returnValue != 0)
            throw new Win32Exception(returnValue);

        return Amsi.AmsiResultIsMalware(result);
    }

    public void Dispose()
    {
        sessionHandle.Dispose();
    }
}
