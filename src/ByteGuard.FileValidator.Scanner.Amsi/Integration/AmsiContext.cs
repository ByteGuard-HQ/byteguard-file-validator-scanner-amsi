using System.ComponentModel;
#if NET5_0_OR_GREATER
using System.Runtime.Versioning;
#endif
using Microsoft.Win32.SafeHandles;

namespace ByteGuard.FileValidator.Scanner.Amsi.Integration;

/// <summary>
/// Safe handle for the AMSI context handle.
/// </summary>
#if NET5_0_OR_GREATER
[SupportedOSPlatform("windows")]
#endif
internal class AmsiContextSafeHandle : SafeHandleMinusOneIsInvalid
{
    internal AmsiContextSafeHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle()
    {
        Amsi.AmsiUninitialize(handle);
        return true;
    }
}

#if NET5_0_OR_GREATER
[SupportedOSPlatform("windows")]
#endif
internal sealed class AmsiContext : IDisposable
{
    internal readonly AmsiContextSafeHandle handle;

    private AmsiContext(AmsiContextSafeHandle handle)
    {
        this.handle = handle;
    }

    /// <summary>
    /// Instantiate a new AMSI context.
    /// </summary>
    /// <param name="applicationName">Name or identifier of the application.</param>
    /// <returns>A new <see cref="AmsiContext"/> instance.</returns>
    /// <exception cref="Win32Exception">Thrown if the instantiation resulted in an internal AMSI error.</exception>
    public static AmsiContext Create(string applicationName)
    {
        int result = Amsi.AmsiInitialize(applicationName, out var ctx);

        if (result != 0)
            throw new Win32Exception(result);

        return new AmsiContext(ctx);
    }

    /// <summary>
    /// Instantiate a new AMSI session.
    /// </summary>
    /// <remarks>
    /// AMSI sessions are used when multiple files should be scanned in the same context.
    /// </remarks>
    /// <returns>A new <see cref="AmsiSession"/> instance.</returns>
    /// <exception cref="Win32Exception">Thrown if the instantiation resulted in an internal AMSI error.</exception>
    public AmsiSession CreateSession()
    {
        var result = Amsi.AmsiOpenSession(handle, out var session);
        session.Context = handle;

        if (result != 0)
            throw new Win32Exception(result);

        return new AmsiSession(this, session);
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
        var returnValue = Amsi.AmsiScanString(handle, payload, contentName, new AmsiSessionSafeHandle(handle), out var result);

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
        var returnValue = Amsi.AmsiScanBuffer(handle, payload, (uint)payload.Length, contentName, new AmsiSessionSafeHandle(handle), out var result);

        if (returnValue != 0)
            throw new Win32Exception(returnValue);

        return Amsi.AmsiResultIsMalware(result);
    }

    public void Dispose()
    {
        handle.Dispose();
    }
}
