namespace ByteGuard.FileValidator.Scanners.Amsi;

/// <summary>
/// Configuration for the Microsoft Antimalware Scan Interface (AMSI) scanner.
/// </summary>
public class AmsiScannerConfiguration
{
    /// <summary>
    /// Name of the application integrating with Microsoft Antimalware Scan Interface (AMSI).
    /// </summary>
    /// <remarks>
    /// The name, version, or GUID string of the app calling the AMSI API.
    /// </remarks>
    public string ApplicationName { get; set; } = default!;
}
