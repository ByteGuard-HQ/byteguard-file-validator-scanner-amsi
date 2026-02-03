
# ByteGuard.FileValidator.Scanner.Amsi ![NuGet Version](https://img.shields.io/nuget/v/ByteGuard.FileValidator.Scanners.Amsi)

`ByteGuard.FileValidator.Scanner.Amsi` is a Microsoft Antimalware Scan Interface (AMSI) specific antimalware scanner implementation for [`ByteGuard.FileValidator`](https://www.nuget.org/packages/ByteGuard.FileValidator).

 AMSI is a Windows API that allows applications to submit content for scanning and receive a verdict from the installed antimalware provider. It lets you route files through the OS antimalware engine (_for example Microsoft Defender or any other AMSI-integrated AV_) before they’re accepted by your application.

> ⚠️ **Important:** This package is one layer in a defense-in-depth strategy.  
> It does **not** replace endpoint protection, sandboxing, input validation, or other security controls.

> ⚠️ **Important:** This package uses the Microsoft Antimalware Scan Interface (AMSI) and will submit content to the installed antimalware engine on the host (_e.g., Microsoft Defender_). Malicious samples or test files (_such as the EICAR test file_) may trigger alerts and incidents in your security monitoring. Make sure your security/operations team is aware of this integration before running tests in shared or production environments.

## Features

- **AMSI-based** implementation of `IAntimalwareScanner` for `ByteGuard.FileValidator`
- Works with **any AMSI-compatible antivirus** installed on the host machine

## Prerequisites

- **Operating system**
  - Windows 10+ or Windows Server 2016+ (_AMSI is available and supported on these versions_).
- **Antimalware**
  - An AMSI-integrated antimalware engine installed and enabled (_e.g. Microsoft Defender Antivirus_).
- **Core packages**
  - [`ByteGuard.FileValidator`](https://www.nuget.org/packages/ByteGuard.FileValidator)

## Getting Started

### Installation
This package is published and installed via [NuGet](https://www.nuget.org/packages/ByteGuard.FileValidator.Scanner.Amsi).

Reference the package in your project:
```bash
dotnet add package ByteGuard.FileValidator.Scanner.Amsi
```

## Usage

```csharp
using ByteGuard.FileValidator;
using ByteGuard.FileValidator.Scanner.Amsi;

var amsiConfig = new AmsiScannerConfiguration()
{
    ApplicationName = "MyApplication"
};

var amsiScanner = new AmsiAntimalwareScanner(amsiConfig);

var configuration = //...;
var fileValidator = new FileValidator(configuration, amsiScanner);

var isValid = fileValidator.IsValidFile(fileStream, fileName);
```

The `FileValidator` will automatically scan the file once provided as argument, and whenever using either `IsValidFile` or `IsMalwareClean` functions.

## Configuration
`AmsiScannerConfiguration` supports the following settings:

| Settings | Required | Description |
| -- | -- | -- |
| `ApplicationName` | Yes | The logical name used when registering the AMSI session (_helps AV engines with context_). | 

### Example
```csharp
[HttpPost("upload")]
public async Task<IActionResult> Upload(IFormFile file)
{
    using var stream = file.OpenReadStream();

    var amsiConfig = new AmsiScannerConfiguration()
    {
        ApplicationName = "MyApplication"
    };

    var amsiScanner = new AmsiAntimalwareScanner(amsiConfig);

    var configuration = //...
    var validator = new FileValidator(configuration, amsiScanner);

    if (!validator.IsValidFile(file.FileName, stream))
    {
        return BadRequest("Invalid or unsupported file.");
    }

    // Proceed with processing/saving...
    
    return Ok();
}
```

### Testing the AMSI integration

If you verify the integration using known test signatures (for example, the EICAR test file), be aware that:

- The installed AV engine may quarantine or block the file.
- Alerts may be raised and forwarded to your SIEM / security team.
- In tightly monitored environments, you should coordinate with your security team before running such tests.


## Security notes & limitations

- AMSI relies on the underlying antimalware provider for detection. If the provider is disabled, misconfigured, or missing signatures, detection quality will be affected. 
- Attackers constantly attempt to evade or disable AMSI; **treat AMSI as a signal, not as a guarantee**.
- **Always** combine this package with:
  - Principle of least privilege for storage and processing
  - Endpoint protection and monitoring

## License

_ByteGuard.FileValidator.Scanner.Amsi is Copyright © ByteGuard Contributors - Provided under the MIT license._
