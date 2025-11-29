
# ByteGuard.FileValidator.Scanners.Amsi ![NuGet Version](https://img.shields.io/nuget/v/ByteGuard.FileValidator.Scanners.Amsi)

`ByteGuard.FileValidator.Scanners.Amsi` is a Microsoft Antimalware Scan Interface (AMSI) specific antimalware scanner implementation for [`ByteGuard.FileValidator`](https://www.nuget.org/packages/ByteGuard.FileValidator).

 AMSI is a Windows API that allows applications to submit content for scanning and receive a verdict from the installed antimalware provider. It lets you route files through the OS antimalware engine (_for example Microsoft Defender or any other AMSI-integrated AV_) before they’re accepted by your application.

> ⚠️ **Important:** This package is one layer in a defense-in-depth strategy.  
> It does **not** replace endpoint protection, sandboxing, input validation, or other security controls.

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
  - Optionally [`ByteGuard.FileValidator.Extensions.DependencyInjection`](https://www.nuget.org/packages/ByteGuard.FileValidator.Extensions.DependencyInjection) for `Microsoft.Extensions.DependencyInjection` integration

## Getting Started

### Installation
This package is published and installed via [NuGet](https://www.nuget.org/packages/ByteGuard.FileValidator.Scanners.Amsi).

Reference the package in your project:
```bash
dotnet add package ByteGuard.FileValidator.Scanners.Amsi
```

## Usage

```csharp
using ByteGuard.FileValidator;
using ByteGuard.FileValidator.Scanners.Amsi;

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

## Security notes & limitations

- AMSI relies on the underlying antimalware provider for detection. If the provider is disabled, misconfigured, or missing signatures, detection quality will be affected. 
- Attackers constantly attempt to evade or disable AMSI; **treat AMSI as a signal, not as a guarantee**.
- **Always** combine this package with:
  - Principle of least privilege for storage and processing
  - Endpoint protection and monitoring

## License
_ByteGuard.FileValidator.Scanners.Amsi is Copyright © ByteGuard Contributors - Provided under the MIT license._