# KeePass Record Exchange Plugin

`keepass_plugin01` extends KeePass 2.x with an encrypted exchange mechanism for complete records. One or more selected records can be transferred between KeePass instances using the Windows clipboard or an encrypted `.kprx` file.

The plugin transfers:

- standard fields such as title, user name, password, URL, and notes;
- custom fields and their protection status;
- tags, expiration status, and expiration time;
- the standard icon;
- file attachments.

UUIDs, creation and modification timestamps, and record history are not transferred. Importing always creates a new KeePass record.

## Features

The plugin adds the following commands under **Tools → Record Exchange** and to the record context menu:

| Command | Purpose |
|---|---|
| `Copy Record(s) Encrypted` | Encrypts all selected records and places the encrypted container on the Windows clipboard. |
| `Paste Record(s) Encrypted` | Reads and decrypts a container from the clipboard and creates new records. |
| `Export Record(s) to File` | Exports all selected records to an encrypted `.kprx` file. |
| `Import Record(s) from File` | Decrypts a `.kprx` file and imports all contained records. |
| `Settings...` | Configures clipboard lifetime and clearing after a successful paste. |

Multiple records can be selected using `Ctrl` or `Shift` and transferred in a single operation.

## Security Design

The complete record payload is encrypted before it is placed on the clipboard or written to a file. Only the technical parameters required for key derivation and decryption remain visible.

The plugin uses:

- PBKDF2-HMAC-SHA-256 key derivation;
- 600,000 iterations;
- a new 16-byte random salt for every export;
- AES-256-GCM encryption;
- a new 12-byte random nonce for every export;
- a 128-bit authentication tag;
- additional authenticated data containing the format and version identifier.

AES-GCM provides confidentiality and integrity. An incorrect password and a modified container intentionally result in the same error message.

### Transfer Password

The transfer password:

- is requested twice when copying or exporting;
- must contain at least 12 characters;
- is not stored in the container;
- should not be identical to the master password of a KeePass database.

Use a separate, long passphrase, for example:

```text
Sailboat-Copper-Atlas-Danube-47
```

Encryption cannot compensate for a weak transfer password. A stored `.kprx` file can be used for offline password-guessing attacks.

### Clipboard Protection

`Copy Record(s) Encrypted` places only the encrypted container on the clipboard. The plugin also sets these Windows clipboard formats:

```text
ExcludeClipboardContentFromMonitorProcessing
CanIncludeInClipboardHistory = 0
CanUploadToCloudClipboard = 0
```

They request that Windows exclude the content from Clipboard History and Cloud Clipboard synchronization.

The clipboard content is also:

- automatically cleared after the configured number of seconds;
- optionally cleared immediately after a successful paste;
- cleared when the plugin terminates.

The default lifetime is 30 seconds and can be configured between 5 and 600 seconds. The clipboard is cleared only if it still contains exactly the value written by the plugin. Content copied by the user in the meantime is not removed.

These measures cannot guarantee that malware or a third-party clipboard manager will not read the content first. Such a process receives an encrypted container rather than plaintext record contents.

## Persistent Settings

Settings are stored using KeePass `CustomConfig` and loaded when the plugin starts:

```text
Zentric.KeePassRecordExchange.ClipboardLifetimeSeconds
Zentric.KeePassRecordExchange.ClearClipboardAfterPaste
```

The settings dialog provides:

- **Clear clipboard after:** 5 to 600 seconds;
- **Clear clipboard immediately after a successful paste**.

Clipboard History and Cloud Clipboard exclusion remain permanently enabled for security reasons.

## Development Requirements

### Software

- Windows 10 or Windows 11;
- KeePass 2.x, preferably the current official release;
- Visual Studio with the **.NET desktop development** workload;
- .NET Framework 4.8 Developer Pack;
- NuGet Package Manager.

Create the project using:

```text
C# → Class Library (.NET Framework)
```

Target framework:

```text
.NET Framework 4.8
```

Do not use `.NET Standard`, `.NET Core`, .NET 6, or another modern .NET class-library template. KeePass 2.x loads this plugin as a .NET Framework assembly.

## Required Assembly References

| Assembly | Source | Required setting |
|---|---|---|
| `KeePass` | Official `KeePass.exe` | `Copy Local = False` |
| `System` | .NET Framework | Default |
| `System.Drawing` | .NET Framework | Default |
| `System.Web.Extensions` | .NET Framework | Default |
| `System.Windows.Forms` | .NET Framework | Default |
| `BouncyCastle.Cryptography` | NuGet | `Copy Local = True` |

### Adding the KeePass Reference

1. Right-click **References** in Solution Explorer.
2. Select **Add Reference → Browse**.
3. Select an official `KeePass.exe`, for example:

   ```text
   D:\Program Files\KeePass Password Safe 2\KeePass.exe
   ```

4. Select the new `KeePass` reference.
5. Set `Copy Local` to `False`.

Whenever possible, reference the same KeePass version that will be used for testing. The official portable package can also be used as the reference source.

### Adding Framework References

Under **References → Add Reference → Assemblies → Framework**, enable:

```text
System.Drawing
System.Web.Extensions
System.Windows.Forms
```

### Installing BouncyCastle

Open **Tools → NuGet Package Manager → Package Manager Console** and run:

```powershell
Install-Package BouncyCastle.Cryptography -Version 2.7.0
```

`BouncyCastle.Cryptography` must then appear under **References** with:

```text
Copy Local = True
```

The build output must contain:

```text
BouncyCastle.Cryptography.dll
```

## KeePass Naming Conventions

KeePass expects a fixed relationship between assembly filename, namespace, and main plugin class:

| Element | Value used by this project |
|---|---|
| Plugin DLL | `keepass_plugin01.dll` |
| Namespace | `keepass_plugin01` |
| Main class | `keepass_plugin01Ext` |

```csharp
namespace keepass_plugin01
{
    public sealed class keepass_plugin01Ext : Plugin
    {
        // Plugin code
    }
}
```

If the project or DLL is renamed, update the namespace and class name accordingly.

## Assembly Information

KeePass uses assembly metadata to recognize a DLL as a plugin. In `Properties\AssemblyInfo.cs`, the product name must be exactly `KeePass Plugin`:

```csharp
[assembly: AssemblyTitle("KeePass Record Exchange")]
[assembly: AssemblyDescription("Encrypted exchange of KeePass records")]
[assembly: AssemblyCompany("Zentric")]
[assembly: AssemblyProduct("KeePass Plugin")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
```

Without `AssemblyProduct("KeePass Plugin")`, KeePass will not recognize the DLL as a plugin.

## Project Structure

```text
keepass_plugin01
├── Properties
│   └── AssemblyInfo.cs
├── keepass_plugin01Ext.cs
├── LICENSE
├── README.md
├── packages.config
└── keepass_plugin01.csproj
```

Depending on the NuGet configuration, a `PackageReference` may be used instead of `packages.config`.

## Building

1. Close KeePass completely.
2. Select `Debug`, or `Release` for distribution.
3. Select **Build → Rebuild Solution**.
4. Check the Error List.

Output is normally written to `bin\Debug\` or `bin\Release\`. At least these files must be present:

```text
keepass_plugin01.dll
BouncyCastle.Cryptography.dll
```

A class library cannot be launched directly using the normal Start command. Visual Studio's corresponding message is expected.

## Installation

1. Close KeePass completely.
2. Use **Tools → Plugins → Open Folder** to locate the actual plugin directory.
3. Copy these files from `bin\Debug` or `bin\Release` into that directory:

   ```text
   keepass_plugin01.dll
   BouncyCastle.Cryptography.dll
   ```

Example:

```text
D:\Program Files\KeePass Password Safe 2\Plugins\
```

4. Restart KeePass.
5. Open **Tools → Plugins** and verify that the plugin is listed.

After each build, replace at least `keepass_plugin01.dll`. If the BouncyCastle package version changed, replace `BouncyCastle.Cryptography.dll` as well.

## User Guide

### Copying Through the Clipboard

1. Select one or more records. Use `Ctrl` or `Shift` for multiple selection.
2. Select **Record Exchange → Copy Record(s) Encrypted**.
3. Enter a transfer password containing at least 12 characters.
4. Confirm the password.

The encrypted container remains on the clipboard for no longer than the configured lifetime.

### Pasting from the Clipboard

1. Switch to the receiving KeePass instance and database.
2. Select an existing record in the desired target group, or select the group itself.
3. Select **Record Exchange → Paste Record(s) Encrypted**.
4. Enter the transfer password used during copying.

If enabled in Settings, the encrypted container is removed immediately after a successful import.

### Exporting to a File

1. Select one or more records.
2. Select **Record Exchange → Export Record(s) to File**.
3. Enter and confirm a transfer password.
4. Select a filename and destination.

The plugin uses the `.kprx` extension. The file does not contain record fields in plaintext.

### Importing from a File

1. Select the target group or a record within it.
2. Select **Record Exchange → Import Record(s) from File**.
3. Select the `.kprx` file.
4. Enter the transfer password used during export.

The export file is not deleted automatically after import.

### Configuring Clipboard Behavior

1. Open **Record Exchange → Settings...**.
2. Set the clipboard lifetime between 5 and 600 seconds.
3. Enable or disable immediate clearing after a successful paste.
4. Select **Save**.

The settings take effect immediately and remain available after restarting KeePass. The settings window also displays:

```text
Author: Chris Ditze-Stephan
License: MIT - free to use, copy, modify and distribute
```

## Target Group Selection

The plugin selects the import group in this order:

1. If a record is selected, its parent group is used.
2. Otherwise, the currently selected group is used.
3. If no group can be determined, the database root group is used.

## Handling Existing Titles

Before importing each record, the plugin checks the target group for the same title using a case-insensitive comparison. If a collision occurs, `_copy` is appended:

```text
Server
Server_copy
Server_copy_copy
```

Existing records are never modified or overwritten.

## Container Format

Clipboard content and `.kprx` files use the same JSON-based format:

```json
{
  "Format": "KeePassRecordExchange",
  "Version": 1,
  "Kdf": "PBKDF2-HMAC-SHA256",
  "Iterations": 600000,
  "Salt": "BASE64",
  "Cipher": "AES-256-GCM",
  "Nonce": "BASE64",
  "Ciphertext": "BASE64"
}
```

The GCM authentication tag is included in `Ciphertext`. The decrypted payload is a JSON list containing one or more KeePass records. Fields outside `Ciphertext` do not expose titles, user names, passwords, notes, or attachments.

## Limits

- no more than 10,000 records per container;
- file size limited to approximately 100 MB;
- restricted JSON recursion depth;
- accepted PBKDF2 iteration values between 100,000 and 5,000,000 during import.

Large attachments increase the container size because they are Base64-encoded. File export is preferable to the clipboard for large transfers.

## Troubleshooting

### The Plugin Does Not Appear

Verify that:

1. `keepass_plugin01.dll` is in the plugin directory used by KeePass.
2. KeePass was completely restarted.
3. `AssemblyProduct` is exactly `KeePass Plugin`.
4. DLL name, namespace, and class name match.

### BouncyCastle.Cryptography Could Not Be Found

If KeePass reports that `BouncyCastle.Cryptography` could not be loaded:

1. Verify that the DLL exists under `bin\Debug` or `bin\Release`.
2. Set `Copy Local = True` on the reference.
3. Copy it directly next to `keepass_plugin01.dll`.
4. Use the DLL from the same build output, not an arbitrary version.

### Missing Framework Types

| Error | Required reference |
|---|---|
| `System.Web.Script` or `JavaScriptSerializer` missing | `System.Web.Extensions` |
| `ToolStripMenuItem` or `MessageBox` missing | `System.Windows.Forms` |
| Type `Image` is in an unreferenced assembly | `System.Drawing` |

Add missing references under **References → Add Reference → Assemblies → Framework**.

### The Project Cannot Be Started Directly

This is normal for a class library. To debug, configure KeePass as the external program in the project's Debug settings:

```text
D:\Program Files\KeePass Password Safe 2\KeePass.exe
```

The plugin DLL must still be present in the KeePass plugin directory.

### Incorrect Password or Modified Container

Both cases intentionally produce:

```text
The password is incorrect or the container has been modified.
```

Verify the password, clipboard completeness, file integrity, and container-format compatibility.

## Updating the Plugin

1. Close KeePass.
2. Build the new version.
3. Replace `keepass_plugin01.dll`.
4. Replace `BouncyCastle.Cryptography.dll` if its package version changed.
5. Restart KeePass and verify the loaded version under **Tools → Plugins**.

Increment `AssemblyVersion` and `AssemblyFileVersion` consistently for published releases.

## Security Limitations

The plugin protects exported data at rest and during transfer. It does not protect against:

- malware with access to the KeePass process;
- keyloggers capturing the transfer password;
- memory dumps of the running process;
- a weak or compromised transfer password;
- modified plugin or KeePass binaries;
- a fully compromised Windows user context.

During export, the plugin must temporarily decrypt protected KeePass fields, serialize them, and process them in memory. Byte arrays are cleared where possible. .NET strings are immutable and cannot be reliably removed immediately from the managed heap.

## Recommendations for Production Use

- Reference only official KeePass releases.
- Obtain the plugin and BouncyCastle dependency from trusted sources.
- Sign release builds using Authenticode.
- Publish cryptographic hashes for released binaries.
- Use a separate, strong transfer password.
- Securely remove `.kprx` files when no longer required.
- Do not distribute exports through uncontrolled channels.
- Perform a security review before production use.

## Author and License

Author: **Chris Ditze-Stephan**

Copyright © 2026 Chris Ditze-Stephan.

This plugin is released under the MIT License. It may be used, copied, modified, merged, published, distributed, sublicensed, and sold, provided that the copyright and license notice are retained. See `LICENSE` for the complete license text.

The license terms of BouncyCastle also apply to that dependency.

## Disclaimer

This software is provided **“as is”**, without warranty of any kind, express or implied. The author is not liable for data loss, disclosure of credentials, loss of availability, business interruption, or other damages arising from the use or inability to use the software.

Users are responsible for testing the plugin, protecting transfer passwords and `.kprx` files, maintaining backups, and determining whether the plugin is suitable for their environment. The complete and legally controlling warranty and liability disclaimer is contained in the `LICENSE` file.
