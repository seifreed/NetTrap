# WinDivert Binaries for NetTrap

This directory is a staging location for the WinDivert binaries required for
Windows x64/x86 packet interception. The files are external runtime/build
artifacts and are intentionally ignored by Git. Windows ARM64 uses native Npcap
capture instead and does not use these files.

## Required Files

Download WinDivert from: https://reqrypt.org/windivert.html

Extract and place the following files:

### 64-bit Windows (x86_64)
- `WinDivert.dll` - Main library
- `WinDivert64.sys` - Kernel driver (x86_64)

### 32-bit Windows (x86)
- `WinDivert.dll` - Main library  
- `WinDivert32.sys` - Kernel driver (x86)

## Download

```powershell
# Download WinDivert 2.2 (latest stable)
Invoke-WebRequest -Uri "https://reqrypt.org/download/WinDivert-2.2.2-A.zip" -OutFile "WinDivert.zip"
Expand-Archive -Path "WinDivert.zip" -DestinationPath "WinDivert"
Copy-Item "WinDivert/WinDivert-2.2.2-A/x64/WinDivert.dll" -Destination "windivert/"
Copy-Item "WinDivert/WinDivert-2.2.2-A/x64/WinDivert64.sys" -Destination "windivert/"
```

## License

WinDivert is distributed under the GNU Lesser General Public License (LGPL).
See: https://www.gnu.org/licenses/lgpl-3.0.html

Note: WinDivert.sys is signed by the author with a Microsoft WHQL certificate,
allowing it to run on Windows without additional signing requirements.
