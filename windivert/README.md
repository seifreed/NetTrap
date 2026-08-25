# WinDivert Binaries for NetTrap

NetTrap `0.1.0-alpha.1` uses WinDivert for experimental TCP/UDP NAT
redirection on Windows x86_64 when `--intercept` is enabled. Release archives
do not include WinDivert binaries or drivers; install them separately before
running that mode.

Windows listener mode does not need WinDivert. Experimental Windows capture
uses an externally installed Npcap runtime.

## Development Files

Download WinDivert from: https://reqrypt.org/windivert.html

Extract and place the following files:

### 64-bit Windows (x86_64)
- `WinDivert.dll` - Main library
- `WinDivert64.sys` - Kernel driver (x86_64)

Windows x86 is not a CI or release target.

## Download

```powershell
# Download the development version pinned by this example
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
