# psmphealth for Windows PowerShell (v0.1.0, UNTESTED on a live PSMP)

PSMP end-user health test for Windows 11 / Windows PowerShell 5.1. It needs no extra modules: it drives the built-in OpenSSH client `ssh.exe`.
Same CSV and `env.json` layout as the Linux tool (see the Linux README for the column list).

## What it does per CSV row
DNS + TCP pre-check of the PSMP server -> end user password from CCP (or typed with `-Manual`) -> one `ssh.exe` session as
`<end user>@<target user>@<target server>` through PSMP -> fixed command `echo S1 <time> <whoami>; sleep <HoldSec>; echo S2 <time> <whoami>` ->
checks (login, identity, session held) -> screenshot PNG -> results CSV -> one status mail with the screenshots inline.

How prompts are answered: `ssh.exe` is started with `SSH_ASKPASS` (+ `SSH_ASKPASS_REQUIRE=force`) pointing at a tiny helper. The helper answers
* a prompt containing **reason** -> `test.reason`
* a prompt containing **passcode / Passcode** (or one-time / OTP) -> `test.passcode_answer` (default `1` = Duo push; `"ask"` = you type the code per row)
* a prompt containing **password** -> the end user password
* anything else -> logged as `unknown` and reported in the failure reason ("PSMP asked a question the tool cannot answer: ...").
The password lives only in memory and in the environment of the one `ssh.exe` child process (never in your PowerShell session, a command line, a file, a log, a screenshot or the mail).
A password prompted twice means "rejected": with `-Manual` the run stops and the remaining rows are marked skipped (no lock-out).

## First-time setup
1. Copy this folder to the laptop (e.g. `C:\Tools\psmphealth-ps`). Check `ssh -V` works (OpenSSH 8.4 or newer).
2. `Copy-Item envs\example envs\prod -Recurse`, then edit `envs\prod\env.json` and `envs\prod\tests.csv`. The folder must sit directly under `envs\`.
3. If scripts are blocked: `powershell -ExecutionPolicy Bypass -File .\Run-PsmpHealth.ps1 ...` (or `Unblock-File .\Run-PsmpHealth.ps1`).
4. `.\Run-PsmpHealth.ps1 -SelfTest`     (no PSMP needed: checks CSV rules, the prompt helper with a fake ssh, verdicts, screenshot, report)
5. `.\Run-PsmpHealth.ps1 -Env prod -Validate`
6. `.\Run-PsmpHealth.ps1 -Env prod -Manual -Only 1 -NoMail`   (asks end user name + password; paste me the run folder's `row-1.out`)
7. Full run: `.\Run-PsmpHealth.ps1 -Env prod` (CCP) or `-Manual`.

## Switches
`-Env <name>` `-Csv <file>` `-Only 1,3` `-Manual` `-NoMail` `-DryRun` `-Validate` `-SelfTest` `-Version`.
Exit code 0 = all passed, 1 = a failure.

## Output
`envs\<name>\results\psmp-results-<run>.csv`; `envs\<name>\logs\runs\<run>\row-N.out` (detail) and `row-N.screen.png`.
`mail.send_on`: `always` (mail every run, subject `ALL OK (n tests)`) or `failure` (only when a row failed). No repeat/recovery tracking in this version.

## Known limits (v0.1)
* Not tested against a live PSMP from Windows. The one unknown: whether this `ssh.exe` build passes PSMP's keyboard-interactive prompts (password, reason, passcode) to `SSH_ASKPASS`. If the log shows ssh waiting or no prompts recorded, send me `row-1.out`.
* A Duo push is approved on the phone while ssh waits (up to hold + 120 s + `test.mfa_wait_sec`). Every row sends a new push.
* Needs a normal interactive window for `-Manual`; cannot be scheduled with it. No lock file, no retention clean-up, no CCP client-certificate test yet (`credentials.ccp.client_certificate_thumbprint` is read if you set it).
