/*
    AMSA starter ruleset.

    Small, simple rules written for this project's demo. They are NOT a
    comprehensive malware ruleset and make no claim about detection rates.
    Each rule carries a "severity" (0-100) that watcher-final.py adds up.
*/

rule EICAR_Test_File
{
    meta:
        description = "Industry-standard EICAR antivirus test file (harmless)"
        severity = 80

    strings:
        // Fragment only, so this rules file is not itself flagged by antivirus.
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii

    condition:
        $eicar and filesize < 1KB
}

rule PE_Process_Injection_APIs
{
    meta:
        description = "Windows executable referencing classic process-injection APIs"
        severity = 40

    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii

    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule PE_Downloader_Strings
{
    meta:
        description = "Windows executable with downloader/launcher API strings"
        severity = 30

    strings:
        $a = "URLDownloadToFile" ascii
        $b = "WinExec" ascii
        $c = "ShellExecute" ascii

    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Script_Encoded_PowerShell
{
    meta:
        description = "Script using PowerShell encoded commands / base64 decoding"
        severity = 40

    strings:
        $a = "-EncodedCommand" ascii nocase
        $b = "FromBase64String" ascii nocase

    condition:
        any of them
}
