RISK_LEVEL_1 = [
    "\\boot\\", "\\bootmgr", "\\bootnxt", "\\efi\\", "\\windows\\boot\\",
    "\\windows\\system32\\config\\", "\\windows\\system32\\drivers\\",
    "\\windows\\system32\\tasks\\", "\\windows\\system32\\ntoskrnl.exe",
    "\\windows\\system32\\winload.exe", "\\windows\\system32\\winload.efi",
    "\\windows\\system32\\hal.dll", "\\windows\\system32\\ntdll.dll",
    "\\system volume information\\"
]
RISK_LEVEL_2 = [
    "\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\",
    "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\",
    "\\windows\\system32\\drivers\\etc\\hosts", "\\windows\\system32\\grouppolicy\\"
]
SYSTEM_CRITICAL_PATHS = [
    "C:\\Windows\\System32", "C:\\Windows\\System32\\drivers",
    "C:\\Windows\\Boot", "C:\\EFI", "C:\\Boot", "C:\\bootmgr",
    "C:\\Windows\\System32\\config"
]
SYSTEM_PROCESSES = {
    'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
    'lsass.exe', 'svchost.exe', 'winlogon.exe', 'explorer.exe',
    'taskhost.exe', 'taskhostw.exe', 'dwm.exe', 'conhost.exe'
}

def get_risk_level(filepath):
    filepath_lower = filepath.lower()
    if filepath_lower.endswith('.log'): return 3
    for risk in RISK_LEVEL_1:
        if risk in filepath_lower: return 1
    for risk in RISK_LEVEL_2:
        if risk in filepath_lower: return 2
    return 3
