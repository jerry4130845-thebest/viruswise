import subprocess

def check_digital_signature(filepath):
    try:
        ps_command = f"""
$file = '{filepath}'
if (Test-Path $file) {{
    $sig = Get-AuthenticodeSignature $file
    if ($sig.Status -eq 'Valid') {{ Write-Output "Valid" }}
    else {{ Write-Output "Invalid" }}
}} else {{ Write-Output "NotFound" }}
"""
        result = subprocess.run(['powershell', '-Command', ps_command],
                              capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
        return result.stdout.strip() == "Valid"
    except: return False
