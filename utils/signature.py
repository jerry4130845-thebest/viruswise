import subprocess

def check_digital_signature(filepath):
    try:
        # 将单引号翻倍以在 PowerShell 单引号字符串内转义，防止命令注入
        safe_path = filepath.replace("'", "''")
        ps_command = f"""
$file = '{safe_path}'
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
