import os
from utils.paths import CONFIG_FILE
def load_config():
    
    config = {
        'apikey': '', 'sensitive': False, 'auto_process': False, 'virustotal': True,
        'windows_defender': False, 'windows_defender_offline_only': True, 'windows_defender_force': False,
        'ad_enabled': False, 'delete_protection': True, 'batch_delete_threshold': 5,
        'modify_protection': True, 'monitor_dirs': [],
        'wl_by_name': False, 'wl_by_hash': True, 'ad_warned_on_enable': False,
        'autoruns_prompted': False, 'theme': 'default',
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if '=' not in line: continue
                    key, value = line.split('=', 1)
                    if key in config:
                        if key == 'apikey': config[key] = value
                        elif key == 'monitor_dirs': config[key] = [d for d in value.split('|') if d] if value else []
                        elif key == 'batch_delete_threshold':
                            try: config[key] = int(value)
                            except: pass
                        elif key in ('sensitive', 'auto_process', 'virustotal', 'windows_defender',
             'windows_defender_offline_only', 'windows_defender_force', 'ad_enabled',
             'delete_protection', 'modify_protection', 'wl_by_name', 'wl_by_hash',
             'ad_warned_on_enable', 'autoruns_prompted'):
                            config[key] = (value == '1')
                        else: config[key] = value
        except Exception as e: print(f"配置文件加载失败: {e}")
    return config

def save_config(config):
    try:
        lines = []
        for k, v in config.items():
            if k == 'monitor_dirs': lines.append(f"monitor_dirs={'|'.join(v)}\n")
            elif isinstance(v, bool): lines.append(f"{k}={'1' if v else '0'}\n")
            elif isinstance(v, int): lines.append(f"{k}={v}\n")
            else: lines.append(f"{k}={v}\n")
        with open(CONFIG_FILE, 'w') as f: f.writelines(lines)
    except Exception as e: print(f"保存配置失败: {e}")