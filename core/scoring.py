import os, subprocess, time, threading

class TrustedPublishers:
    STRONG_TRUSTED = {
        'microsoft corporation', 'google llc', 'adobe inc', 'jetbrains',
        'apple inc', 'github', 'mozilla corporation', 'oracle corporation',
        'amazon.com inc', 'intel corporation', 'nvidia corporation',
        'vmware inc', 'citrix systems', 'wireshark foundation',
        'blender foundation', 'gimp development team', 'vlc media player',
        'canonical ltd', 'fedora project', 'red hat', 'suse',
        'arista networks', 'broadcom', 'cisco systems',
    }

class ProcessBehavior:
    def __init__(self, pid, name, exe):
        self.pid = pid
        self.name = name
        self.exe = exe
        self.start_time = time.time()
        self.last_score_update = time.time()
        self.appdata_writes = []
        self.programdata_writes = []
        self.system32_writes = []
        self.temp_writes = []
        self.exe_dll_writes = []
        self.fake_log_writes = []
        self.normal_log_writes = []
        self.child_processes = []
        self.process_injections = []
        self.api_hooks = []
        self.remote_thread_injections = []
        self.https_requests = []
        self.suspicious_ip_requests = []
        self.encrypted_communications = []
        self.c2_behaviors = []
        self.startup_registrations = []
        self.service_creations = []
        self.registry_writes = []
        self.self_extraction = False
        self.persistence_behavior = False
        self.signature_valid = None
        self.publisher = None
        self.signature_forged = False

class ScoringEngine:
    def __init__(self):
        self.trusted_publishers = TrustedPublishers()
        self.high_risk_dirs = {'C:\\Windows\\System32': True, 'C:\\Windows\\SysWOW64': True, 'C:\\Windows\\System32\\drivers': True}

    def calculate_total_score(self, behavior):
        score = 0
        triggered_rules = []
        sig_score, sig_rules = self._calculate_signature_score(behavior)
        score += sig_score; triggered_rules.extend(sig_rules)
        write_score, write_rules = self._calculate_file_write_score(behavior)
        score += write_score; triggered_rules.extend(write_rules)
        proc_score, proc_rules = self._calculate_process_behavior_score(behavior)
        score += proc_score; triggered_rules.extend(proc_rules)
        net_score, net_rules = self._calculate_network_behavior_score(behavior)
        score += net_score; triggered_rules.extend(net_rules)
        other_score, other_rules = self._calculate_other_behavior_score(behavior)
        score += other_score; triggered_rules.extend(other_rules)
        combo_score, combo_rules = self._calculate_combination_rules(behavior)
        if combo_score > score:
            score = combo_score; triggered_rules = combo_rules
        return score, triggered_rules

    def _calculate_signature_score(self, behavior):
        score = 0; rules = []
        if behavior.signature_forged:
            score += 80; rules.append("签名伪造/异常+80")
            return score, rules
        if behavior.signature_valid is None:
            behavior.signature_valid = self._check_signature(behavior.exe)
        if behavior.signature_valid:
            if behavior.publisher and behavior.publisher.lower() in self.trusted_publishers.STRONG_TRUSTED:
                score -= 40; rules.append("强可信签名-40")
            else:
                score -= 15; rules.append("有效数字签名(未知厂商)-15")
        else:
            score += 40; rules.append("无签名+40")
        return score, rules

    def _calculate_file_write_score(self, behavior):
        score = 0; rules = []
        if behavior.appdata_writes:
            score += 5 * len(behavior.appdata_writes); rules.append(f"写AppData+5x{len(behavior.appdata_writes)}")
        if behavior.programdata_writes:
            score += 10 * len(behavior.programdata_writes); rules.append(f"写ProgramData+10x{len(behavior.programdata_writes)}")
        if behavior.system32_writes:
            score += 15 * len(behavior.system32_writes); rules.append(f"写System32+15x{len(behavior.system32_writes)}")
        if behavior.temp_writes:
            score += 1 * len(behavior.temp_writes); rules.append(f"写Temp+1x{len(behavior.temp_writes)}")
        if behavior.exe_dll_writes:
            score += 50 * len(behavior.exe_dll_writes); rules.append(f"写EXE/DLL+50x{len(behavior.exe_dll_writes)}")
        if behavior.fake_log_writes:
            score += 30 * len(behavior.fake_log_writes); rules.append(f"写伪日志文件+30x{len(behavior.fake_log_writes)}")
        return score, rules

    def _calculate_process_behavior_score(self, behavior):
        score = 0; rules = []
        if behavior.child_processes:
            score += 10 * len(behavior.child_processes); rules.append(f"创建子进程+10x{len(behavior.child_processes)}")
        if behavior.process_injections:
            score += 60 * len(behavior.process_injections); rules.append(f"注入其他进程+60x{len(behavior.process_injections)}")
        if behavior.api_hooks:
            score += 50 * len(behavior.api_hooks); rules.append(f"Hook API+50x{len(behavior.api_hooks)}")
        if behavior.remote_thread_injections:
            score += 80 * len(behavior.remote_thread_injections); rules.append(f"远程线程注入+80x{len(behavior.remote_thread_injections)}")
        return score, rules

    def _calculate_network_behavior_score(self, behavior):
        score = 0; rules = []
        if behavior.suspicious_ip_requests:
            score += 40 * len(behavior.suspicious_ip_requests); rules.append(f"可疑IP通信+40x{len(behavior.suspicious_ip_requests)}")
        if behavior.encrypted_communications:
            score += 50 * len(behavior.encrypted_communications); rules.append(f"加密通信+非标准端口+50x{len(behavior.encrypted_communications)}")
        if behavior.c2_behaviors:
            score += 90 * len(behavior.c2_behaviors); rules.append(f"C2行为特征+90x{len(behavior.c2_behaviors)}")
        return score, rules

    def _calculate_other_behavior_score(self, behavior):
        score = 0; rules = []
        if behavior.startup_registrations:
            score += 15 * len(behavior.startup_registrations); rules.append(f"启动项注册+15x{len(behavior.startup_registrations)}")
        if behavior.service_creations:
            score += 15 * len(behavior.service_creations); rules.append(f"创建服务+15x{len(behavior.service_creations)}")
        if behavior.registry_writes:
            score += 30 * len(behavior.registry_writes); rules.append(f"写入注册表Run键+30x{len(behavior.registry_writes)}")
        if behavior.self_extraction and behavior.persistence_behavior:
            score += 70; rules.append("自解压+持久化+70")
        return score, rules

    def _calculate_combination_rules(self, behavior):
        if not behavior.signature_valid and behavior.system32_writes:
            return 50, ["无签名+写System32+50"]
        if not behavior.signature_valid and behavior.process_injections:
            return 80, ["无签名+注入进程+80"]
        if behavior.system32_writes and behavior.startup_registrations:
            return 60, ["写System32+启动项+60"]
        return 0, []

    def _check_signature(self, exe_path):
        try:
            ps_command = f"""
$file = '{exe_path}'
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

class ProcessScoreTracker:
    def __init__(self):
        self.process_scores = {}
        self.scoring_engine = ScoringEngine()
        self.score_decay_rate = 2
        self.alert_threshold = 60
        self.kill_threshold = 120
        self.score_lock = threading.Lock()

    def add_or_update_process(self, pid, name, exe):
        with self.score_lock:
            if pid not in self.process_scores:
                behavior = ProcessBehavior(pid, name, exe)
                self.process_scores[pid] = {'behavior': behavior, 'score': 0, 'last_update': time.time(), 'alerted': False, 'triggered_rules': []}
            return self.process_scores[pid]

    def get_process_score(self, pid):
        with self.score_lock:
            if pid not in self.process_scores: return 0, []
            record = self.process_scores[pid]
            decayed = max(0, record['score'] - self.score_decay_rate * (time.time() - record['last_update']))
            return decayed, record['triggered_rules']

    def update_process_score(self, pid, name, exe):
        with self.score_lock:
            if pid not in self.process_scores:
                self.add_or_update_process(pid, name, exe)
            record = self.process_scores[pid]
            new_score, triggered_rules = self.scoring_engine.calculate_total_score(record['behavior'])
            record['score'] = new_score
            record['last_update'] = time.time()
            record['triggered_rules'] = triggered_rules
            return new_score, triggered_rules

    def record_file_write(self, pid, file_path):
        with self.score_lock:
            if pid not in self.process_scores: return
            behavior = self.process_scores[pid]['behavior']
            fl = file_path.lower()
            if 'appdata' in fl: behavior.appdata_writes.append(file_path)
            elif 'programdata' in fl: behavior.programdata_writes.append(file_path)
            elif 'system32' in fl or 'syswow64' in fl: behavior.system32_writes.append(file_path)
            elif 'temp' in fl or 'cache' in fl: behavior.temp_writes.append(file_path)
            elif fl.endswith(('.exe', '.dll')): behavior.exe_dll_writes.append(file_path)

    def record_log_write(self, pid, file_path, is_fake):
        with self.score_lock:
            if pid not in self.process_scores: return
            behavior = self.process_scores[pid]['behavior']
            if is_fake: behavior.fake_log_writes.append(file_path)
            else: behavior.normal_log_writes.append(file_path)

    def record_process_injection(self, pid, target_pid):
        with self.score_lock:
            if pid not in self.process_scores: return
            self.process_scores[pid]['behavior'].process_injections.append(target_pid)

    def record_remote_thread_injection(self, pid, target_pid):
        with self.score_lock:
            if pid not in self.process_scores: return
            self.process_scores[pid]['behavior'].remote_thread_injections.append(target_pid)

    def record_child_process(self, pid, child_pid, child_name):
        with self.score_lock:
            if pid not in self.process_scores: return
            self.process_scores[pid]['behavior'].child_processes.append({'pid': child_pid, 'name': child_name})

    def record_startup_registration(self, pid, registry_path):
        with self.score_lock:
            if pid not in self.process_scores: return
            self.process_scores[pid]['behavior'].startup_registrations.append(registry_path)

    def record_service_creation(self, pid, service_name):
        with self.score_lock:
            if pid not in self.process_scores: return
            self.process_scores[pid]['behavior'].service_creations.append(service_name)

    def record_suspicious_network(self, pid, ip_address):
        with self.score_lock:
            if pid not in self.process_scores: return
            self.process_scores[pid]['behavior'].suspicious_ip_requests.append(ip_address)

    def record_c2_behavior(self, pid, behavior_desc):
        with self.score_lock:
            if pid not in self.process_scores: return
            self.process_scores[pid]['behavior'].c2_behaviors.append(behavior_desc)

    def remove_process(self, pid):
        with self.score_lock:
            if pid in self.process_scores: del self.process_scores[pid]
