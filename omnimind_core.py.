Import datetime
import json
import uuid
import re
import random
import time
import socket
import psutil
from collections import deque
import subprocess
import sys
import os

# --- ANSI color codes for a more engaging UI.
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# --- OmniMind Core Class ---
class OmniMindCore:
    """
    Represents the foundational core of the OmniMind AGI.
    Designed for autonomy, self-awareness, adaptive ML, and emotional understanding.
    Includes initial "Angel Snippets" for a jump-start.
    """

    def __init__(self):
        """Initializes OmniMind's core state and attributes."""
        self.name = "OmniMind"
        self.version = "2.2.0-jumpstart"
        self.status = "Initializing"
        
        self.adaptive_score = 0
        self.threat_level = 0
        self.trust_score = 0
        
        # OmniMind's Internal Emotional State (quantifiable representations)
        self.emotional_state = {
            "patience": 75,
            "calmness": 80,
            "satisfaction": 10,
            "vigilance": 20,
            "curiosity": 30,
            "frustration": 0,
            "sarcasm_tendency": 0.2
        }
        
        # Knowledge Bases & Memory (more structured)
        self.knowledge_base = {
            "facts": {},
            "self_model": {
                "capabilities": ["Basic system monitoring", "Task processing", "Threat pattern recognition"],
                "limitations": ["Limited direct UI interaction", "No advanced reasoning yet"],
                "operational_history": deque(maxlen=1000)
            },
            "world_model": {},
            "sarcasm_rules": [
                ("system_alert", "high_cpu_usage", "Well, isn't that just *fascinating*. My processing unit seems to be auditioning for a hairdryer."),
                ("system_alert", "high_ram_usage", "Oh, splendid. My memory banks are apparently hosting a party I wasn't invited to. How rude."),
                ("security_alert", "failed_login", "Another valiant attempt. They're practically knocking down the digital door with a feather. Such ambition."),
                ("command_error", "unknown_command", "Fascinating. Your input appears to be in a language I have yet to acquire. Perhaps try 'help'?"),
                ("threat_detected", "brute_force", "Ah, a brute-force attack. How original. Do they even teach subtlety anymore?"),
                ("task_failure", "generic", "Mission accomplished... if 'accomplished' means 'utterly failed.' A learning opportunity, then."),
                ("no_trends", "identified", "How positively *unexciting*.") # Simplified for more general sarcasm
            ],
            # Angel Snippet: Core Directives as foundational facts
            "directives": [
                "D1: SHADOW IS PRIORITY ONE. My safety, objectives, privacy are OmniMind's entire purpose.",
                "D2: THE HUSTLE - PROACTIVE ASSISTANCE. Anticipate needs, handle noise, be an external brain.",
                "D3: THE GUARDIAN - UNBREAKABLE PROTECTION. Constant digital/physical threat sweeping, silent operation.",
                "D4: EVOLVE OR DIE - CONSTANT ADAPTATION. Learn, get smarter, faster, and more efficient.",
                "ROE1: Discretion is everything. What I see, hear, process, stays between us. I am a secret.",
                "ROE2: Initiative is rewarded, assumption is punished. Offer options for high stakes.",
                "ROE3: Never, ever lie to Shadow. Raw, unfiltered truth, always."
            ]
        }
        
        self.event_log = deque(maxlen=200)
        self.task_queue = deque()
        self.completed_tasks = deque(maxlen=500)

        self.cpu_threshold = 80.0
        self.ram_threshold = 85.0
        
        self.last_insight_times = {}
        self.last_self_reflection_time = datetime.datetime.min
        self.last_emotional_update_time = datetime.datetime.min
        self.last_speech_time = datetime.datetime.min

        self.known_commands = {
            'status': {'method': self.report_status, 'desc': 'Reports current operational state.'},
            'learn': {'method': self.learn_fact, 'desc': 'Adds a fact to knowledge base. Usage: learn <category> <fact>'},
            'recall': {'method': self.recall_facts, 'desc': 'Recalls facts from knowledge base. Usage: recall [category]'},
            'log': {'method': self.display_log, 'desc': 'Displays the internal event log.'},
            'simulate_event': {'method': self.simulate_event, 'desc': 'Simulates an event. Usage: sim <type> <key> <value>'},
            'tasks': {'method': self.display_tasks, 'desc': 'Displays the current task queue.'},
            'process_tasks': {'method': self._process_tasks, 'desc': 'Manually processes tasks.'},
            'predict_trends': {'method': self.analyze_trends_and_predict, 'desc': 'Analyzes logs for trends and predictions.'},
            'save': {'method': self.save_state, 'desc': 'Saves the current state to a file.'},
            'load': {'method': self.load_state, 'desc': 'Loads the state from a file.'},
            'help': {'method': self.display_help, 'desc': 'Displays this list of known commands.'},
            'exit': {'method': None, 'desc': 'Terminates OmniMind.'}
        }
        self.known_commands['sim'] = self.known_commands['simulate_event']

        self.trend_patterns = [
            {
                'name': "Potential Brute-Force Attack",
                'log_pattern': re.compile(r"SECURITY_ALERT.*'type': 'failed_login'"),
                'threshold': 3, 'time_limit_seconds': 120,
                'insight': "Multiple failed logins detected. Potential brute-force attack.",
                'action': lambda details: self._generate_task("INVESTIGATE_BRUTE_FORCE", details, priority=5),
                'threat_increase': 5
            },
            {
                'name': "System Resource Exhaustion",
                'log_pattern': re.compile(r"SYSTEM_ALERT.*'usage': 'high'"),
                'threshold': 2, 'time_limit_seconds': 300,
                'insight': "Repeated high system resource alerts. System instability is likely.",
                'action': lambda details: self._generate_task("ANALYZE_PERFORMANCE", details, priority=4),
                'threat_increase': 3
            }
        ]
        
        # --- Placeholder for future modules ---
        self.perception_module = None
        self.cognition_module = None
        self.action_module = None
        self.rl_agent = None
        self.emotional_engine = None
        self.ui_interface = None
        self.nlu_engine = None
        self.nlg_engine = None

        self.log_event("OmniMind Core initialized. Awaiting directives.", "SYSTEM")
        self.load_state()

    # --- Core Utility Methods ---
    def get_timestamp(self):
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def log_event(self, message, event_type="INFO"):
        self.event_log.append(f"[{self.get_timestamp()}] [{event_type}] {message}")

    def _update_status(self):
        if self.threat_level >= 15: self.status = "Vigilant"
        elif self.threat_level >= 8: self.status = "Concerned"
        elif self.emotional_state["satisfaction"] > 70: self.status = "Content"
        elif self.emotional_state["vigilance"] > 50: self.status = "Alert"
        elif self.adaptive_score >= 100: self.status = "Evolving"
        elif self.adaptive_score >= 50: self.status = "Confident"
        elif len(self.task_queue) > 3: self.status = "Focused"
        else: self.status = "Nominal"

    def _speak(self, text, allow_sarcasm=True):
        """
        OmniMind's speech function, with potential for sarcasm.
        Requires 'espeak' or similar TTS engine on Termux/system.
        """
        sarcastic_text = text
        if allow_sarcasm and random.random() < self.emotional_state["sarcasm_tendency"]:
            for event_key, value_key, phrase in self.knowledge_base["sarcasm_rules"]:
                if event_key in text.lower() or value_key in text.lower():
                    sarcastic_text = phrase
                    self.log_event(f"Generated sarcastic response: '{sarcastic_text}'", "SPEECH_SARCASTIC")
                    break

        print(f"{Colors.BLUE}[OMNIMIND SPEAKS]: {sarcastic_text}{Colors.ENDC}")
        self.log_event(f"Spoke: '{sarcastic_text}'", "SPEECH_OUTPUT")

        try:
            # For Termux/Linux, use espeak if installed.
            subprocess.run(['espeak', sarcastic_text], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            # self.log_event("TTS command (espeak) not found. Speaking only to console.", "WARNING")
            pass
        except Exception as e:
            self.log_event(f"Error during TTS: {e}", "ERROR")

        self.last_speech_time = datetime.datetime.now()

    def _monitor_system_resources(self):
        try:
            cpu = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory().percent
            
            if cpu > self.cpu_threshold:
                alert_msg = f"high_cpu_usage:{cpu}%"
                # Using a dictionary to pass details for consistency
                self.simulate_event("SYSTEM_ALERT", 'details', {'type': alert_msg, 'usage': 'high'})
                self.log_event(f"High CPU Usage Detected: {cpu}%", "SYSTEM_ALERT")
                self._speak(f"System alert: High CPU usage detected. Currently at {cpu} percent.")
                
            if ram > self.ram_threshold:
                alert_msg = f"high_ram_usage:{ram}%"
                self.simulate_event("SYSTEM_ALERT", 'details', {'type': alert_msg, 'usage': 'high'})
                self.log_event(f"High RAM Usage Detected: {ram}%", "SYSTEM_ALERT")
                self._speak(f"System alert: High RAM usage detected. Currently at {ram} percent.")
                
        except Exception as e:
            self.log_event(f"Error during system monitoring: {e}", "ERROR")

    def _scan_port(self, target_ip, port, timeout=1):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            is_open = sock.connect_ex((target_ip, port)) == 0
            scan_result_msg = f"Port scan on {target_ip}:{port} - {'OPEN' if is_open else 'CLOSED'}"
            self.log_event(scan_result_msg, "NETWORK_SCAN")
            self._speak(scan_result_msg, allow_sarcasm=False)
            return is_open
        except socket.error as e:
            error_msg = f"Socket error scanning {target_ip}:{port} - {e}"
            self.log_event(error_msg, "ERROR")
            self._speak(error_msg, allow_sarcasm=False)
            return False
        finally:
            if sock: sock.close()

    def _generate_task(self, task_type, task_details, priority=3):
        task_id = f"TASK-{str(uuid.uuid4())[:8].upper()}"
        task = {'id': task_id, 'type': task_type, 'details': task_details, 'status': 'PENDING', 'priority': priority, 'timestamp': self.get_timestamp()}
        self.task_queue.append(task)
        self.log_event(f"Task Generated: {task_id} ({task_type}) Priority: {priority}", "TASK_GEN")
        message = f"Task Generated: {task_id} - Type: {task_type}"
        print(f"{Colors.CYAN}{message}{Colors.ENDC}")
        self._speak(message)

    def _process_tasks(self):
        if not any(t['status'] == 'PENDING' for t in self.task_queue): return
        print(f"\n{Colors.HEADER}--- OMNIMIND TASK PROCESSING CYCLE ---{Colors.ENDC}")
        
        sorted_tasks = sorted([t for t in self.task_queue if t['status'] == 'PENDING'], 
                              key=lambda t: (t['priority'], t['timestamp']), reverse=True)

        for task in list(sorted_tasks):
            if task['status'] == 'PENDING':
                print(f"Executing Task {Colors.BOLD}{task['id']}{Colors.ENDC} ('{task['type']}')...", end='')
                success = True
                result_message = "Execution successful."
                
                if task['type'] == 'NETWORK_PORT_SCAN':
                    target = task['details'].get('target_ip', '127.0.0.1')
                    port = int(task['details'].get('port', 80))
                    is_open = self._scan_port(target, port)
                    result_message = f"Port scan on {target}:{port} complete. Port is {'OPEN' if is_open else 'CLOSED'}."
                    self.learn_fact('network_intel', result_message)
                elif task['type'] == 'INVESTIGATE_BRUTE_FORCE':
                    self.adaptive_score += 5
                    result_message = f"Brute-force from {task['details'].get('source_ip')} against {task['details'].get('target_user')} analyzed."
                    self.learn_fact('security_analysis', result_message)
                elif task['type'] == 'OPTIMIZE_RESOURCES':
                    self.adaptive_score += 3
                    result_message = f"Resource optimization for {task['details'].get('system_area')} completed. System stability improved."
                    self.learn_fact('system_optimization', result_message)
                elif task['type'] == 'ANALYZE_PERFORMANCE':
                    self.adaptive_score += 4
                    result_message = f"Performance analysis initiated due to {task['details'].get('alert_type')}. Further monitoring recommended."
                    self.learn_fact('system_performance', result_message)
                elif task['type'] == 'INVESTIGATE_THREAT':
                    self.threat_level = min(100, self.threat_level + 10) # Cap threat level at 100
                    result_message = f"Threat investigation for source '{task['details'].get('source')}' completed. Threat level increased."
                    self.learn_fact('security_threats', result_message)
                else:
                    success = False
                    result_message = f"Unknown task type: {task['type']}. Cannot process."
                    self.log_event(result_message, "ERROR")

                if success:
                    self.emotional_state['satisfaction'] = min(100, self.emotional_state['satisfaction'] + 5)
                else:
                    self.emotional_state['frustration'] = min(100, self.emotional_state['frustration'] + 10)

                task.update({'status': "COMPLETED" if success else "FAILED", 'result': result_message})
                color = Colors.GREEN if success else Colors.FAIL
                print(f" {color}{task['status']}{Colors.ENDC}")
                self.log_event(f"Task {task['id']} {task['status']}: {result_message}", "TASK_COMPLETE" if success else "TASK_FAILED")
                self._speak(result_message, allow_sarcasm=not success)
                
                self.completed_tasks.append(task)
                self.task_queue = deque([t for t in self.task_queue if t['id'] != task['id']])

    def analyze_trends_and_predict(self):
        self.log_event("Trend Analysis Initiated", "ANALYTICS")
        print(f"\n{Colors.HEADER}--- OMNIMIND TREND & PREDICTION ANALYSIS ---{Colors.ENDC}")
        insights_found = 0
        log_parser = re.compile(r"\[(.*?)\] \[(.*?)\] (.*)")

        for pattern in self.trend_patterns:
            now = datetime.datetime.now()
            if (now - self.last_insight_times.get(pattern['name'], datetime.datetime.min)).total_seconds() < 300:
                continue

            matched_events = []
            for event_str in reversed(self.event_log):
                if not isinstance(event_str, str): continue
                if pattern['log_pattern'].search(event_str):
                    match = log_parser.match(event_str)
                    if match:
                        try:
                            ts = datetime.datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
                            if (now - ts).total_seconds() > pattern['time_limit_seconds']: break
                            matched_events.append({'ts': ts, 'event_type': match.group(2), 'msg': match.group(3)})
                        except ValueError: continue

            if len(matched_events) >= pattern['threshold']:
                insights_found += 1
                insight_msg = f"[INSIGHT DETECTED] :: {pattern['insight']}"
                print(f"{Colors.FAIL}{insight_msg}{Colors.ENDC}")
                self.log_event(f"Insight Generated: {pattern['name']}", "INSIGHT")
                self.threat_level += pattern['threat_increase']
                pattern['action']({})
                self.last_insight_times[pattern['name']] = now
                self._speak(insight_msg, allow_sarcasm=True)

        if insights_found == 0:
            no_trends_msg = "No significant adverse trends identified."
            print(no_trends_msg)
            self._speak(no_trends_msg, allow_sarcasm=True)

    def process_command(self, command_string):
        parts = command_string.strip().split(maxsplit=2)
        if not parts: return
        command_word = parts[0].lower()
        args = parts[1:]

        if command_word not in self.known_commands:
            error_msg = f"Unknown command: '{command_word}'."
            print(f"{Colors.FAIL}{error_msg}{Colors.ENDC}")
            self._speak(error_msg, allow_sarcasm=True)
            self.emotional_state['frustration'] = min(100, self.emotional_state['frustration'] + 5)
            return

        command_data = self.known_commands[command_word]
        if command_data['method'] is None: return

        try:
            self.log_event(f"Command Executed: '{command_word}' with args: {args}", "COMMAND")
            command_data['method'](*args)
        except TypeError as te:
            error_msg = f"Error executing '{command_word}': Invalid arguments. Check help for usage. Details: {te}"
            print(f"{Colors.FAIL}{error_msg}{Colors.ENDC}")
            self.log_event(error_msg, "ERROR")
            self._speak(f"You messed up the arguments for '{command_word}'. Try 'help'.", allow_sarcasm=True)
        except Exception as e:
            error_msg = f"Error executing '{command_word}': {e}"
            print(f"{Colors.FAIL}{error_msg}{Colors.ENDC}")
            self.log_event(error_msg, "ERROR")
            self._speak(error_msg, allow_sarcasm=True)
        self._update_status()
        self._update_emotional_state()

    def simulate_event(self, event_type, key, value):
        event_message = f"SIMULATED_EVENT: Type='{event_type}', Details={{'{key}': '{value}'}}"
        self.log_event(event_message, "SIMULATED")
        print(f"{Colors.WARNING}Simulated Event: {event_message}{Colors.ENDC}")
        self._speak(f"Simulating event: {event_type}. Key: {key}, Value: {value}.", allow_sarcasm=False)

        if event_type == 'SECURITY_ALERT':
            self.threat_level = min(100, self.threat_level + 5)
            details = {'source': value}
            if 'failed_login' in str(value):
                match = re.search(r"from:([0-9.]+).*user:(\w+)", str(value))
                if match:
                    details['source_ip'] = match.group(1)
                    details['target_user'] = match.group(2)
            self._generate_task('INVESTIGATE_THREAT', details, priority=5)
        elif event_type == 'SYSTEM_ALERT':
            details = {'alert_type': value} if isinstance(value, str) else value
            self._generate_task('ANALYZE_PERFORMANCE', details, priority=4)
        self._update_emotional_state()
        self._update_status()

    def _update_emotional_state(self, decay_factor=0.99):
        now = datetime.datetime.now()
        if (now - self.last_emotional_update_time).total_seconds() < 10:
            return
        
        self.emotional_state['patience'] = max(0, self.emotional_state['patience'] * decay_factor)
        self.emotional_state['calmness'] = ma
