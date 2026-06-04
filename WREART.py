# -*- coding: utf-8 -*-
import os
import sys
import ctypes
import winreg
import subprocess
import tempfile
import json
import atexit
import threading
import datetime
import time
import csv
import io
import shlex
import shutil
import hashlib
import logging
import re
import uuid
from tkinter import *
from tkinter import ttk, messagebox, filedialog, simpledialog
import winsound

CONFIG_PATH = os.path.join(tempfile.gettempdir(), 'WRERT_cfg.json')
EXCLUDED_NAMES = {'system idle process', 'system', 'registry', 'smss.exe', 'csrss.exe',
                  'wininit.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'spoolsv.exe',
                  'winlogon.exe', 'dwm.exe', 'fontdrvhost.exe', 'memory compression',
                  'trustedinstaller.exe', 'tiworker.exe', 'searchindexer.exe',
                  'wlanext.exe', 'conhost.exe', 'taskhostw.exe', 'sihost.exe',
                  'ctfmon.exe', 'audiodg.exe', 'dashost.exe', 'wudfhost.exe',
                  'unsecapp.exe', 'backgroundtaskhost.exe', 'runtimebroker.exe',
                  'shellexperiencehost.exe', 'startmenuexperiencehost.exe',
                  'textinputhost.exe', 'searchapp.exe', 'aggregatorhost.exe',
                  'mousocoreworker.exe', 'wmiprvse.exe', 'winws.exe', 'explorer.exe',
                  'tasklist.exe', 'cmd.exe', 'systemsettings.exe',
                  'applicationframehost.exe', 'searchprotocolhost.exe', 'searchfilterhost.exe',
                  'msmpeng.exe', 'nis.exe', 'securityhealthservice.exe', 'securityhealthsystray.exe',
                  'vssvc.exe', 'wbengine.exe', 'taskmgr.exe', 'regedit.exe', 'notepad.exe',
                  'userinit.exe', 'sigcheck64.exe'}
EXCLUDED_USERS = {'NT AUTHORITY\\SYSTEM', 'NT AUTHORITY\\LOCAL SERVICE',
                  'NT AUTHORITY\\NETWORK SERVICE', 'NT AUTHORITY\\СИСТЕМА',
                  'NT AUTHORITY\\ЛОКАЛЬНАЯ СЛУЖБА', 'NT AUTHORITY\\СЕТЕВАЯ СЛУЖБА'}
SYSTEM_PATHS = {'C:\\Windows\\System32\\', 'C:\\Windows\\SysWOW64\\',
                'C:\\Windows\\System\\', 'C:\\Windows\\SystemResources\\'}
POLICY_VALUES = ['DisableTaskMgr', 'DisableRegistryTools', 'DisableCMD',
                 'NoControlPanel', 'NoRun', 'NoFind', 'NoClose',
                 'NoSettingsPage', 'NoSetFolders', 'NoFolderOptions',
                 'NoViewContextMenu', 'NoTrayContextMenu']
POLICY_PATHS = [
    'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
    'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'
]
SCRIPT_NAMES = ['raton', 'xworm', 'webrat', '000', 'noescape', 'dcrat', 'njrat', 'sheetrat']

LOG_PATH = os.path.join(tempfile.gettempdir(), 'WREART.log')
QUARANTINE_DIR = os.path.join(tempfile.gettempdir(), 'WREART_Quarantine')
EXPORT_DIR = os.path.join(tempfile.gettempdir(), 'WREART_Exports')
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(EXPORT_DIR, exist_ok=True)
logging.basicConfig(filename=LOG_PATH, level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s', encoding='utf-8')

SUSPICIOUS_PATH_PARTS = ('\\temp\\', '\\appdata\\local\\temp', '\\appdata\\roaming',
                         '\\users\\public', '\\programdata\\', '\\windows\\temp',
                         '\\perflogs\\', '\\recycler\\')
SCRIPT_EXTENSIONS = ('.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.bat', '.cmd', '.scr')
EXECUTABLE_EXTENSIONS = ('.exe', '.dll', '.sys', '.scr', '.com', '.cpl')


def log_exception(context, exc):
    logging.exception('%s: %s', context, exc)


def run_command(args, timeout=30, check=False, capture_output=True, text=True):
    logging.info('RUN: %r', args)
    return subprocess.run(args, shell=False, timeout=timeout, check=check,
                          capture_output=capture_output, text=text,
                          creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))


def check_output_command(args, timeout=30, text=True, encoding=None):
    logging.info('CHECK_OUTPUT: %r', args)
    kwargs = dict(shell=False, timeout=timeout, text=text,
                  stderr=subprocess.PIPE,
                  creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if encoding:
        kwargs['encoding'] = encoding
    return subprocess.check_output(args, **kwargs)


def ps_single_quote(value):
    return str(value).replace("'", "''")


def export_json_artifact(prefix, payload):
    os.makedirs(EXPORT_DIR, exist_ok=True)
    fname = f"{prefix}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}.json"
    path = os.path.join(EXPORT_DIR, fname)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, default=str)
    logging.info('Exported artifact: %s', path)
    return path


def extract_executable_path(command_line):
    if not command_line:
        return ''
    text = str(command_line).strip()
    m = re.match(r'^"([^"]+)"', text)
    if m:
        return m.group(1)
    parts = text.split()
    return parts[0] if parts else ''


def filetime_to_dt(ft):
    if not ft or ft == 0:
        return ''
    try:
        seconds_since_epoch = (ft - 116444736000000000) / 10000000
        dt = datetime.datetime.utcfromtimestamp(seconds_since_epoch)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return ''

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def clean_orphaned_userinit_entry():
    try:
        winlogon_path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, winlogon_path, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            current_userinit, _ = winreg.QueryValueEx(key, 'Userinit')
            exe_path = sys.executable
            if exe_path.lower().endswith('.py'):
                our_cmd = f'"{sys.executable}" "{os.path.abspath(__file__)}" --check-startup'
            else:
                our_cmd = f'"{exe_path}" --check-startup'
            if our_cmd in current_userinit:
                parts = current_userinit.split(',')
                new_parts = [p.strip() for p in parts if p.strip() and p.strip() != our_cmd]
                new_userinit = ','.join(new_parts) if new_parts else 'C:\\Windows\\System32\\userinit.exe,'
                winreg.SetValueEx(key, 'Userinit', 0, winreg.REG_SZ, new_userinit)
    except:
        pass

if len(sys.argv) > 1 and sys.argv[1] == '--check-startup':
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable,
                                            ' '.join(f'"{p}"' for p in sys.argv), None, 1)
        sys.exit(0)
    timeout = 90
    start_wait = time.time()
    explorer_found = False
    while time.time() - start_wait < timeout:
        try:
            subprocess.check_output(['tasklist', '/fi', 'imagename eq explorer.exe'],
                                    creationflags=subprocess.CREATE_NO_WINDOW, stderr=subprocess.DEVNULL)
            explorer_found = True
            break
        except:
            time.sleep(1)
    time.sleep(10)
    log_path = os.path.join(os.path.dirname(sys.executable), 'startup_processes.log')
    current_pid = os.getpid()
    try:
        import psutil
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time', 'username']):
            try:
                pinfo = proc.info
                if pinfo['pid'] == current_pid:
                    continue
                if pinfo['name'] and pinfo['name'].lower() in EXCLUDED_NAMES:
                    continue
                if pinfo['username'] and pinfo['username'].upper() in EXCLUDED_USERS:
                    continue
                exe_path = pinfo['exe'] or ''
                if any(exe_path.upper().startswith(p.upper()) for p in SYSTEM_PATHS):
                    if not any(app in exe_path.lower() for app in ['program files', 'programdata', 'users']):
                        continue
                processes.append(f"{pinfo['name']} ({pinfo['pid']}) - {exe_path} (User: {pinfo['username']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write(f"User processes after login ({datetime.datetime.now()}):\n")
            f.write('=' * 80 + '\n')
            if processes:
                f.write('\n'.join(processes))
            else:
                f.write("No suspicious processes found.\n")
    except ImportError:
        try:
            output = subprocess.check_output(['tasklist', '/v', '/fo', 'csv'], text=True,
                                             encoding='cp866', creationflags=subprocess.CREATE_NO_WINDOW)
            filtered = []
            lines = output.strip().split('\n')
            if len(lines) > 1:
                reader = csv.reader(io.StringIO('\n'.join(lines[1:])))
                for row in reader:
                    if len(row) < 8:
                        continue
                    name = row[0].strip()
                    pid = row[1].strip()
                    user = row[6].strip()
                    if int(pid) == current_pid:
                        continue
                    if user.upper() in EXCLUDED_USERS:
                        continue
                    if name.lower() in EXCLUDED_NAMES:
                        continue
                    filtered.append(f"{name} (PID {pid}) - User: {user}")
            with open(log_path, 'w', encoding='utf-8') as f:
                f.write(f"User processes after login ({datetime.datetime.now()}):\n")
                f.write('=' * 80 + '\n')
                if filtered:
                    f.write('\n'.join(filtered))
                else:
                    f.write("No suspicious processes found.\n")
        except Exception as e:
            with open(log_path, 'w', encoding='utf-8') as f:
                f.write(f"Error getting process list: {e}")
    task_name = "WREART_StartupCheck"
    try:
        run_command(['schtasks', '/delete', '/tn', task_name, '/f'], timeout=30, capture_output=True)
    except:
        pass
    sys.exit(0)

if not is_admin():
    try:
        params = ' '.join((f'"{p}"' for p in sys.argv))
        ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, params, None, 1)
    except:
        pass
    sys.exit(0)

clean_orphaned_userinit_entry()

def load_persisted_config():
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {}

def save_persisted_config(cfg):
    try:
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(cfg, f)
    except:
        pass

def get_drive_info(letter):
    info = {'label': '', 'fs': '', 'size': 0}
    try:
        kernel = ctypes.windll.kernel32
        vol_name_buf = ctypes.create_unicode_buffer(261)
        fs_name_buf = ctypes.create_unicode_buffer(261)
        serial = ctypes.c_ulong()
        max_comp_len = ctypes.c_ulong()
        flags = ctypes.c_ulong()
        root = letter if letter.endswith('\\') else letter + '\\'
        kernel.GetVolumeInformationW(ctypes.c_wchar_p(root), vol_name_buf, ctypes.sizeof(vol_name_buf),
                                     ctypes.byref(serial), ctypes.byref(max_comp_len), ctypes.byref(flags),
                                     fs_name_buf, ctypes.sizeof(fs_name_buf))
        info['label'] = vol_name_buf.value
        info['fs'] = fs_name_buf.value
        free_bytes = ctypes.c_ulonglong()
        total_bytes = ctypes.c_ulonglong()
        kernel.GetDiskFreeSpaceExW(ctypes.c_wchar_p(root), ctypes.byref(free_bytes), ctypes.byref(total_bytes), None)
        info['size'] = round(total_bytes.value / 1073741824) if total_bytes.value else 0
    except:
        pass
    return info

def pretty_drive_name(letter):
    i = get_drive_info(letter)
    label = f" — {i['label']}" if i['label'] else ''
    fs = f", {i['fs']}" if i['fs'] else ''
    size = f", {i['size']} GB" if i['size'] else ''
    return f'{letter}{label}{fs}{size}'

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        widget.bind('<Enter>', self.showtip)
        widget.bind('<Leave>', self.hidetip)
    def showtip(self, event=None):
        if self.tipwindow or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + 20
        self.tipwindow = tw = Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f'+{x}+{y}')
        lbl = Label(tw, text=self.text, justify=LEFT, background='#ffffe0',
                    relief=SOLID, borderwidth=1, font=('Segoe UI', 9))
        lbl.pack(ipadx=4, ipady=2)
    def hidetip(self, event=None):
        if self.tipwindow:
            self.tipwindow.destroy()
            self.tipwindow = None

class ProgressDialog(Toplevel):
    def __init__(self, parent, title='Executing...'):
        super().__init__(parent)
        self.title(title)
        self.geometry('300x100')
        self.transient(parent)
        self.grab_set()
        self.progress = ttk.Progressbar(self, mode='indeterminate')
        self.progress.pack(fill=X, padx=20, pady=10)
        self.label = Label(self, text=title, font=('Segoe UI', 9))
        self.label.pack(pady=5)
        self.progress.start()
    def close(self):
        self.progress.stop()
        self.destroy()


class WindowsREHelperPro(Tk):
    def __init__(self):
        super().__init__()
        self.title('WREART - Recovery & Autoruns Repair')
        self.geometry('1300x850')
        self.minsize(1100, 750)
        self.option_add('*Font', '{Segoe UI} 9')
        self.setup_styles()
        self.repair_mode = self.detect_winre_environment()
        self.system_drive = self.detect_or_prompt_system_drive()
        self.system_root = 'SYSTEM'
        self.software_root = 'SOFTWARE'
        self.signature_cache = {}
        self.scanning_flag = False
        self.fim_snapshots = {}
        
        if self.repair_mode:
            try:
                self.load_system_hives()
                atexit.register(self.unload_hives)
            except Exception as e:
                messagebox.showerror('Error', f'Cannot load registry hives: {e}')
        if not self.validate_system_drive():
            messagebox.showerror('Error', 'System drive is invalid. Exiting.')
            self.destroy()
            return
        self.setup_ui()
        self.status_var = StringVar()
        status_bar = ttk.Frame(self, style='Status.TFrame')
        status_bar.pack(side=BOTTOM, fill=X)
        status_label = ttk.Label(status_bar, textvariable=self.status_var, anchor=W, style='Status.TLabel')
        status_label.pack(side=LEFT, fill=X, expand=True, padx=8, pady=4)
        disclaimer = ttk.Label(status_bar, text="Provided AS-IS, no warranties.", style='Warning.Status.TLabel')
        disclaimer.pack(side=LEFT, padx=10, pady=4)
        ttk.Button(status_bar, text='Change drive', command=self.change_system_drive).pack(side=RIGHT, padx=4)
        ttk.Button(status_bar, text='Auto-detect', command=self.auto_detect_drive).pack(side=RIGHT)
        ttk.Button(status_bar, text='Refresh all', command=self.initial_load).pack(side=RIGHT, padx=4)
        self.update_status()
        self.after(100, self.initial_load)
        self.after(2500, self.auto_prepare_recovery_kit)


    def setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except Exception:
            pass
        self.configure(bg='#f3f6fb')
        base_font = ('Segoe UI', 9)
        heading_font = ('Segoe UI', 9, 'bold')
        style.configure('.', font=base_font)
        style.configure('TNotebook', background='#f3f6fb', borderwidth=0)
        style.configure('TNotebook.Tab', font=heading_font, padding=(12, 6))
        style.configure('TLabelframe', background='#f3f6fb')
        style.configure('TLabelframe.Label', font=heading_font, background='#f3f6fb', foreground='#1f2937')
        style.configure('TButton', font=base_font, padding=(8, 4))
        style.configure('TLabel', font=base_font, background='#f3f6fb')
        style.configure('TEntry', font=base_font)
        style.configure('TCombobox', font=base_font)
        style.configure('Treeview', font=base_font, rowheight=24, fieldbackground='#ffffff', background='#ffffff')
        style.configure('Treeview.Heading', font=heading_font, background='#e5e7eb', foreground='#111827', padding=(4, 4))
        style.configure('Status.TFrame', background='#e8edf5')
        style.configure('Status.TLabel', background='#e8edf5', foreground='#374151', font=base_font)
        style.configure('Warning.Status.TLabel', background='#e8edf5', foreground='#b91c1c', font=('Segoe UI', 8, 'bold'))
        style.configure('Toolbar.TFrame', background='#f3f6fb')
        style.configure('Title.TLabel', background='#f3f6fb', foreground='#111827', font=('Segoe UI', 12, 'bold'))
        style.configure('Muted.TLabel', background='#f3f6fb', foreground='#6b7280', font=('Segoe UI', 9))
        style.map('Treeview', background=[('selected', '#dbeafe')], foreground=[('selected', '#111827')])

    def load_system_hives(self):
        system_hive = os.path.join(self.system_drive, 'Windows', 'System32', 'config', 'SYSTEM')
        software_hive = os.path.join(self.system_drive, 'Windows', 'System32', 'config', 'SOFTWARE')
        sam_hive = os.path.join(self.system_drive, 'Windows', 'System32', 'config', 'SAM')
        security_hive = os.path.join(self.system_drive, 'Windows', 'System32', 'config', 'SECURITY')
        if not os.path.exists(system_hive) or not os.path.exists(software_hive):
            raise FileNotFoundError('SYSTEM/SOFTWARE hives not found.')
        try:
            run_command(['reg', 'unload', r'HKLM\MainSystem'], timeout=10)
        except Exception:
            pass
        try:
            run_command(['reg', 'unload', r'HKLM\MainSoftware'], timeout=10)
        except Exception:
            pass
        run_command(['reg', 'load', r'HKLM\MainSystem', system_hive], check=True)
        run_command(['reg', 'load', r'HKLM\MainSoftware', software_hive], check=True)
        try:
            run_command(['reg', 'load', r'HKLM\MainSAM', sam_hive], check=True)
            run_command(['reg', 'load', r'HKLM\MainSecurity', security_hive], check=True)
        except:
            pass
        self.system_root = 'MainSystem'
        self.software_root = 'MainSoftware'

    def unload_hives(self):
        try:
            run_command(['reg', 'unload', r'HKLM\MainSystem'])
            run_command(['reg', 'unload', r'HKLM\MainSoftware'])
            run_command(['reg', 'unload', r'HKLM\MainSAM'])
            run_command(['reg', 'unload', r'HKLM\MainSecurity'])
        except:
            pass

    def get_registry_path(self, base_path):
        if self.repair_mode and self.software_root != 'SOFTWARE':
            return base_path.replace('SOFTWARE', self.software_root).replace('SYSTEM', self.system_root)
        return base_path

    def is_normal_windows(self):
        return not getattr(self, 'repair_mode', False)

    def command_exists(self, exe_name):
        try:
            if shutil.which(exe_name):
                return True
            system32 = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', exe_name)
            return os.path.exists(system32)
        except Exception:
            return False

    def winre_notice(self, feature):
        self.show_info(f'{feature} is disabled in WinRE mode. Use it from a running Windows installation.')



    def get_sigcheck_path(self) -> str:
        local_path = os.path.join(os.path.dirname(sys.executable), 'sigcheck64.exe')
        if os.path.exists(local_path):
            return local_path
        import shutil
        system_path = shutil.which('sigcheck64.exe')
        if system_path:
            return system_path
        temp_path = os.path.join(tempfile.gettempdir(), 'WinREHelper', 'sigcheck64.exe')
        if os.path.exists(temp_path):
            return temp_path
        return local_path

    def _is_winget_available(self) -> bool:
        if getattr(self, 'repair_mode', False):
            return False
        try:
            result = subprocess.run(
                ['winget', '--version'],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False

    def _install_via_winget(self) -> bool:
        if getattr(self, 'repair_mode', False):
            return False
        try:
            cmd = ['winget', 'install', '--id', 'Microsoft.Sysinternals.Sigcheck', '--accept-package-agreements', '--accept-source-agreements', '-e']
            run_command(cmd, timeout=120, check=True)
            import shutil
            if shutil.which('sigcheck64.exe'):
                return True
            return False
        except:
            return False

    def _download_via_powershell(self, target_path: str) -> bool:
        if getattr(self, 'repair_mode', False):
            return False
        try:
            ps_cmd = f'$client = New-Object System.Net.WebClient; $client.DownloadFile("https://live.sysinternals.com/sigcheck64.exe", "{target_path}")'
            subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30, check=True)
            return os.path.exists(target_path)
        except:
            return False

    def _download_via_requests(self, target_path: str) -> bool:
        if getattr(self, 'repair_mode', False):
            return False
        try:
            import requests
            url = "https://live.sysinternals.com/sigcheck64.exe"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, 'wb') as f:
                    f.write(response.content)
                return True
            return False
        except:
            return False

    def ensure_sigcheck_available(self) -> bool:
        sigcheck_path = self.get_sigcheck_path()
        if os.path.exists(sigcheck_path):
            return True
        if getattr(self, 'repair_mode', False):
            return False
        os.makedirs(os.path.dirname(sigcheck_path) or tempfile.gettempdir(), exist_ok=True)
        if self._is_winget_available():
            if self._install_via_winget():
                if os.path.exists(sigcheck_path) or self.get_sigcheck_path() != sigcheck_path:
                    return True
        if self._download_via_powershell(sigcheck_path):
            return True
        if self._download_via_requests(sigcheck_path):
            return True
        return False

    def verify_signature(self, filepath):
        if filepath in self.signature_cache:
            return self.signature_cache[filepath]
        if not self.ensure_sigcheck_available():
            self.signature_cache[filepath] = None
            return None
        sigcheck_path = self.get_sigcheck_path()
        if not os.path.exists(sigcheck_path):
            self.signature_cache[filepath] = None
            return None
        try:
            output = check_output_command([sigcheck_path, '-q', '-a', filepath], timeout=15)
            if 'Signed' in output and 'Microsoft' in output:
                self.signature_cache[filepath] = 'Microsoft'
                return 'Microsoft'
            elif 'Signed' in output:
                self.signature_cache[filepath] = 'Other'
                return 'Other'
            else:
                self.signature_cache[filepath] = 'Unsigned'
                return 'Unsigned'
        except:
            self.signature_cache[filepath] = 'Error'
            return 'Error'

    def verify_signatures_batch(self, file_list):
        if not file_list:
            return {}
        if not self.ensure_sigcheck_available():
            return {f: None for f in file_list}
        sigcheck_path = self.get_sigcheck_path()
        if not os.path.exists(sigcheck_path):
            return {f: None for f in file_list}
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8')
        try:
            for f in file_list:
                temp_file.write(f + '\n')
            temp_file.close()
            output = check_output_command([sigcheck_path, '-q', '-a', '-nobanner', '-f', temp_file.name], timeout=120)
            results = {}
            current_file = None
            for line in output.splitlines():
                if line and (line[0].isalpha() and ':\\' in line[:3]):
                    current_file = line.strip()
                elif 'Signed:' in line and current_file:
                    if 'Microsoft' in output[max(0, output.find(current_file)):output.find(current_file)+1000]:
                        results[current_file] = 'Microsoft'
                    elif 'Signed' in line:
                        results[current_file] = 'Other'
                    else:
                        results[current_file] = 'Unsigned'
            for f in file_list:
                if f not in results:
                    results[f] = 'Error'
            return results
        except:
            return {f: 'Error' for f in file_list}
        finally:
            try:
                os.unlink(temp_file.name)
            except:
                pass

    def is_path_suspicious(self, path):
        if not path:
            return False
        lower_path = str(path).lower()
        return any(s in lower_path for s in SUSPICIOUS_PATH_PARTS)

    def assess_path_risk(self, path='', signature=None, context=''):
        score = 0
        reasons = []
        lower = str(path or '').lower()
        exe = extract_executable_path(path)
        ext = os.path.splitext(exe or lower)[1].lower()
        if any(s in lower for s in SUSPICIOUS_PATH_PARTS):
            score += 25
            reasons.append('suspicious_path')
        if ext in SCRIPT_EXTENSIONS:
            score += 15
            reasons.append('script_or_screensaver')
        if signature in ('Unsigned', 'Error', None):
            score += 20
            reasons.append(f'signature_{signature or "unknown"}')
        elif signature == 'Other':
            score += 5
            reasons.append('non_microsoft_signature')
        if context in ('WMI', 'COM', 'LSA', 'HiddenTask'):
            score += 30
            reasons.append(f'persistence_{context}')
        if any(name in lower for name in SCRIPT_NAMES):
            score += 35
            reasons.append('known_malware_family_name')
        return min(score, 100), reasons

    def risk_tag(self, score):
        if score >= 60:
            return ('highrisk',)
        if score >= 35:
            return ('suspicious',)
        return ('info',)

    def ui_safe(self, func, *args, **kwargs):
        try:
            self.after(0, lambda: func(*args, **kwargs))
        except Exception as e:
            log_exception('ui_safe', e)

    def export_selected_tree_rows(self, tree, prefix, extra=None):
        rows = []
        for item in tree.get_children():
            rows.append(tree.item(item, 'values'))
        payload = {'rows': rows, 'extra': extra or {}, 'created_at': datetime.datetime.now().isoformat()}
        return export_json_artifact(prefix, payload)

    def get_drivers_info_batch(self, progress_callback=None):
        drivers_dir = os.path.join(self.system_drive, 'Windows', 'System32', 'drivers')
        if not os.path.isdir(drivers_dir):
            return []
        sys_files = [os.path.join(drivers_dir, f) for f in os.listdir(drivers_dir) if f.lower().endswith('.sys')]
        sys_files = sys_files[:300]
        uncached = [f for f in sys_files if f not in self.signature_cache]
        if uncached:
            signatures = self.verify_signatures_batch(uncached)
            for f, sig in signatures.items():
                self.signature_cache[f] = sig
        drivers = []
        for i, full_path in enumerate(sys_files):
            if not self.scanning_flag:
                break
            fname = os.path.basename(full_path)
            sig = self.signature_cache.get(full_path, 'N/A')
            is_suspicious = (sig in ('Unsigned', 'Error')) and not fname.lower().startswith(('nt', 'win', 'hal', 'tcp', 'usb', 'pci', 'cdrom', 'disk', 'vol', 'fve', 'mount', 'sbp', 'vhd', 'vmbus'))
            drivers.append({
                'name': fname,
                'path': full_path,
                'signature': sig,
                'suspicious': is_suspicious
            })
            if progress_callback and i % 5 == 0:
                progress_callback(i, len(sys_files))
        return drivers

    def calculate_file_hash(self, filepath, algorithm='sha256'):
        try:
            if not os.path.isfile(filepath):
                return None
            hash_func = hashlib.new(algorithm)
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except:
            return None

    def take_fim_snapshot(self, directory, recursive=True):
        snapshot = {}
        if not os.path.exists(directory):
            return snapshot
        try:
            if recursive:
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        full_path = os.path.join(root, file)
                        try:
                            stat = os.stat(full_path)
                            snapshot[full_path.lower()] = {
                                'hash': self.calculate_file_hash(full_path),
                                'size': stat.st_size,
                                'mtime': stat.st_mtime,
                                'path': full_path
                            }
                        except:
                            continue
            else:
                for item in os.listdir(directory):
                    full_path = os.path.join(directory, item)
                    if os.path.isfile(full_path):
                        try:
                            stat = os.stat(full_path)
                            snapshot[full_path.lower()] = {
                                'hash': self.calculate_file_hash(full_path),
                                'size': stat.st_size,
                                'mtime': stat.st_mtime,
                                'path': full_path
                            }
                        except:
                            continue
        except:
            pass
        return snapshot

    def compare_fim_snapshots(self, old_snapshot, new_snapshot):
        changes = {
            'added': [],
            'removed': [],
            'modified': []
        }
        for path, info in new_snapshot.items():
            if path not in old_snapshot:
                changes['added'].append(info)
            else:
                old_info = old_snapshot[path]
                if old_info['hash'] != info['hash']:
                    changes['modified'].append({
                        'path': path,
                        'old_hash': old_info['hash'],
                        'new_hash': info['hash'],
                        'old_size': old_info['size'],
                        'new_size': info['size']
                    })
        for path, info in old_snapshot.items():
            if path not in new_snapshot:
                changes['removed'].append(info)
        return changes


    def _estimate_capture_size_gb(self, source_drive):
        total = 0
        skip_dirs = {'$recycle.bin', 'system volume information', 'pagefile.sys', 'hiberfil.sys', 'swapfile.sys'}
        for root, dirs, files in os.walk(source_drive):
            low_root = root.lower()
            if any(part in low_root for part in ('\\windows\\temp', '\\appdata\\local\\temp')):
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if d.lower() not in skip_dirs]
            for f in files:
                if f.lower() in skip_dirs:
                    continue
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except Exception:
                    pass
            if total > 80 * 1024**3:
                break
        return max(1, int(total / 1024**3 * 0.65))

    def create_recovery_kit(self):
        if self.repair_mode:
            self.show_error('Create Recovery Kit is intended for a running Windows installation, not WinRE mode.')
            return
        dest_dir = filedialog.askdirectory(title='Select destination folder for RecoveryKit')
        if not dest_dir:
            return
        kit_dir = os.path.join(dest_dir, 'RecoveryKit_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
        os.makedirs(kit_dir, exist_ok=True)
        image_path = os.path.join(kit_dir, 'install_backup.wim')
        winre_backup = os.path.join(kit_dir, 'winre_backup.wim')
        info_path = os.path.join(kit_dir, 'system_info.json')
        hash_path = os.path.join(kit_dir, 'hashes.json')
        source = self.system_drive.rstrip('\\') + '\\'
        if not messagebox.askyesno('Create Recovery Kit',
            f'This will capture the current Windows volume into a WIM image.\n\nSource: {source}\nDestination: {kit_dir}\n\nContinue?'):
            return
        progress = ProgressDialog(self, 'Creating Recovery Kit...')

        def worker():
            result = {'kit_dir': kit_dir, 'image_path': image_path, 'winre_backup': None, 'errors': []}
            try:
                bcd_path = os.path.join(kit_dir, 'bcd_backup.bcd')
                try:
                    run_command(['bcdedit', '/export', bcd_path], timeout=60)
                    result['bcd_backup'] = bcd_path
                except Exception as e:
                    result['errors'].append(f'BCD export failed: {e}')

                try:
                    proc = run_command(['reagentc', '/info'], timeout=30)
                    result['reagentc_info'] = proc.stdout
                    m = re.search(r'Windows RE location:\s*(.+)', proc.stdout or '', re.IGNORECASE)
                    if m:
                        loc = m.group(1).strip()
                        candidates = []
                        if loc.startswith('\\\\?\\GLOBALROOT'):
                            candidates.append(loc + '\\winre.wim')
                        candidates.append(os.path.join(self.system_drive, 'Windows', 'System32', 'Recovery', 'winre.wim'))
                        for c in candidates:
                            if os.path.exists(c):
                                shutil.copy2(c, winre_backup)
                                result['winre_backup'] = winre_backup
                                break
                except Exception as e:
                    result['errors'].append(f'WinRE backup failed: {e}')

                scratch = os.path.join(kit_dir, 'scratch')
                os.makedirs(scratch, exist_ok=True)
                exclusions = os.path.join(kit_dir, 'wim_exclusions.ini')
                with open(exclusions, 'w', encoding='utf-8') as f:
                    f.write('[ExclusionList]\n\\$Recycle.Bin\n\\System Volume Information\n\\pagefile.sys\n\\hiberfil.sys\n\\swapfile.sys\n\\Windows\\Temp\n')
                cmd = [
                    'dism', '/Capture-Image', f'/ImageFile:{image_path}', f'/CaptureDir:{source}',
                    '/Name:Current Windows Recovery Backup', '/Description:Captured by WREART',
                    '/Compress:Max', '/CheckIntegrity', f'/ScratchDir:{scratch}', f'/ConfigFile:{exclusions}'
                ]
                run_command(cmd, timeout=24*60*60, check=True)
                result['image_created'] = os.path.exists(image_path)

                try:
                    info = check_output_command(['dism', '/Get-WimInfo', f'/WimFile:{image_path}'], timeout=120)
                    result['wim_info'] = info
                except Exception as e:
                    result['errors'].append(f'WIM verification failed: {e}')

                hashes = {}
                for fp in (image_path, winre_backup):
                    if fp and os.path.exists(fp):
                        hashes[os.path.basename(fp)] = self.calculate_file_hash(fp)
                with open(hash_path, 'w', encoding='utf-8') as f:
                    json.dump(hashes, f, ensure_ascii=False, indent=2)
                result['hashes'] = hashes

                with open(info_path, 'w', encoding='utf-8') as f:
                    json.dump(result, f, ensure_ascii=False, indent=2, default=str)

                cfg = load_persisted_config()
                cfg['install_wim_backup'] = image_path
                cfg['recovery_kit_dir'] = kit_dir
                cfg['winre_backup'] = winre_backup if os.path.exists(winre_backup) else ''
                save_persisted_config(cfg)
                self.after(0, lambda: self.backup_status_label.config(text=f'RecoveryKit: {kit_dir}', foreground='green'))
                self.after(0, lambda: self.show_info(f'Recovery Kit created:\n{kit_dir}'))
            except Exception as e:
                log_exception('create_recovery_kit', e)
                self.after(0, lambda: self.show_error(f'Recovery Kit creation failed:\n{e}'))
            finally:
                self.after(0, progress.close)
        threading.Thread(target=worker, daemon=True).start()

    def auto_prepare_recovery_kit(self):
        if self.repair_mode:
            return
        cfg = load_persisted_config()
        existing = cfg.get('recovery_kit_dir')
        if existing and os.path.isdir(existing):
            kit_dir = existing
        else:
            kit_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'WinREHelperPro_RecoveryKit')
            os.makedirs(kit_dir, exist_ok=True)
            cfg['recovery_kit_dir'] = kit_dir
            save_persisted_config(cfg)
        def worker():
            result = {'kit_dir': kit_dir, 'created_at': datetime.datetime.now().isoformat(), 'mode': 'auto-lightweight', 'errors': []}
            try:
                bcd_path = os.path.join(kit_dir, 'bcd_backup_auto.bcd')
                try:
                    run_command(['bcdedit', '/export', bcd_path], timeout=60)
                    result['bcd_backup'] = bcd_path
                except Exception as e:
                    result['errors'].append(f'BCD export failed: {e}')
                winre_dest = os.path.join(kit_dir, 'winre_backup_auto.wim')
                try:
                    candidates = [os.path.join(self.system_drive, 'Windows', 'System32', 'Recovery', 'winre.wim')]
                    proc = run_command(['reagentc', '/info'], timeout=30)
                    result['reagentc_info'] = proc.stdout
                    m = re.search(r'Windows RE location:\s*(.+)', proc.stdout or '', re.IGNORECASE)
                    if m:
                        loc = m.group(1).strip()
                        if loc.startswith('\\\\?\\GLOBALROOT'):
                            candidates.insert(0, loc + '\\winre.wim')
                    for c in candidates:
                        if c and os.path.exists(c):
                            shutil.copy2(c, winre_dest)
                            result['winre_backup'] = winre_dest
                            break
                except Exception as e:
                    result['errors'].append(f'WinRE auto backup failed: {e}')
                sysinfo = {
                    'computer': os.environ.get('COMPUTERNAME', ''),
                    'user': os.environ.get('USERNAME', ''),
                    'system_drive': self.system_drive,
                    'repair_mode': self.repair_mode,
                    'timestamp': datetime.datetime.now().isoformat(),
                }
                result['system_info'] = sysinfo
                hashes = {}
                for fp in (result.get('winre_backup'), result.get('bcd_backup')):
                    if fp and os.path.exists(fp):
                        hashes[os.path.basename(fp)] = self.calculate_file_hash(fp)
                result['hashes'] = hashes
                with open(os.path.join(kit_dir, 'auto_recovery_kit_status.json'), 'w', encoding='utf-8') as f:
                    json.dump(result, f, ensure_ascii=False, indent=2)
                cfg = load_persisted_config()
                cfg['recovery_kit_dir'] = kit_dir
                if result.get('winre_backup'):
                    cfg['winre_backup'] = result['winre_backup']
                save_persisted_config(cfg)
                self.after(0, lambda: self.update_status(f'Auto Recovery Kit prepared: {kit_dir}'))
                if hasattr(self, 'backup_status_label'):
                    self.after(0, lambda: self.backup_status_label.config(text=f'Auto RecoveryKit: {kit_dir}', foreground='#047857'))
            except Exception as e:
                log_exception('auto_prepare_recovery_kit', e)
        threading.Thread(target=worker, daemon=True).start()

    def backup_install_wim(self):
        self.create_recovery_kit()

    def verify_wim_backup(self):
        cfg = load_persisted_config()
        wim = cfg.get('install_wim_backup') or filedialog.askopenfilename(title='Select WIM/ESD to verify', filetypes=[('Windows images', '*.wim *.esd'), ('All files', '*.*')])
        if not wim:
            return
        try:
            info = check_output_command(['dism', '/Get-WimInfo', f'/WimFile:{wim}'], timeout=120)
            sha = self.calculate_file_hash(wim)
            out = export_json_artifact('wim_verify', {'path': wim, 'sha256': sha, 'dism_info': info})
            self.show_info(f'WIM verified. SHA256:\n{sha}\n\nReport:\n{out}')
        except Exception as e:
            self.show_error(f'WIM verification failed: {e}')

    def restore_winre_from_backup(self):
        cfg = load_persisted_config()
        src = cfg.get('winre_backup') if cfg.get('winre_backup') and os.path.exists(cfg.get('winre_backup')) else ''
        if not src:
            src = filedialog.askopenfilename(title='Select winre_backup.wim', filetypes=[('WIM files', '*.wim'), ('All files', '*.*')])
        if not src:
            return
        dst_dir = os.path.join(self.system_drive, 'Windows', 'System32', 'Recovery')
        dst = os.path.join(dst_dir, 'winre.wim')
        if not messagebox.askyesno('Restore WinRE', f'Copy:\n{src}\n\nto:\n{dst}\n\nContinue?'):
            return
        try:
            os.makedirs(dst_dir, exist_ok=True)
            if os.path.exists(dst):
                shutil.copy2(dst, dst + '.bak_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
            shutil.copy2(src, dst)
            try:
                if self.repair_mode:
                    run_command(['reagentc', '/setreimage', '/path', dst_dir, '/target', self.system_drive.rstrip('\\')], timeout=60)
                else:
                    run_command(['reagentc', '/setreimage', '/path', dst_dir], timeout=60)
                    run_command(['reagentc', '/enable'], timeout=60)
            except Exception as e:
                log_exception('restore_winre_reagentc', e)
            self.show_info(f'WinRE restored to:\n{dst}')
        except Exception as e:
            self.show_error(f'WinRE restore failed: {e}')

    def repair_winre(self):
        cfg = load_persisted_config()
        install_wim = cfg.get('install_wim_backup')
        if install_wim and os.path.exists(install_wim):
            if messagebox.askyesno('Use backup', f'Use existing backup?\n{install_wim}'):
                pass
            else:
                install_wim = filedialog.askopenfilename(
                    title='Select install.wim',
                    filetypes=[('WIM files', '*.wim'), ('All files', '*.*')]
                )
        else:
            install_wim = filedialog.askopenfilename(
                title='Select install.wim',
                filetypes=[('WIM files', '*.wim'), ('All files', '*.*')]
            )
        if not install_wim:
            return
        mount_point = os.path.join(tempfile.gettempdir(), 'mount_wim_repair')
        os.makedirs(mount_point, exist_ok=True)
        try:
            out = check_output_command(['dism', '/Get-WimInfo', f'/WimFile:{install_wim}'], timeout=30)
            index = '1'
            for line in out.splitlines():
                if 'Index :' in line:
                    index = line.split(':')[1].strip()
                    break
            run_command(['dism', '/Mount-Image', f'/ImageFile:{install_wim}', f'/Index:{index}', f'/MountDir:{mount_point}'], check=True, timeout=120)
            src_winre = os.path.join(mount_point, 'Windows', 'System32', 'Recovery', 'winre.wim')
            dst_winre = os.path.join(self.system_drive, 'Windows', 'System32', 'Recovery', 'winre.wim')
            dst_dir = os.path.dirname(dst_winre)
            if not os.path.exists(dst_dir):
                os.makedirs(dst_dir, exist_ok=True)
            if os.path.exists(src_winre):
                shutil.copy2(src_winre, dst_winre)
                self.show_info('WinRE restored. Run "reagentc /enable" to activate.')
            else:
                self.show_error('winre.wim not found in install image.')
        except subprocess.CalledProcessError as e:
            self.show_error(f'DISM error: {e}')
        except Exception as e:
            self.show_error(f'Repair failed: {e}')
        finally:
            try:
                run_command(['dism', '/Unmount-Image', f'/MountDir:{mount_point}', '/Discard'], timeout=60)
                os.rmdir(mount_point)
            except:
                pass




    def show_drivers_window(self):
        win = Toplevel(self)
        win.title('Driver Analysis - Non-Microsoft Drivers Highlighted')
        win.geometry('900x500')
        columns = ('Driver', 'Signature', 'Path')
        tree = ttk.Treeview(win, columns=columns, show='headings')
        for col in columns:
            tree.heading(col, text=col)
            tree.column('Driver', width=200)
            tree.column('Signature', width=100)
            tree.column('Path', width=550)
        tree.tag_configure('suspicious', foreground='red')
        tree.tag_configure('microsoft', foreground='green')
        scroll = ttk.Scrollbar(win, orient=VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side=LEFT, fill=BOTH, expand=True)
        scroll.pack(side=RIGHT, fill=Y)
        button_frame = ttk.Frame(win)
        button_frame.pack(fill=X, padx=10, pady=5)
        stop_btn = ttk.Button(button_frame, text='Stop', command=self.stop_scanning)
        stop_btn.pack(side=RIGHT, padx=5)
        progress_frame = ttk.Frame(win)
        progress_frame.pack(fill=X, padx=10, pady=5)
        progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        progress_bar.pack(side=LEFT, fill=X, expand=True, padx=5)
        status_label = ttk.Label(win, text="Analyzing drivers...", font=('Segoe UI', 8))
        status_label.pack(pady=5)
        self.scanning_flag = True
        def progress_callback(current, total):
            win.after(0, lambda: progress_bar.configure(value=current, maximum=total))
            win.after(0, lambda: status_label.config(text=f"Checking {current}/{total} drivers..."))
        def load():
            drivers = self.get_drivers_info_batch(progress_callback)
            win.after(0, lambda: self._populate_drivers_tree(win, tree, drivers, progress_bar, status_label, stop_btn))
        threading.Thread(target=load, daemon=True).start()

    def _populate_drivers_tree(self, win, tree, drivers, progress_bar, status_label, stop_btn):
        for item in tree.get_children():
            tree.delete(item)
        for d in drivers:
            if d['signature'] == 'Microsoft':
                tags = ('microsoft',)
            elif d['suspicious']:
                tags = ('suspicious',)
            else:
                tags = ()
            tree.insert('', 'end', values=(d['name'], d['signature'] or 'N/A', d['path']), tags=tags)
        progress_bar.stop()
        stop_btn.destroy()
        status_label.config(text=f"Found {len(drivers)} drivers. Red = suspicious (unsigned/error)")

    def stop_scanning(self):
        self.scanning_flag = False

    def initial_load(self):
        progress = ProgressDialog(self, 'Loading data...')
        def load_thread():
            try:
                self.populate_winlogon()
                self.update_gp_values()
                self.update_shell_values()
                self.populate_ifeo()
                self.populate_all_autostart()
                self.populate_services()
                self.refresh_tasks()
                self.populate_advanced_autostart()
                self.after(0, progress.close)
                self.after(0, lambda: self.update_status('Data loaded successfully'))
            except Exception as e:
                self.after(0, progress.close)
                self.after(0, lambda: self.show_error(f'Load error: {e}'))
        threading.Thread(target=load_thread, daemon=True).start()

    def detect_winre_environment(self):
        return os.getenv('SystemRoot', '').upper().startswith('X:')

    def get_available_drives(self):
        drives = []
        try:
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i, letter in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
                if bitmask & (1 << i):
                    drives.append(f'{letter}:\\')
        except:
            drives = [f'{c}:\\' for c in 'CDEFGHIJKLMNOPQRSTUVWXYZ']
        return drives

    def detect_or_prompt_system_drive(self):
        cfg = load_persisted_config()
        last = cfg.get('system_drive')
        if last and self.is_valid_system_drive(last):
            return last
        for d in self.get_available_drives():
            if self.is_valid_system_drive(d):
                cfg['system_drive'] = d
                save_persisted_config(cfg)
                return d
        return 'C:\\'

    def is_valid_system_drive(self, drive):
        required = [
            'Windows\\System32\\kernel32.dll',
            'Windows\\System32\\config\\SYSTEM',
            'Windows\\System32\\cmd.exe',
            'Windows\\explorer.exe'
        ]
        for p in required:
            if not os.path.exists(os.path.join(drive, p)):
                return False
        return True

    def persist_drive(self):
        cfg = load_persisted_config()
        cfg['system_drive'] = self.system_drive
        save_persisted_config(cfg)

    def manual_select_drive(self, drives):
        win = Toplevel(self)
        win.title('Select system drive')
        win.geometry('500x350')
        win.transient(self)
        win.grab_set()
        ttk.Label(win, text='Press OK to select system volume:', font=('Segoe UI', 9)).pack(anchor=W, padx=10, pady=6)
        columns = ('Letter', 'Label/FS/Size', 'Windows')
        tree = ttk.Treeview(win, columns=columns, show='headings', height=12)
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, anchor=W, width=150 if col == 'Label/FS/Size' else 70)
        tree.pack(fill=BOTH, expand=True, padx=10, pady=5)
        for d in drives:
            info = pretty_drive_name(d)
            iswin = 'Yes' if self.is_valid_system_drive(d) else ''
            tree.insert('', END, values=(d, info[3:], iswin))
        sel_var = StringVar()
        def on_select(_):
            item = tree.item(tree.focus())
            if item and item['values']:
                sel_var.set(item['values'][0])
        tree.bind('<<TreeviewSelect>>', on_select)
        btns = Frame(win)
        btns.pack(pady=6)
        ttk.Button(btns, text='OK', width=10, command=win.destroy).pack(side=LEFT, padx=4)
        ttk.Button(btns, text='Cancel', width=10, command=lambda: (sel_var.set(''), win.destroy())).pack(side=LEFT)
        self.wait_window(win)
        return sel_var.get() if sel_var.get() else None

    def auto_detect_drive(self):
        drive = self.detect_or_prompt_system_drive()
        if drive and drive != self.system_drive:
            self.system_drive = drive
            self.persist_drive()
            self.update_status()
            messagebox.showinfo('Drive found', f'System drive set to: {drive}')
        else:
            messagebox.showinfo('Auto-detect', f'System drive: {self.system_drive}')

    def update_status(self, message=None):
        if message is None:
            drive_info = pretty_drive_name(self.system_drive)
            message = f"Ready. Mode: {'WinRE' if self.repair_mode else 'Windows'}, Drive: {drive_info}"
        self.status_var.set(message)
        self.update()

    def change_system_drive(self):
        new_drive = self.manual_select_drive(self.get_available_drives())
        if new_drive and self.is_valid_system_drive(new_drive):
            self.system_drive = new_drive
            self.persist_drive()
            self.update_status()
            self.initial_load()
            messagebox.showinfo('Success', f'System drive changed to {self.system_drive}')
        else:
            messagebox.showwarning('Cancel', 'Selected drive is not a system drive or cancelled.')

    def validate_system_drive(self):
        if os.path.abspath(self.system_drive).upper().startswith('X:\\'):
            messagebox.showerror('Error', 'Attempt to work with WinRE drive (X:). Exiting.')
            return False
        return self.is_valid_system_drive(self.system_drive)

    def setup_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=BOTH, expand=True, padx=5, pady=5)
        tabs = [
            ('Autostart', self.setup_autostart_tab),
            ('Advanced Autostart', self.setup_advanced_autostart_tab),
            ('Deep Autoruns', self.setup_deep_autoruns_tab),
            ('IFEO', self.setup_ifeo_tab),
            ('Policies', self.setup_gp_tab),
            ('Shell/Userinit', self.setup_shell_tab),
            ('Services', self.setup_services_tab),
            ('Task Scheduler', self.setup_taskscheduler_tab),
            ('Boot/Disk', self.setup_mbr_tab),
            ('Advanced', self.setup_advanced_tab),
            ('Unlock', self.setup_unlock_tab),
            ('Virus Removal', self.setup_virus_removal_tab),
            ('Forensics', self.setup_forensics_tab),
            ('FIM / Integrity', self.setup_fim_tab),
            ('About', self.setup_about_tab)
        ]
        for name, maker in tabs:
            frame = ttk.Frame(notebook)
            maker(frame)
            notebook.add(frame, text=name)



    def setup_about_tab(self, parent):
        wrapper = ttk.Frame(parent)
        wrapper.pack(fill=BOTH, expand=True, padx=24, pady=24)
        ttk.Label(wrapper, text='WREART', style='Title.TLabel').pack(anchor=W, pady=(0, 12))
        ttk.Label(wrapper, text='Windows recovery and manual autoruns repair utility.', style='Muted.TLabel').pack(anchor=W, pady=(0, 18))
        card = ttk.LabelFrame(wrapper, text='Contacts')
        card.pack(anchor=W, fill=X, padx=0, pady=8)
        ttk.Label(card, text='Telegram channel: @antiratnik').pack(anchor=W, padx=12, pady=(12, 4))
        ttk.Label(card, text='Donate: www.donationalerts.com/r/antirat').pack(anchor=W, padx=12, pady=(4, 12))
        ttk.Separator(wrapper).pack(fill=X, pady=18)
        ttk.Label(wrapper, text='The tool is designed for manual review and recovery workflows. Always create backups before changing autorun entries.', wraplength=760, justify=LEFT).pack(anchor=W)

    def setup_forensics_tab(self, parent):
        group = ttk.LabelFrame(parent, text='Forensic / Recovery Kit')
        group.pack(fill=BOTH, expand=True, padx=10, pady=10)

        header = ttk.Label(group, text='Create a recovery kit from the currently working Windows installation.', font=('Segoe UI', 10, 'bold'))
        header.pack(anchor=W, padx=10, pady=(10, 4))
        desc = ttk.Label(group, text='The kit can include install_backup.wim, winre_backup.wim, BCD backup, hashes and system metadata. Use it before remediation so you can restore WinRE or recover files later.', justify=LEFT)
        desc.pack(anchor=W, padx=10, pady=(0, 10))
        if self.repair_mode:
            ttk.Label(group, text='WinRE mode: Recovery Kit capture is disabled; offline WinRE restore/repair and WIM verification remain available.', foreground='#b45309').pack(anchor=W, padx=10, pady=(0, 10))

        btn_frame = ttk.Frame(group)
        btn_frame.pack(fill=X, padx=10, pady=5)
        create_btn = ttk.Button(btn_frame, text='Create Recovery Kit from current Windows', command=self.create_recovery_kit)
        create_btn.pack(side=LEFT, padx=4)
        auto_btn = ttk.Button(btn_frame, text='Refresh Auto Recovery Kit', command=self.auto_prepare_recovery_kit)
        auto_btn.pack(side=LEFT, padx=4)
        ttk.Button(btn_frame, text='Verify WIM Backup', command=self.verify_wim_backup).pack(side=LEFT, padx=4)
        ttk.Button(btn_frame, text='Restore WinRE from Backup', command=self.restore_winre_from_backup).pack(side=LEFT, padx=4)
        ttk.Button(btn_frame, text='Repair WinRE from WIM/ESD', command=self.repair_winre).pack(side=LEFT, padx=4)
        if self.repair_mode:
            create_btn.configure(state=DISABLED)
            auto_btn.configure(state=DISABLED)

        self.backup_status_label = ttk.Label(group, text='', font=('Segoe UI', 9, 'italic'))
        self.backup_status_label.pack(anchor=W, padx=12, pady=8)
        cfg = load_persisted_config()
        kit = cfg.get('recovery_kit_dir')
        backup_path = cfg.get('install_wim_backup')
        if kit and os.path.exists(kit):
            self.backup_status_label.config(text=f'Last RecoveryKit: {kit}', foreground='#047857')
        elif backup_path and os.path.exists(backup_path):
            self.backup_status_label.config(text=f'WIM backup exists: {backup_path}', foreground='#047857')
        else:
            self.backup_status_label.config(text='No RecoveryKit found yet', foreground='#b45309')

        ttk.Separator(group).pack(fill=X, padx=10, pady=10)
        ttk.Button(group, text='Analyze Drivers (Unsigned / Non-Microsoft)', command=self.show_drivers_window).pack(anchor=W, padx=10, pady=5)
        ttk.Label(group, text='Note: CAPA and YARA modules were removed. Driver and persistence scans use local Windows data and Authenticode/Sigcheck where available.', justify=LEFT).pack(anchor=W, padx=10, pady=10)

    def setup_deep_autoruns_tab(self, parent):
        self.deep_filter = StringVar(value='')
        self.deep_status = StringVar(value='Ready')
        wrapper = ttk.Frame(parent)
        wrapper.pack(fill=BOTH, expand=True, padx=10, pady=10)

        header = ttk.Frame(wrapper)
        header.pack(fill=X, pady=(0, 8))
        ttk.Label(header, text='Deep Autoruns', style='Title.TLabel').pack(side=LEFT)
        ttk.Button(header, text='Refresh', command=self.populate_deep_autoruns).pack(side=RIGHT, padx=3)
        ttk.Button(header, text='Export CSV', command=self.export_deep_autoruns).pack(side=RIGHT, padx=3)
        ttk.Button(header, text='Backup selected', command=self.backup_deep_entry).pack(side=RIGHT, padx=3)
        ttk.Button(header, text='Delete selected', command=self.delete_deep_entry).pack(side=RIGHT, padx=3)
        ttk.Button(header, text='Edit value', command=self.edit_deep_entry).pack(side=RIGHT, padx=3)
        ttk.Button(header, text='Disable selected', command=self.disable_deep_entry).pack(side=RIGHT, padx=3)

        search = ttk.Frame(wrapper)
        search.pack(fill=X, pady=(0, 8))
        ttk.Label(search, text='Filter:').pack(side=LEFT)
        entry = ttk.Entry(search, textvariable=self.deep_filter, width=42)
        entry.pack(side=LEFT, padx=6)
        entry.bind('<KeyRelease>', lambda _e: self.apply_deep_filter())
        ttk.Button(search, text='Clear', command=lambda: (self.deep_filter.set(''), self.apply_deep_filter())).pack(side=LEFT)

        self.deep_notebook = ttk.Notebook(wrapper)
        self.deep_notebook.pack(fill=BOTH, expand=True)
        self.deep_trees = {}
        self.deep_rows = {}
        self.deep_meta = {}
        categories = [
            ('Run Keys', ('Hive', 'Registry Path', 'Name', 'Command', 'Status')),
            ('Startup Folders', ('Profile', 'Folder', 'File', 'Target', 'Status')),
            ('AppInit DLLs', ('Hive', 'Registry Path', 'Value', 'Data', 'Status')),
            ('Winlogon', ('Hive', 'Registry Path', 'Value', 'Data', 'Status')),
            ('Active Setup', ('Hive', 'Component', 'Value', 'Data', 'Status')),
            ('Explorer Extensions', ('Hive', 'Extension Type', 'Name/CLSID', 'Data', 'Status')),
            ('Browser Components', ('Hive', 'Component Type', 'Name/CLSID', 'Data', 'Status')),
            ('Winsock / Network', ('Source', 'Name', 'Value', 'Data', 'Status')),
            ('Hosts / DNS', ('Source', 'Name', 'Value', 'Data', 'Status')),
        ]
        for title, cols in categories:
            frame = ttk.Frame(self.deep_notebook)
            self.deep_notebook.add(frame, text=title)
            tree = ttk.Treeview(frame, columns=cols, show='headings', selectmode='browse')
            for c in cols:
                tree.heading(c, text=c, command=lambda tr=tree, col=c: self._sort_treeview_column(tr, col, False))
                width = 120
                if c in ('Command', 'Data', 'Target'):
                    width = 480
                elif c in ('Registry Path', 'Folder', 'Component'):
                    width = 280
                tree.column(c, width=width, anchor=W)
            tree.tag_configure('default', foreground='#111827')
            tree.tag_configure('attention', foreground='#b45309')
            tree.tag_configure('disabled', foreground='#6b7280')
            tree.tag_configure('missing', foreground='#dc2626')
            scroll_y = ttk.Scrollbar(frame, orient=VERTICAL, command=tree.yview)
            scroll_x = ttk.Scrollbar(frame, orient=HORIZONTAL, command=tree.xview)
            tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
            tree.pack(side=LEFT, fill=BOTH, expand=True)
            scroll_y.pack(side=RIGHT, fill=Y)
            scroll_x.pack(side=BOTTOM, fill=X)
            menu = Menu(self, tearoff=0)
            menu.add_command(label='Disable selected autorun', command=self.disable_deep_entry)
            menu.add_command(label='Edit registry value', command=self.edit_deep_entry)
            menu.add_command(label='Delete / quarantine entry', command=self.delete_deep_entry)
            menu.add_command(label='Backup selected entry', command=self.backup_deep_entry)
            menu.add_separator()
            menu.add_command(label='Copy row', command=lambda tr=tree: self.copy_tree_row(tr))
            menu.add_command(label='Open file location', command=lambda tr=tree: self.open_selected_path_location(tr))
            tree.bind('<Button-3>', lambda e, tr=tree, m=menu: self._show_tree_menu(e, tr, m))
            self.deep_trees[title] = tree
            self.deep_rows[title] = []
        ttk.Label(wrapper, textvariable=self.deep_status, anchor=W).pack(fill=X, pady=(6, 0))
        self.populate_deep_autoruns()

    def _show_tree_menu(self, event, tree, menu):
        row = tree.identify_row(event.y)
        if row:
            tree.selection_set(row)
            tree.focus(row)
            menu.post(event.x_root, event.y_root)

    def copy_tree_row(self, tree):
        item = tree.focus()
        if not item:
            return
        vals = tree.item(item, 'values')
        self.clipboard_clear()
        self.clipboard_append('\t'.join(map(str, vals)))

    def open_selected_path_location(self, tree):
        if getattr(self, 'repair_mode', False) or not self.command_exists('explorer.exe'):
            self.show_info('Open file location is unavailable in WinRE mode.')
            return
        item = tree.focus()
        if not item:
            return
        vals = [str(x) for x in tree.item(item, 'values')]
        for v in reversed(vals):
            path = extract_executable_path(v)
            if path and os.path.exists(path):
                try:
                    run_command(['explorer', f'/select,{path}'], timeout=10)
                except Exception as e:
                    self.show_error(str(e))
                return
        self.show_info('No existing local file path found in selected row.')

    def _add_deep_row(self, category, values, status='Info', meta=None):
        tag = 'default'
        low = ' '.join(map(str, values)).lower()
        if status.lower().startswith('disabled'):
            tag = 'disabled'
        elif 'file missing' in status.lower():
            tag = 'missing'
        elif any(part in low for part in SUSPICIOUS_PATH_PARTS) or any(ext in low for ext in SCRIPT_EXTENSIONS):
            tag = 'attention'
        row = tuple(values)
        self.deep_rows.setdefault(category, []).append((row, tag))
        if meta:
            meta = dict(meta)
            meta.setdefault('category', category)
            self.deep_meta[(category, row)] = meta

    def _registry_value_status(self, data):
        text = str(data or '').strip()
        if not text:
            return 'Empty'
        exe = extract_executable_path(text)
        expanded = os.path.expandvars(exe)
        if exe and (':' in exe or exe.startswith('\\')) and not os.path.exists(expanded):
            return 'File missing'
        return 'Present'

    def _read_values_from_key(self, hive, path, category, hive_name, only_names=None, recurse_subkeys=False, component_value_names=None):
        try:
            with winreg.OpenKey(hive, path) as key:
                if component_value_names:
                    i = 0
                    while True:
                        try:
                            sub = winreg.EnumKey(key, i)
                            subpath = path + '\\' + sub
                            try:
                                with winreg.OpenKey(hive, subpath) as sk:
                                    for vn in component_value_names:
                                        try:
                                            val, typ = winreg.QueryValueEx(sk, vn)
                                            self._add_deep_row(category, (hive_name, sub, vn, str(val), self._registry_value_status(val)), meta={'type':'registry','hive_name':hive_name,'path':subpath,'value_name':vn,'reg_type':typ})
                                        except FileNotFoundError:
                                            pass
                            except Exception:
                                pass
                            i += 1
                        except OSError:
                            break
                    return
                i = 0
                while True:
                    try:
                        name, val, typ = winreg.EnumValue(key, i)
                        if only_names is None or name in only_names:
                            self._add_deep_row(category, (hive_name, path, name, str(val), self._registry_value_status(val)), meta={'type':'registry','hive_name':hive_name,'path':path,'value_name':name,'reg_type':typ})
                        i += 1
                    except OSError:
                        break
                if recurse_subkeys:
                    j = 0
                    while True:
                        try:
                            sub = winreg.EnumKey(key, j)
                            self._read_values_from_key(hive, path + '\\' + sub, category, hive_name, only_names, False, None)
                            j += 1
                        except OSError:
                            break
        except FileNotFoundError:
            return
        except Exception as e:
            logging.info('Registry read failed %s %s: %s', hive_name, path, e)

    def _collect_deep_run_keys(self):
        run_paths = [
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
            r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
            r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
            r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
            r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run',
            r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        ]
        for path in run_paths:
            self._read_values_from_key(winreg.HKEY_LOCAL_MACHINE, self.get_registry_path(path), 'Run Keys', 'HKLM')
        if not self.repair_mode:
            user_paths = [p.replace('SOFTWARE\\', 'Software\\', 1) for p in run_paths if not p.startswith('SOFTWARE\\Wow6432Node')]
            user_paths += [r'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run', r'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run']
            for path in user_paths:
                self._read_values_from_key(winreg.HKEY_CURRENT_USER, path, 'Run Keys', 'HKCU')

    def _collect_deep_startup_folders(self):
        folders = []
        folders.append(('All Users', os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')))
        users_root = os.path.join(self.system_drive, 'Users')
        if os.path.isdir(users_root):
            for user in os.listdir(users_root):
                folders.append((user, os.path.join(users_root, user, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')))
        for profile, folder in folders:
            if not os.path.isdir(folder):
                continue
            try:
                for name in os.listdir(folder):
                    full = os.path.join(folder, name)
                    status = 'Present' if os.path.exists(full) else 'File missing'
                    self._add_deep_row('Startup Folders', (profile, folder, name, full, status), status, meta={'type':'file','path':full,'folder':folder,'name':name})
            except Exception as e:
                logging.info('Startup folder scan failed %s: %s', folder, e)

    def _collect_deep_appinit_winlogon_active(self):
        appinit_values = {'AppInit_DLLs', 'LoadAppInit_DLLs', 'RequireSignedAppInit_DLLs'}
        appinit_paths = [r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', r'SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows']
        for path in appinit_paths:
            self._read_values_from_key(winreg.HKEY_LOCAL_MACHINE, self.get_registry_path(path), 'AppInit DLLs', 'HKLM', only_names=appinit_values)
        winlogon_values = {'Shell', 'Userinit', 'TaskMan', 'System', 'VmApplet', 'AutoAdminLogon'}
        self._read_values_from_key(winreg.HKEY_LOCAL_MACHINE, self.get_registry_path(r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'), 'Winlogon', 'HKLM', only_names=winlogon_values)
        self._read_values_from_key(winreg.HKEY_LOCAL_MACHINE, self.get_registry_path(r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify'), 'Winlogon', 'HKLM', recurse_subkeys=True)
        if not self.repair_mode:
            self._read_values_from_key(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon', 'Winlogon', 'HKCU', only_names=winlogon_values)
        active_values = ['StubPath', 'Localized Name', 'Version', 'IsInstalled']
        self._read_values_from_key(winreg.HKEY_LOCAL_MACHINE, self.get_registry_path(r'SOFTWARE\Microsoft\Active Setup\Installed Components'), 'Active Setup', 'HKLM', component_value_names=active_values)
        if not self.repair_mode:
            self._read_values_from_key(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Active Setup\Installed Components', 'Active Setup', 'HKCU', component_value_names=active_values)

    def _collect_deep_explorer_browser(self):
        explorer_paths = [
            ('ContextMenuHandlers', r'SOFTWARE\Classes\*\shellex\ContextMenuHandlers'),
            ('Directory ContextMenuHandlers', r'SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers'),
            ('Folder ContextMenuHandlers', r'SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers'),
            ('IconHandler', r'SOFTWARE\Classes\lnkfile\shellex\IconHandler'),
            ('PropertySheetHandlers', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\PropertySheetHandlers'),
            ('ShellExecuteHooks', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks'),
            ('SharedTaskScheduler', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler'),
            ('Approved Shell Extensions', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved'),
        ]
        for typ, path in explorer_paths:
            before = len(self.deep_rows.get('Explorer Extensions', []))
            self._read_values_from_key(winreg.HKEY_LOCAL_MACHINE, self.get_registry_path(path), 'Explorer Extensions', 'HKLM')
            if not self.repair_mode:
                self._read_values_from_key(winreg.HKEY_CURRENT_USER, path.replace('SOFTWARE\\', 'Software\\', 1), 'Explorer Extensions', 'HKCU')
        browser_paths = [
            ('Browser Helper Objects', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'),
            ('URLSearchHooks', r'SOFTWARE\Microsoft\Internet Explorer\URLSearchHooks'),
            ('Toolbar', r'SOFTWARE\Microsoft\Internet Explorer\Toolbar'),
            ('Extensions', r'SOFTWARE\Microsoft\Internet Explorer\Extensions'),
        ]
        for typ, path in browser_paths:
            self._read_values_from_key(winreg.HKEY_LOCAL_MACHINE, self.get_registry_path(path), 'Browser Components', 'HKLM', recurse_subkeys=True)
            if not self.repair_mode:
                self._read_values_from_key(winreg.HKEY_CURRENT_USER, path.replace('SOFTWARE\\', 'Software\\', 1), 'Browser Components', 'HKCU', recurse_subkeys=True)

    def _collect_deep_network(self):
        winsock_paths = [
            r'SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries',
            r'SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries',
        ]
        for path in winsock_paths:
            self._read_values_from_key(winreg.HKEY_LOCAL_MACHINE, self.get_registry_path(path), 'Winsock / Network', 'HKLM', recurse_subkeys=True)
        hosts = os.path.join(self.system_drive, 'Windows', 'System32', 'drivers', 'etc', 'hosts')
        if os.path.exists(hosts):
            try:
                with open(hosts, 'r', encoding='utf-8', errors='ignore') as f:
                    for n, line in enumerate(f, 1):
                        raw = line.strip()
                        if not raw or raw.startswith('#'):
                            continue
                        status = 'Present'
                        lowered = raw.lower()
                        if any(vendor in lowered for vendor in ('microsoft.com', 'windowsupdate.com', 'kaspersky', 'eset', 'avast', 'malwarebytes', 'virustotal')):
                            status = 'Review'
                        self._add_deep_row('Hosts / DNS', ('hosts', f'line {n}', 'entry', raw, status), status, meta={'type':'hosts','path':hosts,'line':n,'data':raw})
            except Exception as e:
                logging.info('Hosts read failed: %s', e)
        interfaces = self.get_registry_path(r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces')
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, interfaces) as key:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(key, i)
                        sp = interfaces + '\\' + sub
                        for vn in ('NameServer', 'DhcpNameServer', 'DefaultGateway', 'DhcpDefaultGateway'):
                            try:
                                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sp) as sk:
                                    val, typ = winreg.QueryValueEx(sk, vn)
                                    if val:
                                        self._add_deep_row('Hosts / DNS', ('TCP/IP', sub, vn, str(val), 'Present'), meta={'type':'registry','hive_name':'HKLM','path':sp,'value_name':vn,'reg_type':typ})
                            except FileNotFoundError:
                                pass
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass

    def populate_deep_autoruns(self):
        for k in self.deep_rows:
            self.deep_rows[k] = []
        self.deep_meta = {}
        self.deep_status.set('Collecting autorun locations...')
        def worker():
            try:
                self._collect_deep_run_keys()
                self._collect_deep_startup_folders()
                self._collect_deep_appinit_winlogon_active()
                self._collect_deep_explorer_browser()
                self._collect_deep_network()
                self.after(0, self.apply_deep_filter)
            except Exception as e:
                log_exception('populate_deep_autoruns', e)
                self.after(0, lambda: self.deep_status.set(f'Error: {e}'))
        threading.Thread(target=worker, daemon=True).start()

    def apply_deep_filter(self):
        needle = self.deep_filter.get().strip().lower()
        total = shown = 0
        for cat, tree in self.deep_trees.items():
            tree.delete(*tree.get_children())
            for row, tag in self.deep_rows.get(cat, []):
                total += 1
                if needle and needle not in ' '.join(map(str, row)).lower():
                    continue
                shown += 1
                tree.insert('', 'end', values=row, tags=(tag,))
        self.deep_status.set(f'Showing {shown} of {total} autorun-related entries')

    def export_deep_autoruns(self):
        file_path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV files', '*.csv'), ('All files', '*.*')], title='Export Deep Autoruns')
        if not file_path:
            return
        try:
            with open(file_path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(['Category', 'Column1', 'Column2', 'Column3', 'Column4', 'Column5'])
                for cat, rows in self.deep_rows.items():
                    for row, _tag in rows:
                        writer.writerow([cat] + list(row))
            self.show_info(f'Exported to:\n{file_path}')
        except Exception as e:
            self.show_error(f'Export failed: {e}')


    def _active_deep_category(self):
        try:
            tab_id = self.deep_notebook.select()
            return self.deep_notebook.tab(tab_id, 'text')
        except Exception:
            return None

    def _get_selected_deep_entry(self):
        category = self._active_deep_category()
        if not category:
            return None, None, None, None
        tree = self.deep_trees.get(category)
        if not tree:
            return category, None, None, None
        item = tree.focus()
        if not item:
            sel = tree.selection()
            item = sel[0] if sel else ''
        if not item:
            return category, tree, None, None
        row = tuple(tree.item(item, 'values'))
        meta = self.deep_meta.get((category, row), {})
        return category, tree, row, meta

    def _deep_hive_from_meta(self, meta):
        hive_name = (meta or {}).get('hive_name')
        if hive_name == 'HKLM':
            return winreg.HKEY_LOCAL_MACHINE
        if hive_name == 'HKCU':
            return winreg.HKEY_CURRENT_USER
        return None

    def backup_deep_entry(self):
        category, tree, row, meta = self._get_selected_deep_entry()
        if not row:
            self.show_info('Select an entry first.')
            return
        try:
            path = export_json_artifact('deep_autoruns_entry', {
                'category': category,
                'row': row,
                'metadata': meta,
                'created_at': datetime.datetime.now().isoformat()
            })
            self.show_info(f'Entry backup saved:\n{path}')
        except Exception as e:
            self.show_error(f'Backup failed: {e}')

    def disable_deep_entry(self):
        category, tree, row, meta = self._get_selected_deep_entry()
        if not row:
            self.show_info('Select an entry first.')
            return
        if not messagebox.askyesno('Disable autorun entry', 'Disable selected autorun entry?\n\nA JSON backup will be created before changes.'):
            return
        self.backup_deep_entry()
        try:
            typ = meta.get('type')
            if typ == 'registry':
                hive = self._deep_hive_from_meta(meta)
                value_name = meta.get('value_name', '')
                if hive is None:
                    raise RuntimeError('Unsupported registry hive.')
                if value_name == '':
                    raise RuntimeError('Default registry values cannot be safely renamed. Use Edit or Delete instead.')
                disabled_name = f'WREART_Disabled_{value_name}_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}'
                with winreg.OpenKey(hive, meta['path'], 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
                    data, reg_type = winreg.QueryValueEx(key, value_name)
                    winreg.SetValueEx(key, disabled_name, 0, reg_type, data)
                    winreg.DeleteValue(key, value_name)
                self.show_info('Registry autorun value was disabled by renaming it.')
            elif typ == 'file':
                src = meta.get('path')
                if not src or not os.path.exists(src):
                    raise RuntimeError('Startup file not found.')
                dst = src + '.disabled'
                counter = 1
                while os.path.exists(dst):
                    dst = src + f'.disabled.{counter}'
                    counter += 1
                shutil.move(src, dst)
                self.show_info(f'Startup item disabled:\n{dst}')
            else:
                raise RuntimeError('This entry type cannot be disabled automatically. Use Edit/Delete where available.')
            self.populate_deep_autoruns()
        except Exception as e:
            log_exception('disable_deep_entry', e)
            self.show_error(f'Disable failed: {e}')

    def edit_deep_entry(self):
        category, tree, row, meta = self._get_selected_deep_entry()
        if not row:
            self.show_info('Select an entry first.')
            return
        try:
            if meta.get('type') != 'registry':
                self.show_info('Only registry-backed Deep Autoruns entries can be edited here.')
                return
            hive = self._deep_hive_from_meta(meta)
            if hive is None:
                raise RuntimeError('Unsupported registry hive.')
            value_name = meta.get('value_name', '')
            current = str(row[3]) if len(row) > 3 else ''
            new_value = simpledialog.askstring('Edit registry value', f'Value: {value_name or "(Default)"}\nKey: {meta.get("path")}\n\nNew data:', initialvalue=current, parent=self)
            if new_value is None:
                return
            self.backup_deep_entry()
            with winreg.OpenKey(hive, meta['path'], 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, new_value)
            self.show_info('Registry value updated.')
            self.populate_deep_autoruns()
        except Exception as e:
            log_exception('edit_deep_entry', e)
            self.show_error(f'Edit failed: {e}')

    def delete_deep_entry(self):
        category, tree, row, meta = self._get_selected_deep_entry()
        if not row:
            self.show_info('Select an entry first.')
            return
        if not messagebox.askyesno('Delete / quarantine entry', 'Delete selected entry?\n\nRegistry values are deleted after backup. Startup files are moved to quarantine, not permanently erased.'):
            return
        self.backup_deep_entry()
        try:
            typ = meta.get('type')
            if typ == 'registry':
                hive = self._deep_hive_from_meta(meta)
                if hive is None:
                    raise RuntimeError('Unsupported registry hive.')
                with winreg.OpenKey(hive, meta['path'], 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, meta.get('value_name', ''))
                self.show_info('Registry value deleted.')
            elif typ == 'file':
                src = meta.get('path')
                if not src or not os.path.exists(src):
                    raise RuntimeError('Startup file not found.')
                os.makedirs(QUARANTINE_DIR, exist_ok=True)
                dst = os.path.join(QUARANTINE_DIR, os.path.basename(src) + '_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
                shutil.move(src, dst)
                self.show_info(f'Startup file moved to quarantine:\n{dst}')
            elif typ == 'hosts':
                raise RuntimeError('Hosts file entries should be edited manually from the Hosts/DNS view.')
            else:
                raise RuntimeError('This entry type cannot be deleted by this editor.')
            self.populate_deep_autoruns()
        except Exception as e:
            log_exception('delete_deep_entry', e)
            self.show_error(f'Delete failed: {e}')

    def setup_fim_tab(self, parent):
        group = ttk.LabelFrame(parent, text='File Integrity Monitoring (Wazuh-style)')
        group.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        dir_frame = ttk.Frame(group)
        dir_frame.pack(fill=X, padx=10, pady=5)
        ttk.Label(dir_frame, text='Directory to monitor:').pack(side=LEFT)
        self.fim_dir_var = StringVar(value=os.path.join(self.system_drive, 'Windows', 'System32', 'drivers'))
        dir_entry = ttk.Entry(dir_frame, textvariable=self.fim_dir_var, width=60)
        dir_entry.pack(side=LEFT, padx=5)
        ttk.Button(dir_frame, text='Browse', command=lambda: self.fim_dir_var.set(filedialog.askdirectory(initialdir=self.fim_dir_var.get()))).pack(side=LEFT)
        
        btn_frame = ttk.Frame(group)
        btn_frame.pack(fill=X, padx=10, pady=5)
        ttk.Button(btn_frame, text='Take Snapshot', command=self.fim_take_snapshot_ui).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Compare with Last', command=self.fim_compare_snapshot_ui).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Save Snapshot', command=self.fim_save_snapshot_ui).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Load Snapshot', command=self.fim_load_snapshot_ui).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Export Changes', command=self.fim_export_changes).pack(side=LEFT, padx=2)
        
        columns = ('Status', 'File Path', 'Size (bytes)', 'Hash')
        self.fim_tree = ttk.Treeview(group, columns=columns, show='headings')
        for col in columns:
            self.fim_tree.heading(col, text=col)
            self.fim_tree.column(col, width=200 if col == 'File Path' else 150)
        self.fim_tree.column('File Path', width=500)
        self.fim_tree.tag_configure('added', foreground='green')
        self.fim_tree.tag_configure('removed', foreground='red')
        self.fim_tree.tag_configure('modified', foreground='orange')
        
        scroll = ttk.Scrollbar(group, orient=VERTICAL, command=self.fim_tree.yview)
        self.fim_tree.configure(yscrollcommand=scroll.set)
        self.fim_tree.pack(side=LEFT, fill=BOTH, expand=True, padx=10, pady=5)
        scroll.pack(side=RIGHT, fill=Y)
        
        self.fim_status = ttk.Label(group, text='Ready', font=('Segoe UI', 8))
        self.fim_status.pack(pady=5)
        
        self.current_fim_snapshot = {}
        self.last_fim_changes = None

    def fim_take_snapshot_ui(self):
        directory = self.fim_dir_var.get()
        if not os.path.exists(directory):
            self.fim_status.config(text=f'Directory not found: {directory}', foreground='red')
            return
        self.fim_status.config(text=f'Scanning {directory}...', foreground='blue')
        self.update()
        
        def scan_thread():
            snapshot = self.take_fim_snapshot(directory, recursive=True)
            self.current_fim_snapshot = snapshot
            self.after(0, lambda: self.fim_status.config(text=f'Snapshot taken: {len(snapshot)} files', foreground='green'))
            self.after(0, lambda: self.fim_display_snapshot_ui(snapshot))
        threading.Thread(target=scan_thread, daemon=True).start()

    def fim_display_snapshot_ui(self, snapshot):
        for item in self.fim_tree.get_children():
            self.fim_tree.delete(item)
        for path, info in list(snapshot.items())[:500]:
            self.fim_tree.insert('', 'end', values=('Current', info['path'], info['size'], info['hash'][:16] + '...' if info['hash'] else 'N/A'))

    def fim_compare_snapshot_ui(self):
        if not self.current_fim_snapshot:
            self.fim_status.config(text='No snapshot to compare. Take a snapshot first.', foreground='red')
            return
        directory = self.fim_dir_var.get()
        if not os.path.exists(directory):
            self.fim_status.config(text=f'Directory not found: {directory}', foreground='red')
            return
        self.fim_status.config(text=f'Comparing {directory}...', foreground='blue')
        self.update()
        
        def compare_thread():
            new_snapshot = self.take_fim_snapshot(directory, recursive=True)
            changes = self.compare_fim_snapshots(self.current_fim_snapshot, new_snapshot)
            self.last_fim_changes = changes
            self.after(0, lambda: self.fim_display_changes_ui(changes))
            self.after(0, lambda: self.fim_status.config(text=f"Changes: +{len(changes['added'])} -{len(changes['removed'])} *{len(changes['modified'])}", foreground='blue'))
        threading.Thread(target=compare_thread, daemon=True).start()

    def fim_display_changes_ui(self, changes):
        for item in self.fim_tree.get_children():
            self.fim_tree.delete(item)
        for info in changes['added']:
            self.fim_tree.insert('', 'end', values=('ADDED', info['path'], info['size'], info['hash'][:16] + '...' if info['hash'] else 'N/A'), tags=('added',))
        for info in changes['removed']:
            self.fim_tree.insert('', 'end', values=('REMOVED', info['path'], info['size'], info['hash'][:16] + '...' if info['hash'] else 'N/A'), tags=('removed',))
        for mod in changes['modified']:
            self.fim_tree.insert('', 'end', values=('MODIFIED', mod['path'], f"{mod['old_size']} -> {mod['new_size']}", f"{mod['old_hash'][:16] if mod['old_hash'] else 'N/A'}... -> {mod['new_hash'][:16] if mod['new_hash'] else 'N/A'}..."), tags=('modified',))

    def fim_save_snapshot_ui(self):
        if not self.current_fim_snapshot:
            self.fim_status.config(text='No snapshot to save', foreground='red')
            return
        filepath = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON files', '*.json')])
        if filepath:
            try:
                serializable = {}
                for path, info in self.current_fim_snapshot.items():
                    serializable[path] = {
                        'hash': info['hash'],
                        'size': info['size'],
                        'mtime': info['mtime'],
                        'path': info['path']
                    }
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(serializable, f, indent=2)
                self.fim_status.config(text=f'Saved to {filepath}', foreground='green')
            except Exception as e:
                self.fim_status.config(text=f'Error: {e}', foreground='red')

    def fim_load_snapshot_ui(self):
        filepath = filedialog.askopenfilename(filetypes=[('JSON files', '*.json')])
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.current_fim_snapshot = {}
                for path, info in data.items():
                    self.current_fim_snapshot[path] = {
                        'hash': info['hash'],
                        'size': info['size'],
                        'mtime': info['mtime'],
                        'path': info['path']
                    }
                self.fim_status.config(text=f'Loaded {len(self.current_fim_snapshot)} files from {filepath}', foreground='green')
                self.fim_display_snapshot_ui(self.current_fim_snapshot)
            except Exception as e:
                self.fim_status.config(text=f'Error loading: {e}', foreground='red')

    def fim_export_changes(self):
        if not self.last_fim_changes:
            self.fim_status.config(text='No comparison results to export. Run Compare first.', foreground='red')
            return
        filepath = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV files', '*.csv')])
        if filepath:
            try:
                with open(filepath, 'w', encoding='utf-8-sig') as f:
                    f.write('Status,Path,Old Size,New Size,Old Hash,New Hash\n')
                    for info in self.last_fim_changes['added']:
                        f.write(f"ADDED,{info['path']},{info['size']},,{info['hash']},\n")
                    for info in self.last_fim_changes['removed']:
                        f.write(f"REMOVED,{info['path']},,{info['size']},,{info['hash']}\n")
                    for mod in self.last_fim_changes['modified']:
                        f.write(f"MODIFIED,{mod['path']},{mod['old_size']},{mod['new_size']},{mod['old_hash']},{mod['new_hash']}\n")
                self.fim_status.config(text=f'Exported to {filepath}', foreground='green')
            except Exception as e:
                self.fim_status.config(text=f'Export error: {e}', foreground='red')

    def setup_autostart_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=X, pady=5)
        ttk.Button(top_frame, text='Refresh all', command=self.populate_all_autostart).pack(side=LEFT, padx=2)
        ttk.Button(top_frame, text='Disable selected', command=self.disable_autostart_item).pack(side=LEFT, padx=2)
        ttk.Button(top_frame, text='Enable selected', command=self.enable_autostart_item).pack(side=LEFT, padx=2)
        ttk.Button(top_frame, text='Delete permanently', command=self.delete_autostart_item).pack(side=LEFT, padx=2)
        ttk.Button(top_frame, text='Export list', command=self.export_autostart).pack(side=LEFT, padx=2)
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=BOTH, expand=True)
        columns = ('Type', 'Name', 'Path/Command', 'Status', 'Location')
        self.autostart_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', selectmode='extended')
        for col in columns:
            self.autostart_tree.heading(col, text=col, command=lambda c=col: self.sort_autostart_by_column(c))
            self.autostart_tree.column(col, width=120 if col == 'Type' else 200)
        self.autostart_tree.tag_configure('risk', foreground='red')
        scrollbar = ttk.Scrollbar(tree_frame, orient=VERTICAL, command=self.autostart_tree.yview)
        self.autostart_tree.configure(yscrollcommand=scrollbar.set)
        self.autostart_tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.autostart_menu = Menu(self, tearoff=0)
        self.autostart_menu.add_command(label='Disable', command=self.disable_autostart_item)
        self.autostart_menu.add_command(label='Enable', command=self.enable_autostart_item)
        self.autostart_menu.add_separator()
        self.autostart_menu.add_command(label='Delete', command=self.delete_autostart_item)
        self.autostart_menu.add_command(label='Copy path', command=self.copy_autostart_path)
        self.autostart_tree.bind('<Button-3>', self.show_autostart_menu)

    def sort_autostart_by_column(self, col):
        col_index = {'Type':0, 'Name':1, 'Path/Command':2, 'Status':3, 'Location':4}[col]
        items = [(self.autostart_tree.set(k, col), k) for k in self.autostart_tree.get_children('')]
        items.sort(key=lambda x: x[0].lower())
        for index, (_, k) in enumerate(items):
            self.autostart_tree.move(k, '', index)

    def show_autostart_menu(self, event):
        item = self.autostart_tree.identify_row(event.y)
        if item:
            self.autostart_tree.selection_set(item)
            self.autostart_menu.post(event.x_root, event.y_root)

    def copy_autostart_path(self):
        sel = self.autostart_tree.focus()
        if sel:
            vals = self.autostart_tree.item(sel, 'values')
            if len(vals) > 2:
                self.clipboard_clear()
                self.clipboard_append(vals[2])
                self.update_status('Path copied to clipboard')

    def export_autostart(self):
        file_path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV files', '*.csv'), ('Text files', '*.txt')], title='Export autostart list')
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('Type;Name;Path;Status;Location\n')
                    for item in self.autostart_tree.get_children():
                        values = self.autostart_tree.item(item, 'values')
                        f.write(';'.join(values) + '\n')
                self.show_info(f'Autostart list exported to {file_path}')
            except Exception as e:
                self.show_error(f'Export error: {e}')

    def populate_all_autostart(self):
        self.autostart_tree.delete(*self.autostart_tree.get_children())
        progress = ProgressDialog(self, 'Scanning autostart...')
        def scan_thread():
            try:
                locations = [
                    (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'), 'HKLM Run'),
                    (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'), 'HKLM RunOnce'),
                    (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'), 'HKLM Policies Run'),
                    (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'), 'HKLM WOW6432 Run'),
                ]
                if not self.repair_mode:
                    locations.extend([
                        (winreg.HKEY_CURRENT_USER, 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKCU Run'),
                        (winreg.HKEY_CURRENT_USER, 'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce', 'HKCU RunOnce'),
                        (winreg.HKEY_CURRENT_USER, 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run', 'HKCU Policies Run')
                    ])
                winlogon_path = self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
                important_keys = ['Shell', 'Userinit', 'VmApplet', 'Taskman', 'System']
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, winlogon_path) as wl_key:
                        for key_name in important_keys:
                            try:
                                value, _ = winreg.QueryValueEx(wl_key, key_name)
                                tags = ('risk',) if self.is_path_suspicious(value) else ()
                                self.autostart_tree.insert('', 'end', values=('Winlogon', key_name, value, 'Active', winlogon_path), tags=tags)
                            except FileNotFoundError:
                                pass
                except:
                    pass
                for hive, path, desc in locations:
                    try:
                        with winreg.OpenKey(hive, path) as key:
                            i = 0
                            while True:
                                try:
                                    name, value, _ = winreg.EnumValue(key, i)
                                    tags = ('risk',) if self.is_path_suspicious(value) else ()
                                    self.autostart_tree.insert('', 'end', values=(desc, name, value, 'Active', path), tags=tags)
                                    i += 1
                                except OSError:
                                    break
                    except FileNotFoundError:
                        pass
                    except:
                        pass
                self.scan_startup_folders()
                self.after(0, progress.close)
                self.after(0, lambda: self.update_status('Autostart updated'))
            except Exception as e:
                self.after(0, progress.close)
                self.after(0, lambda: self.show_error(f'Autostart scan error: {e}'))
        threading.Thread(target=scan_thread, daemon=True).start()

    def scan_startup_folders(self):
        startup_folders = [
            (os.path.join(self.system_drive, 'ProgramData', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'), 'Startup All Users'),
            (os.path.join(self.system_drive, 'Users', 'Default', 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'), 'Startup Default User')
        ]
        if not self.repair_mode:
            userprofile = os.environ.get('USERPROFILE', '')
            if userprofile:
                startup_folders.append((os.path.join(userprofile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'), 'Startup Current User'))
        for folder_path, desc in startup_folders:
            if os.path.exists(folder_path):
                try:
                    for file in os.listdir(folder_path):
                        full_path = os.path.join(folder_path, file)
                        if os.path.isfile(full_path):
                            tags = ('risk',) if self.is_path_suspicious(full_path) else ()
                            self.autostart_tree.insert('', 'end', values=('Startup Folder', file, full_path, 'Active', desc), tags=tags)
                except:
                    pass

    def disable_autostart_item(self):
        sel = self.autostart_tree.selection()
        if not sel:
            self.show_info('No item selected.')
            return
        for item in sel:
            vals = list(self.autostart_tree.item(item, 'values'))
            vals[3] = 'Disabled (local)'
            self.autostart_tree.item(item, values=vals)

    def enable_autostart_item(self):
        sel = self.autostart_tree.selection()
        if not sel:
            self.show_info('No item selected.')
            return
        for item in sel:
            vals = list(self.autostart_tree.item(item, 'values'))
            vals[3] = 'Active'
            self.autostart_tree.item(item, values=vals)

    def delete_autostart_item(self):
        sel = self.autostart_tree.selection()
        if not sel:
            self.show_info('No item selected.')
            return
        if messagebox.askyesno('Confirm', f'Delete {len(sel)} selected entries?'):
            for item in sel:
                self.autostart_tree.delete(item)

    def setup_advanced_autostart_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=X, pady=5)
        ttk.Button(btn_frame, text='Refresh', command=self.populate_advanced_autostart).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Delete selected', command=self.delete_advanced_autostart_item).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Edit value', command=self.edit_advanced_autostart_item).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Export CSV', command=self.export_advanced_autostart).pack(side=LEFT, padx=2)
        columns = ('Section', 'Parameter', 'Value', 'Type')
        self.adv_autostart_tree = ttk.Treeview(main_frame, columns=columns, show='headings', selectmode='browse')
        for col in columns:
            self.adv_autostart_tree.heading(col, text=col, command=lambda c=col: self._sort_treeview_column(self.adv_autostart_tree, c, False))
        self.adv_autostart_tree.column('Section', width=250)
        self.adv_autostart_tree.column('Parameter', width=200)
        self.adv_autostart_tree.column('Value', width=500)
        self.adv_autostart_tree.column('Type', width=80)
        self.adv_autostart_tree.tag_configure('risk', foreground='#b45309')
        scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=self.adv_autostart_tree.yview)
        self.adv_autostart_tree.configure(yscrollcommand=scrollbar.set)
        self.adv_autostart_tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.adv_menu = Menu(self, tearoff=0)
        self.adv_menu.add_command(label='Delete', command=self.delete_advanced_autostart_item)
        self.adv_menu.add_command(label='Edit', command=self.edit_advanced_autostart_item)
        self.adv_menu.add_command(label='Copy value', command=self.copy_advanced_value)
        self.adv_autostart_tree.bind('<Button-3>', self.show_adv_autostart_menu)
        self.adv_status = StringVar()
        status_label = Label(main_frame, textvariable=self.adv_status, anchor=W, font=('Segoe UI', 8))
        status_label.pack(fill=X)

    def show_adv_autostart_menu(self, event):
        item = self.adv_autostart_tree.identify_row(event.y)
        if item:
            self.adv_autostart_tree.selection_set(item)
            self.adv_menu.post(event.x_root, event.y_root)

    def copy_advanced_value(self):
        sel = self.adv_autostart_tree.focus()
        if sel:
            vals = self.adv_autostart_tree.item(sel, 'values')
            if len(vals) >= 3:
                self.clipboard_clear()
                self.clipboard_append(vals[2])
                self.adv_status.set('Value copied to clipboard')
                self.after(2000, lambda: self.adv_status.set(''))

    def populate_advanced_autostart(self):
        self.adv_autostart_tree.delete(*self.adv_autostart_tree.get_children())
        self.adv_status.set('Collecting focused advanced autostart values...')
        items = [
            ('Setup', winreg.HKEY_LOCAL_MACHINE, self.get_registry_path(r'SYSTEM\Setup'), ['CmdLine', 'SetupType', 'SystemPartition']),
            ('Boot Execute', winreg.HKEY_LOCAL_MACHINE, self.get_registry_path(r'SYSTEM\CurrentControlSet\Control\Session Manager'), ['BootExecute']),
            ('AppInit DLLs', winreg.HKEY_LOCAL_MACHINE, self.get_registry_path(r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'), ['AppInit_DLLs', 'LoadAppInit_DLLs', 'RequireSignedAppInit_DLLs']),
            ('AppInit DLLs WOW64', winreg.HKEY_LOCAL_MACHINE, self.get_registry_path(r'SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows'), ['AppInit_DLLs', 'LoadAppInit_DLLs', 'RequireSignedAppInit_DLLs']),
            ('Winlogon', winreg.HKEY_LOCAL_MACHINE, self.get_registry_path(r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'), ['Shell', 'Userinit', 'TaskMan', 'System', 'VmApplet']),
            ('Image Load', winreg.HKEY_LOCAL_MACHINE, self.get_registry_path(r'SYSTEM\CurrentControlSet\Control\Session Manager'), ['AppCertDlls']),
        ]
        count = 0
        for section, hive, subkey, names in items:
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    for value_name in names:
                        try:
                            val, typ = winreg.QueryValueEx(key, value_name)
                            val_str = str(val)
                            if len(val_str) > 300:
                                val_str = val_str[:300] + '...'
                            status = self._registry_value_status(val_str)
                            tags = ('risk',) if status == 'File missing' or self.is_path_suspicious(val_str) else ()
                            self.adv_autostart_tree.insert('', 'end', values=(section, value_name, val_str, self._reg_type_to_str(typ)), tags=tags)
                            count += 1
                        except FileNotFoundError:
                            continue
            except FileNotFoundError:
                continue
            except Exception as e:
                logging.info('Advanced autostart read failed %s: %s', section, e)
        for hive, hive_name, base in [
            (winreg.HKEY_LOCAL_MACHINE, 'HKLM', self.get_registry_path(r'SOFTWARE\Microsoft\Active Setup\Installed Components')),
            (winreg.HKEY_CURRENT_USER, 'HKCU', r'Software\Microsoft\Active Setup\Installed Components'),
        ]:
            if self.repair_mode and hive_name == 'HKCU':
                continue
            try:
                with winreg.OpenKey(hive, base) as key:
                    i = 0
                    while True:
                        try:
                            comp = winreg.EnumKey(key, i)
                            with winreg.OpenKey(hive, base + '\\' + comp) as sk:
                                for value_name in ('StubPath', 'IsInstalled'):
                                    try:
                                        val, typ = winreg.QueryValueEx(sk, value_name)
                                        val_str = str(val)
                                        tags = ('risk',) if self.is_path_suspicious(val_str) else ()
                                        self.adv_autostart_tree.insert('', 'end', values=(f'Active Setup ({hive_name})', f'{comp}::{value_name}', val_str, self._reg_type_to_str(typ)), tags=tags)
                                        count += 1
                                    except FileNotFoundError:
                                        pass
                            i += 1
                        except OSError:
                            break
            except FileNotFoundError:
                pass
            except Exception as e:
                logging.info('Active Setup read failed: %s', e)
        self.adv_status.set(f'Loaded focused entries: {count}')

    def _reg_type_to_str(self, typ):
        types = {
            winreg.REG_SZ: 'SZ',
            winreg.REG_EXPAND_SZ: 'EXPAND_SZ',
            winreg.REG_BINARY: 'BINARY',
            winreg.REG_DWORD: 'DWORD',
            winreg.REG_MULTI_SZ: 'MULTI_SZ',
            winreg.REG_QWORD: 'QWORD'
        }
        return types.get(typ, str(typ))

    def delete_advanced_autostart_item(self):
        sel = self.adv_autostart_tree.focus()
        if not sel:
            self.show_info('Nothing selected')
            return
        vals = self.adv_autostart_tree.item(sel, 'values')
        section, param, value, typ = vals
        if not messagebox.askyesno('Delete', f'Delete parameter "{param}" from section "{section}"?'):
            return
        hive = winreg.HKEY_LOCAL_MACHINE
        subkey = ''
        if section == 'Setup Parameters':
            subkey = self.get_registry_path('SYSTEM\\Setup')
        elif section == 'Session Manager':
            subkey = self.get_registry_path('SYSTEM\\CurrentControlSet\\Control\\Session Manager')
        elif section == 'AppInit':
            subkey = self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows')
        elif section.startswith('Active Setup'):
            if section == 'Active Setup (HKLM)':
                hive = winreg.HKEY_LOCAL_MACHINE
                subkey = self.get_registry_path('SOFTWARE\\Microsoft\\Active Setup\\Installed Components')
            else:
                hive = winreg.HKEY_CURRENT_USER
                subkey = 'Software\\Microsoft\\Active Setup\\Installed Components'
        elif section.startswith('RunServices'):
            hive = winreg.HKEY_LOCAL_MACHINE
            subkey = self.get_registry_path('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices')
            if 'Once' in section:
                subkey = self.get_registry_path('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce')
        elif section == 'KnownDLLs':
            subkey = self.get_registry_path('SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs')
        elif section == 'Winlogon Notify':
            subkey = self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify')
        else:
            if param == 'CmdLine (Setup)' or param == 'SetupType' or param == 'SystemPartition':
                subkey = self.get_registry_path('SYSTEM\\Setup')
                param = param.split()[0]
            elif param == 'BootExecute':
                subkey = self.get_registry_path('SYSTEM\\CurrentControlSet\\Control\\Session Manager')
            elif param in ('AppInit_DLLs', 'LoadAppInit_DLLs', 'RequireSignedAppInit_DLLs'):
                subkey = self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows')
            else:
                self.show_error('Cannot determine registry path for deletion')
                return
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, param)
            self.show_info(f'Parameter "{param}" deleted')
            self.populate_advanced_autostart()
        except Exception as e:
            self.show_error(f'Delete error: {e}')

    def edit_advanced_autostart_item(self):
        sel = self.adv_autostart_tree.focus()
        if not sel:
            self.show_info('Nothing selected')
            return
        vals = self.adv_autostart_tree.item(sel, 'values')
        section, param, value, typ = vals
        new_value = simpledialog.askstring('Edit value', f'New value for "{param}":', initialvalue=value)
        if new_value is None:
            return
        hive = winreg.HKEY_LOCAL_MACHINE
        subkey = ''
        reg_type = winreg.REG_SZ
        if typ == 'DWORD':
            reg_type = winreg.REG_DWORD
            try:
                new_value = int(new_value)
            except:
                self.show_error('DWORD requires an integer')
                return
        elif typ == 'QWORD':
            reg_type = winreg.REG_QWORD
            try:
                new_value = int(new_value)
            except:
                self.show_error('QWORD requires an integer')
                return
        elif typ == 'EXPAND_SZ':
            reg_type = winreg.REG_EXPAND_SZ
        if section == 'Setup Parameters':
            subkey = self.get_registry_path('SYSTEM\\Setup')
        elif section == 'Session Manager':
            subkey = self.get_registry_path('SYSTEM\\CurrentControlSet\\Control\\Session Manager')
        elif section == 'AppInit':
            subkey = self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows')
        elif section.startswith('Active Setup'):
            if section == 'Active Setup (HKLM)':
                hive = winreg.HKEY_LOCAL_MACHINE
                subkey = self.get_registry_path('SOFTWARE\\Microsoft\\Active Setup\\Installed Components')
            else:
                hive = winreg.HKEY_CURRENT_USER
                subkey = 'Software\\Microsoft\\Active Setup\\Installed Components'
        elif section.startswith('RunServices'):
            hive = winreg.HKEY_LOCAL_MACHINE
            subkey = self.get_registry_path('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices')
            if 'Once' in section:
                subkey = self.get_registry_path('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce')
        elif section == 'KnownDLLs':
            subkey = self.get_registry_path('SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs')
        elif section == 'Winlogon Notify':
            subkey = self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify')
        else:
            if param == 'CmdLine (Setup)' or param == 'SetupType' or param == 'SystemPartition':
                subkey = self.get_registry_path('SYSTEM\\Setup')
                param = param.split()[0]
            elif param == 'BootExecute':
                subkey = self.get_registry_path('SYSTEM\\CurrentControlSet\\Control\\Session Manager')
            elif param in ('AppInit_DLLs', 'LoadAppInit_DLLs', 'RequireSignedAppInit_DLLs'):
                subkey = self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows')
            else:
                self.show_error('Cannot determine registry path')
                return
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, param, 0, reg_type, new_value)
            self.show_info(f'Parameter "{param}" changed')
            self.populate_advanced_autostart()
        except Exception as e:
            self.show_error(f'Edit error: {e}')

    def export_advanced_autostart(self):
        file_path = filedialog.asksaveasfilename(defaultextension='.csv',
                                                 filetypes=[('CSV files', '*.csv')],
                                                 title='Export advanced autostart')
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8-sig') as f:
                    f.write('Section;Parameter;Value;Type\n')
                    for item in self.adv_autostart_tree.get_children():
                        vals = self.adv_autostart_tree.item(item, 'values')
                        f.write(';'.join(vals) + '\n')
                self.show_info(f'Export completed: {file_path}')
            except Exception as e:
                self.show_error(f'Export error: {e}')

    def setup_ifeo_tab(self, parent):
        group = ttk.LabelFrame(parent, text='Image File Execution Options (IFEO)')
        group.pack(fill=BOTH, expand=True, padx=5, pady=5)
        columns = ('Executable', 'Debugger', 'Status')
        self.ifeo_tree = ttk.Treeview(group, columns=columns, show='headings', selectmode='extended')
        for col in columns:
            self.ifeo_tree.heading(col, text=col)
        self.ifeo_tree.column('Executable', width=300)
        self.ifeo_tree.column('Debugger', width=400)
        scrollbar = ttk.Scrollbar(group, orient=VERTICAL, command=self.ifeo_tree.yview)
        self.ifeo_tree.configure(yscrollcommand=scrollbar.set)
        self.ifeo_tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)
        btn_frame = ttk.Frame(group)
        btn_frame.pack(fill=X, pady=5)
        ttk.Button(btn_frame, text='Refresh', command=self.populate_ifeo).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Delete selected', command=self.delete_ifeo_items).pack(side=LEFT, padx=2)

    def populate_ifeo(self):
        self.ifeo_tree.delete(*self.ifeo_tree.get_children())
        path = self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options')
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        try:
                            with winreg.OpenKey(key, subkey_name) as sub:
                                try:
                                    debugger, _ = winreg.QueryValueEx(sub, 'Debugger')
                                    self.ifeo_tree.insert('', 'end', values=(subkey_name, debugger, 'Active'))
                                except FileNotFoundError:
                                    pass
                        except:
                            pass
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except Exception as e:
            self.show_error(f'Error reading IFEO: {e}')

    def delete_ifeo_items(self):
        sel = self.ifeo_tree.selection()
        if not sel:
            self.show_info('No item selected.')
            return
        if not messagebox.askyesno('Confirm', f'Delete {len(sel)} IFEO entries?'):
            return
        path = self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options')
        for item in sel:
            vals = self.ifeo_tree.item(item, 'values')
            exe_name = vals[0]
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteKey(key, exe_name)
                self.ifeo_tree.delete(item)
            except Exception as e:
                self.show_error(f'Error deleting {exe_name}: {e}')
        self.show_info('Selected entries deleted')

    def setup_gp_tab(self, parent):
        group = ttk.LabelFrame(parent, text='System Policies')
        group.pack(fill=BOTH, expand=True, padx=5, pady=5)
        columns = ('Policy', 'Key', 'Current Value', 'Recommended')
        self.gp_tree = ttk.Treeview(group, columns=columns, show='headings', selectmode='browse')
        for col in columns:
            self.gp_tree.heading(col, text=col)
        self.gp_tree.pack(fill=BOTH, expand=True)
        self.policies = [
            ('Disable Task Manager', 'DisableTaskMgr', '?', 0),
            ('Disable Registry Tools', 'DisableRegistryTools', '?', 0),
            ('Disable Command Prompt', 'DisableCMD', '?', 0),
            ('Disable UAC', 'EnableLUA', '?', 1),
            ('Hide Control Panel', 'NoControlPanel', '?', 0),
            ('Disable Run command', 'NoRun', '?', 0),
            ('Disable Find', 'NoFind', '?', 0),
            ('Disable Shutdown', 'NoClose', '?', 0),
            ('Hide Folder Options', 'NoFolderOptions', '?', 0),
            ('Hide Desktop Context Menu', 'NoViewContextMenu', '?', 0),
            ('Hide Taskbar Context Menu', 'NoTrayContextMenu', '?', 0),
            ('Disable Password Change', 'DisableChangePassword', '?', 0),
            ('Hide Screen Saver tab', 'NoDispScrSavPage', '?', 0),
            ('Hide Background tab', 'NoDispBackgroundPage', '?', 0),
            ('Hide Appearance tab', 'NoDispAppearancePage', '?', 0),
            ('Hide Settings tab', 'NoDispSettingsPage', '?', 0),
            ('Disable Active Desktop', 'NoActiveDesktop', '?', 0),
            ('Disable Active Desktop changes', 'NoActiveDesktopChanges', '?', 0),
            ('Hide Themes tab', 'NoThemesTab', '?', 0),
            ('Hide Desktop', 'NoDesktop', '?', 0),
            ('Disable Settings folders', 'NoSetFolders', '?', 0),
        ]
        for p in self.policies:
            self.gp_tree.insert('', 'end', values=p)
        btns = ttk.Frame(group)
        btns.pack(fill=X)
        ttk.Button(btns, text='Refresh', command=self.update_gp_values).pack(side=LEFT, padx=2)
        ttk.Button(btns, text='Reset values', command=self.reset_gp_values).pack(side=LEFT, padx=2)

    def update_gp_values(self):
        for item in self.gp_tree.get_children():
            vals = list(self.gp_tree.item(item, 'values'))
            k = vals[1]
            try:
                path = self.get_registry_path('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                    try:
                        v, _ = winreg.QueryValueEx(key, k)
                        vals[2] = v
                    except FileNotFoundError:
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer')) as exp_key:
                                v, _ = winreg.QueryValueEx(exp_key, k)
                                vals[2] = v
                        except FileNotFoundError:
                            if not self.repair_mode:
                                try:
                                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') as key_user:
                                        v, _ = winreg.QueryValueEx(key_user, k)
                                        vals[2] = v
                                except FileNotFoundError:
                                    vals[2] = 'Not set'
                            else:
                                vals[2] = 'Not set'
            except Exception as e:
                vals[2] = f'Error: {e}'
            self.gp_tree.item(item, values=vals)

    def reset_gp_values(self):
        try:
            for path in POLICY_PATHS:
                reg_path = self.get_registry_path(path)
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                    for policy in self.policies:
                        try:
                            winreg.DeleteValue(key, policy[1])
                        except FileNotFoundError:
                            pass
            if not self.repair_mode:
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 0, winreg.KEY_SET_VALUE) as key_user:
                        for policy in self.policies:
                            try:
                                winreg.DeleteValue(key_user, policy[1])
                            except FileNotFoundError:
                                pass
                except:
                    pass
            self.update_gp_values()
            self.show_info('Policies reset to defaults')
        except Exception as e:
            self.show_error(f'Error resetting policies: {e}')

    def setup_shell_tab(self, parent):
        group = ttk.LabelFrame(parent, text='Critical Boot Parameters')
        group.pack(fill=BOTH, expand=True, padx=5, pady=5)
        shell_group = ttk.LabelFrame(group, text='Shell')
        shell_group.pack(side=LEFT, fill=BOTH, expand=True, padx=5)
        self.shell_label = ttk.Label(shell_group, text='Current value: ')
        self.shell_label.pack(anchor=W)
        self.shell_edit = ttk.Entry(shell_group)
        self.shell_edit.pack(fill=X, padx=5, pady=2)
        ttk.Button(shell_group, text='Save Shell', command=self.save_shell).pack(fill=X, padx=5, pady=2)
        userinit_group = ttk.LabelFrame(group, text='Userinit')
        userinit_group.pack(side=LEFT, fill=BOTH, expand=True, padx=5)
        self.userinit_label = ttk.Label(userinit_group, text='Current value: ')
        self.userinit_label.pack(anchor=W)
        self.userinit_edit = ttk.Entry(userinit_group)
        self.userinit_edit.pack(fill=X, padx=5, pady=2)
        ttk.Button(userinit_group, text='Save Userinit', command=self.save_userinit).pack(fill=X, padx=5, pady=2)
        winlogon_group = ttk.LabelFrame(group, text='Winlogon')
        winlogon_group.pack(fill=BOTH, expand=True, padx=5, pady=5)
        columns = ('Parameter', 'Value')
        self.winlogon_tree = ttk.Treeview(winlogon_group, columns=columns, show='headings')
        for col in columns:
            self.winlogon_tree.heading(col, text=col)
        self.winlogon_tree.pack(fill=BOTH, expand=True)
        btn_frame = ttk.Frame(group)
        btn_frame.pack(fill=X)
        ttk.Button(btn_frame, text='Refresh', command=self.populate_winlogon).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Save changes', command=self.save_winlogon).pack(side=LEFT, padx=2)
        self.update_shell_values()
        self.populate_winlogon()

    def update_shell_values(self):
        path = self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                try:
                    shell, _ = winreg.QueryValueEx(key, 'Shell')
                except:
                    shell = 'explorer.exe'
                try:
                    userinit, _ = winreg.QueryValueEx(key, 'Userinit')
                except:
                    userinit = 'userinit.exe'
                self.shell_label.config(text=f'Current value: {shell}')
                self.shell_edit.delete(0, END)
                self.shell_edit.insert(0, shell)
                self.userinit_label.config(text=f'Current value: {userinit}')
                self.userinit_edit.delete(0, END)
                self.userinit_edit.insert(0, userinit)
        except Exception as e:
            self.shell_label.config(text=f'Registry access error: {e}')
            self.userinit_label.config(text=f'Registry access error: {e}')

    def save_shell(self):
        new_shell = self.shell_edit.get().strip()
        if not new_shell:
            self.show_error('Enter value for Shell')
            return
        try:
            path = self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, 'Shell', 0, winreg.REG_SZ, new_shell)
            self.show_info('Shell updated.')
            self.update_shell_values()
        except Exception as e:
            self.show_error(f'Failed to write Shell: {e}')

    def save_userinit(self):
        new_userinit = self.userinit_edit.get().strip()
        if not new_userinit:
            self.show_error('Enter value for Userinit')
            return
        try:
            path = self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, 'Userinit', 0, winreg.REG_SZ, new_userinit)
            self.show_info('Userinit updated.')
            self.update_shell_values()
        except Exception as e:
            self.show_error(f'Failed to write Userinit: {e}')

    def populate_winlogon(self):
        self.winlogon_tree.delete(*self.winlogon_tree.get_children())
        path = self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        self.winlogon_tree.insert('', 'end', values=(name, str(value)))
                        i += 1
                    except OSError:
                        break
        except Exception as e:
            self.show_error(f'Error reading Winlogon: {e}')

    def save_winlogon(self):
        try:
            path = self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
                for item in self.winlogon_tree.get_children():
                    name, value = self.winlogon_tree.item(item, 'values')
                    try:
                        v = int(value)
                        reg_type = winreg.REG_DWORD
                    except:
                        v = value
                        reg_type = winreg.REG_SZ
                    winreg.SetValueEx(key, name, 0, reg_type, v)
            self.show_info('Winlogon parameters updated')
            self.populate_winlogon()
        except Exception as e:
            self.show_error(f'Error saving Winlogon: {e}')

    def setup_services_tab(self, parent):
        group = ttk.LabelFrame(parent, text='Services')
        group.pack(fill=BOTH, expand=True, padx=5, pady=5)
        filter_frame = ttk.Frame(group)
        filter_frame.pack(fill=X, pady=5)
        ttk.Label(filter_frame, text='Filter by name:').pack(side=LEFT)
        self.service_filter = ttk.Entry(filter_frame)
        self.service_filter.pack(side=LEFT, padx=2, expand=True, fill=X)
        self.service_filter.bind('<KeyRelease>', lambda e: self.populate_services())
        ttk.Label(filter_frame, text='State:').pack(side=LEFT, padx=(10,2))
        self.service_state_filter = ttk.Combobox(filter_frame, values=['All', 'Running', 'Stopped'], state='readonly')
        self.service_state_filter.current(0)
        self.service_state_filter.pack(side=LEFT, padx=2)
        self.service_state_filter.bind('<<ComboboxSelected>>', lambda e: self.populate_services())
        ttk.Label(filter_frame, text='Start type:').pack(side=LEFT, padx=(10,2))
        self.service_start_filter = ttk.Combobox(filter_frame, values=['All', 'Auto', 'Manual', 'Disabled', 'Boot', 'System'], state='readonly')
        self.service_start_filter.current(0)
        self.service_start_filter.pack(side=LEFT, padx=2)
        self.service_start_filter.bind('<<ComboboxSelected>>', lambda e: self.populate_services())
        columns = ('Service', 'State', 'Start Type', 'Path', 'Description')
        self.services_tree = ttk.Treeview(group, columns=columns, show='headings')
        for col in columns:
            self.services_tree.heading(col, text=col)
            self.services_tree.column(col, width=100)
        self.services_tree.column('Service', width=200)
        self.services_tree.column('Path', width=350)
        self.services_tree.column('Description', width=250)
        scrollbar = ttk.Scrollbar(group, orient=VERTICAL, command=self.services_tree.yview)
        self.services_tree.configure(yscroll=scrollbar.set)
        self.services_tree.pack(side=TOP, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)
        btn_frame = ttk.Frame(group)
        btn_frame.pack(fill=X, pady=5)
        ttk.Button(btn_frame, text='Refresh', command=self.populate_services).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Start', command=lambda: self.manage_service('start')).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Stop', command=lambda: self.manage_service('stop')).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Delete', command=lambda: self.manage_service('delete')).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Export', command=self.export_services).pack(side=LEFT, padx=2)
        change_frame = ttk.Frame(group)
        change_frame.pack(fill=X, pady=5)
        ttk.Label(change_frame, text='New start type:').pack(side=LEFT)
        self.service_new_start = ttk.Combobox(change_frame, values=['Auto', 'Manual', 'Disabled'], state='readonly')
        self.service_new_start.pack(side=LEFT, padx=2)
        ttk.Button(change_frame, text='Apply', command=self.change_service_start_type).pack(side=LEFT, padx=2)
        self.services_menu = Menu(self, tearoff=0)
        self.services_menu.add_command(label='Start', command=lambda: self.manage_service('start'))
        self.services_menu.add_command(label='Stop', command=lambda: self.manage_service('stop'))
        self.services_menu.add_separator()
        self.services_menu.add_command(label='Delete', command=lambda: self.manage_service('delete'))
        self.services_menu.add_command(label='Copy name', command=self.copy_service_name)
        self.services_tree.bind('<Button-3>', self.show_services_menu)

    def show_services_menu(self, event):
        item = self.services_tree.identify_row(event.y)
        if item:
            self.services_tree.selection_set(item)
            self.services_menu.post(event.x_root, event.y_root)

    def copy_service_name(self):
        sel = self.services_tree.focus()
        if sel:
            vals = self.services_tree.item(sel, 'values')
            if vals:
                self.clipboard_clear()
                self.clipboard_append(vals[0])
                self.update_status('Service name copied')

    def export_services(self):
        file_path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV files', '*.csv'), ('Text files', '*.txt')], title='Export services list')
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('Service;State;Start Type;Path;Description\n')
                    for item in self.services_tree.get_children():
                        values = self.services_tree.item(item, 'values')
                        f.write(';'.join(values) + '\n')
                self.show_info(f'Services list exported to {file_path}')
            except Exception as e:
                self.show_error(f'Export error: {e}')

    def populate_services(self):
        self.services_tree.delete(*self.services_tree.get_children())
        name_filter = self.service_filter.get().lower()
        state_filter = self.service_state_filter.get()
        start_filter = self.service_start_filter.get()
        if self.repair_mode:
            path = self.get_registry_path('SYSTEM\\CurrentControlSet\\Services')
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                    i = 0
                    while True:
                        try:
                            service_name = winreg.EnumKey(key, i)
                            try:
                                with winreg.OpenKey(key, service_name) as service_key:
                                    try:
                                        display_name, _ = winreg.QueryValueEx(service_key, 'DisplayName')
                                    except:
                                        display_name = service_name
                                    try:
                                        description, _ = winreg.QueryValueEx(service_key, 'Description')
                                    except:
                                        description = ''
                                    try:
                                        image_path, _ = winreg.QueryValueEx(service_key, 'ImagePath')
                                    except:
                                        image_path = ''
                                    try:
                                        start_type, _ = winreg.QueryValueEx(service_key, 'Start')
                                        start_types = {0: 'Boot', 1: 'System', 2: 'Auto', 3: 'Manual', 4: 'Disabled'}
                                        start_type_str = start_types.get(start_type, str(start_type))
                                    except:
                                        start_type_str = 'Unknown'
                                    state = 'Unknown'
                                    if name_filter and name_filter not in display_name.lower() and name_filter not in service_name.lower():
                                        i += 1
                                        continue
                                    if state_filter != 'All' and state != state_filter:
                                        i += 1
                                        continue
                                    if start_filter != 'All' and start_type_str != start_filter:
                                        i += 1
                                        continue
                                    self.services_tree.insert('', 'end', values=(display_name, state, start_type_str, image_path, description))
                            except:
                                pass
                            i += 1
                        except OSError:
                            break
            except Exception as e:
                self.show_error(f'Error reading services from registry: {e}')
        else:
            try:
                output = subprocess.check_output('sc query type= service state= all', shell=True, text=True,
                                                 stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW,
                                                 encoding='cp866', errors='ignore', timeout=30)
                services = []
                current = {}
                for line in output.splitlines():
                    if not line.strip():
                        if current:
                            services.append(current)
                            current = {}
                        continue
                    if ':' in line:
                        parts = line.split(':', 1)
                        key = parts[0].strip()
                        val = parts[1].strip()
                        if key == 'SERVICE_NAME':
                            current['SERVICE_NAME'] = val
                        else:
                            current[key] = val
                if current:
                    services.append(current)
                for s in services:
                    name = s.get('SERVICE_NAME', '')
                    state = s.get('STATE', '')
                    try:
                        qc_out = subprocess.check_output(f'sc qc "{name}"', shell=True, text=True,
                                                         stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW,
                                                         encoding='cp866', errors='ignore', timeout=30)
                        start_type = ''
                        bin_path = ''
                        display_name = name
                        for line in qc_out.splitlines():
                            if 'START_TYPE' in line:
                                start_type = line.split(':',1)[1].strip()
                            elif 'BINARY_PATH_NAME' in line:
                                bin_path = line.split(':',1)[1].strip()
                            elif 'DISPLAY_NAME' in line:
                                display_name = line.split(':',1)[1].strip()
                        description = ''
                        try:
                            reg_out = subprocess.check_output(f'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{name}" /v Description', shell=True, text=True,
                                                              stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW,
                                                              encoding='cp866', errors='ignore', timeout=30)
                            for line in reg_out.splitlines():
                                if 'Description' in line:
                                    description = line.split('REG_SZ')[-1].strip()
                        except:
                            pass
                    except:
                        start_type = ''
                        bin_path = ''
                        display_name = name
                        description = ''
                    if name_filter and name_filter not in display_name.lower() and name_filter not in name.lower():
                        continue
                    if state_filter != 'All':
                        if state_filter == 'Running' and 'RUNNING' not in state:
                            continue
                        if state_filter == 'Stopped' and 'STOPPED' not in state:
                            continue
                    if start_filter != 'All' and start_filter not in start_type:
                        continue
                    self.services_tree.insert('', 'end', values=(display_name, state, start_type, bin_path, description))
            except Exception as e:
                self.show_error(f'Error getting services list: {e}')

    def manage_service(self, action):
        if self.repair_mode:
            self.show_error('Service management not supported in WinRE mode')
            return
        sel = self.services_tree.focus()
        if not sel:
            self.show_info('No service selected.')
            return
        vals = self.services_tree.item(sel, 'values')
        svc = vals[0]
        try:
            if action == 'start':
                run_command(['net', 'start', svc], timeout=30)
            elif action == 'stop':
                run_command(['net', 'stop', svc], timeout=30)
            elif action == 'delete':
                run_command(['sc', 'delete', svc], timeout=30)
            self.show_info(f'Action "{action}" performed for {svc}')
            self.populate_services()
        except Exception as e:
            self.show_error(f'Error managing service: {e}')

    def change_service_start_type(self):
        if self.repair_mode:
            self.show_error('Service start type change not supported in WinRE mode')
            return
        sel = self.services_tree.focus()
        if not sel:
            self.show_info('No service selected.')
            return
        new_type = self.service_new_start.get()
        if not new_type:
            self.show_info('Select new start type.')
            return
        vals = self.services_tree.item(sel, 'values')
        svc = vals[0]
        start_map = {'Auto': 'auto', 'Manual': 'demand', 'Disabled': 'disabled'}
        start_arg = start_map.get(new_type, 'auto')
        try:
            run_command(['sc', 'config', svc, 'start=', start_arg], timeout=30)
            self.show_info(f'Start type of {svc} changed to {new_type}')
            self.populate_services()
        except Exception as e:
            self.show_error(f'Error changing start type: {e}')

    def setup_taskscheduler_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=X, pady=5)
        ttk.Button(btn_frame, text='Refresh', command=self.refresh_tasks).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Create task', command=self.create_task).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Delete selected', command=self.delete_task).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Export CSV', command=self.export_tasks).pack(side=LEFT, padx=2)
        filter_frame = ttk.Frame(main_frame)
        filter_frame.pack(fill=X, pady=5)
        ttk.Label(filter_frame, text='Filter by name:').pack(side=LEFT)
        self.task_filter = ttk.Entry(filter_frame)
        self.task_filter.pack(side=LEFT, padx=2, expand=True, fill=X)
        self.task_filter.bind('<KeyRelease>', lambda e: self.refresh_tasks())
        columns = ('Name', 'Status', 'Triggers', 'Action', 'Last Run')
        self.tasks_tree = ttk.Treeview(main_frame, columns=columns, show='headings', selectmode='browse')
        for col in columns:
            self.tasks_tree.heading(col, text=col)
        self.tasks_tree.column('Name', width=250)
        self.tasks_tree.column('Status', width=100)
        self.tasks_tree.column('Triggers', width=300)
        self.tasks_tree.column('Action', width=300)
        self.tasks_tree.column('Last Run', width=150)
        scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=self.tasks_tree.yview)
        self.tasks_tree.configure(yscrollcommand=scrollbar.set)
        self.tasks_tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.tasks_menu = Menu(self, tearoff=0)
        self.tasks_menu.add_command(label='Copy name', command=self.copy_task_name)
        self.tasks_tree.bind('<Button-3>', self.show_tasks_menu)
        self.task_status = StringVar()
        task_status_label = Label(main_frame, textvariable=self.task_status, anchor=W, font=('Segoe UI', 8))
        task_status_label.pack(fill=X, pady=2)

    def show_tasks_menu(self, event):
        item = self.tasks_tree.identify_row(event.y)
        if item:
            self.tasks_tree.selection_set(item)
            self.tasks_menu.post(event.x_root, event.y_root)

    def copy_task_name(self):
        sel = self.tasks_tree.focus()
        if sel:
            vals = self.tasks_tree.item(sel, 'values')
            if vals:
                self.clipboard_clear()
                self.clipboard_append(vals[0])
                self.task_status.set('Task name copied')
                self.after(3000, lambda: self.task_status.set(''))

    def refresh_tasks(self):
        if self.repair_mode:
            self.task_status.set('Task Scheduler not available in WinRE mode')
            return
        self.tasks_tree.delete(*self.tasks_tree.get_children())
        self.task_status.set('Loading tasks...')
        def get_tasks_thread():
            try:
                output = subprocess.check_output(
                    'chcp 65001 > nul && schtasks /query /fo LIST /v',
                    shell=True, text=True, stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW, encoding='utf-8', errors='ignore', timeout=30
                )
                tasks = []
                current_task = {}
                for line in output.splitlines():
                    line = line.strip()
                    if not line and current_task:
                        tasks.append(current_task)
                        current_task = {}
                        continue
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip()
                        value = value.strip()
                        current_task[key] = value
                if current_task:
                    tasks.append(current_task)
                name_filter = self.task_filter.get().lower()
                for task in tasks:
                    task_name = task.get('TaskName', '')
                    if name_filter and name_filter not in task_name.lower():
                        continue
                    status = task.get('Status', 'Unknown')
                    if 'Running' in status:
                        status_ru = 'Running'
                    elif 'Ready' in status:
                        status_ru = 'Ready'
                    elif 'Disabled' in status:
                        status_ru = 'Disabled'
                    else:
                        status_ru = status
                    triggers = task.get('Schedule', '') or task.get('Task To Run', '')
                    if not triggers:
                        triggers = 'Not specified'
                    action = task.get('Task To Run', '')
                    if not action:
                        action = task.get('Run As User', '')
                    last_run = task.get('Last Run Time', 'Never')
                    if 'N/A' in last_run or not last_run:
                        last_run = 'Never'
                    self.after(0, lambda n=task_name, s=status_ru, t=triggers, a=action, l=last_run:
                               self.tasks_tree.insert('', 'end', values=(n, s, t[:300], a[:300], l)))
                self.after(0, lambda: self.task_status.set(f'Loaded tasks: {len(tasks)}'))
            except subprocess.CalledProcessError as e:
                self.after(0, lambda: self.task_status.set(f'Error getting tasks: {e.stderr}'))
            except Exception as e:
                self.after(0, lambda: self.task_status.set(f'Error: {str(e)}'))
        threading.Thread(target=get_tasks_thread, daemon=True).start()

    def create_task(self):
        if self.repair_mode:
            self.show_error('Task creation not supported in WinRE mode')
            return 
        dialog = Toplevel(self)
        dialog.title('Create scheduled task')
        dialog.geometry('500x400')
        dialog.transient(self)
        dialog.grab_set()
        ttk.Label(dialog, text='Task name:').pack(anchor=W, padx=10, pady=(10,0))
        task_name_entry = ttk.Entry(dialog, width=50)
        task_name_entry.pack(fill=X, padx=10, pady=5)
        ttk.Label(dialog, text='Program/script:').pack(anchor=W, padx=10, pady=(10,0))
        prog_frame = ttk.Frame(dialog)
        prog_frame.pack(fill=X, padx=10, pady=5)
        prog_entry = ttk.Entry(prog_frame)
        prog_entry.pack(side=LEFT, fill=X, expand=True)
        ttk.Button(prog_frame, text='Browse...', command=lambda: self._browse_file(prog_entry)).pack(side=RIGHT, padx=5)
        ttk.Label(dialog, text='Arguments (optional):').pack(anchor=W, padx=10, pady=(10,0))
        args_entry = ttk.Entry(dialog, width=50)
        args_entry.pack(fill=X, padx=10, pady=5)
        ttk.Label(dialog, text='Trigger:').pack(anchor=W, padx=10, pady=(10,0))
        trigger_var = StringVar(value='ONLOGON')
        ttk.Radiobutton(dialog, text='At system startup', variable=trigger_var, value='ONSTART').pack(anchor=W, padx=20)
        ttk.Radiobutton(dialog, text='At user logon', variable=trigger_var, value='ONLOGON').pack(anchor=W, padx=20)
        ttk.Radiobutton(dialog, text='Daily', variable=trigger_var, value='DAILY').pack(anchor=W, padx=20)
        status_label = ttk.Label(dialog, text='', foreground='blue')
        status_label.pack(pady=10)
        def do_create():
            name = task_name_entry.get().strip()
            prog = prog_entry.get().strip()
            args = args_entry.get().strip()
            trigger = trigger_var.get()
            if not name:
                status_label.config(text='Enter task name', foreground='red')
                return
            if not prog:
                status_label.config(text='Select a program', foreground='red')
                return
            if not os.path.exists(prog):
                status_label.config(text='Program file does not exist', foreground='red')
                return
            try:
                cmd = f'schtasks /create /tn "{shlex.quote(name)}" /tr "{shlex.quote(prog)} {shlex.quote(args)}" /sc '
                if trigger == 'ONSTART':
                    cmd += 'ONSTART /ru SYSTEM'
                elif trigger == 'ONLOGON':
                    cmd += 'ONLOGON'
                elif trigger == 'DAILY':
                    cmd += 'DAILY /st 09:00'
                subprocess.run(cmd, shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
                status_label.config(text='Task created successfully!', foreground='green')
                dialog.after(1500, dialog.destroy)
                self.refresh_tasks()
            except subprocess.CalledProcessError as e:
                status_label.config(text=f'Creation error: {e}', foreground='red')
            except Exception as e:
                status_label.config(text=f'Error: {str(e)}', foreground='red')
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text='Create', command=do_create).pack(side=LEFT, padx=5)
        ttk.Button(btn_frame, text='Cancel', command=dialog.destroy).pack(side=LEFT, padx=5)

    def _browse_file(self, entry):
        file_path = filedialog.askopenfilename(title='Select program', filetypes=[('Executable files', '*.exe'), ('All files', '*.*')])
        if file_path:
            entry.delete(0, END)
            entry.insert(0, file_path)

    def delete_task(self):
        if self.repair_mode:
            self.show_error('Task deletion not supported in WinRE mode')
            return
        sel = self.tasks_tree.focus()
        if not sel:
            self.show_info('No task selected')
            return
        vals = self.tasks_tree.item(sel, 'values')
        task_name = vals[0]
        if messagebox.askyesno('Confirm', f'Delete task "{task_name}"?'):
            try:
                run_command(['schtasks', '/delete', '/tn', task_name, '/f'], check=True, timeout=30)
                self.show_info(f'Task "{task_name}" deleted')
                self.refresh_tasks()
            except subprocess.CalledProcessError as e:
                self.show_error(f'Error deleting task: {e}')
            except Exception as e:
                self.show_error(f'Error: {str(e)}')

    def export_tasks(self):
        file_path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV files', '*.csv')], title='Export task list')
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8-sig') as f:
                    f.write('Name;Status;Triggers;Action;Last Run\n')
                    for item in self.tasks_tree.get_children():
                        values = self.tasks_tree.item(item, 'values')
                        f.write(';'.join(values) + '\n')
                self.show_info(f'Task list exported to {file_path}')
            except Exception as e:
                self.show_error(f'Export error: {e}')

    def setup_mbr_tab(self, parent):
        boot_group = ttk.LabelFrame(parent, text='Boot Recovery')
        boot_group.pack(fill=BOTH, expand=True, padx=5, pady=5)
        actions = [
            ('Restore MBR', self.restore_mbr, 'Restores MBR'),
            ('Restore bootloader', self.fix_bootloader, 'Restore bootloader'),
            ('Rebuild BCD', self.rebuild_bcd, 'Rebuilds BCD'),
            ('Check boot sector', self.check_bootsector, 'Checks boot sector')
        ]
        for text, handler, tip in actions:
            btn = ttk.Button(boot_group, text=text, command=handler)
            btn.pack(fill=X, padx=5, pady=2)
            ToolTip(btn, tip)
        disk_group = ttk.LabelFrame(parent, text='Disk Check')
        disk_group.pack(fill=BOTH, expand=True, padx=5, pady=5)
        self.disk_result = Text(disk_group, wrap=WORD, height=10, font=('Consolas', 9))
        scrollbar = ttk.Scrollbar(disk_group, orient=VERTICAL, command=self.disk_result.yview)
        self.disk_result.configure(yscrollcommand=scrollbar.set)
        self.disk_result.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)
        disk_btn_frame = ttk.Frame(disk_group)
        disk_btn_frame.pack(fill=X)
        ttk.Button(disk_btn_frame, text='CHKDSK', command=self.run_chkdsk).pack(side=LEFT, padx=2)
        ttk.Button(disk_btn_frame, text='SFC', command=self.run_sfc).pack(side=LEFT, padx=2)
        ttk.Button(disk_btn_frame, text='DISM', command=self.run_dism).pack(side=LEFT, padx=2)
        ttk.Button(disk_btn_frame, text='System Restore', command=self.open_system_restore).pack(side=LEFT, padx=2)

    def restore_mbr(self):
        try:
            res = subprocess.run('bootrec /fixmbr', shell=True, capture_output=True, text=True,
                                 creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            self.disk_result.delete(1.0, END)
            self.disk_result.insert(END, res.stdout or res.stderr or 'MBR restored.')
        except Exception as e:
            self.show_error(f'Error restoring MBR: {e}')

    def fix_bootloader(self):
        try:
            cmds = ['bootrec /fixmbr', 'bootrec /fixboot', 'bootrec /scanos', 'bootrec /rebuildbcd']
            self.disk_result.delete(1.0, END)
            for cmd in cmds:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                                   creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
                self.disk_result.insert(END, f'{cmd}:\n{r.stdout}\n{r.stderr}\n')
            self.show_info('Bootloader recovery completed.')
        except Exception as e:
            self.show_error(f'Error recovering bootloader: {e}')

    def rebuild_bcd(self):
        try:
            r = subprocess.run('bootrec /rebuildbcd', shell=True, capture_output=True, text=True,
                               creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            self.disk_result.delete(1.0, END)
            self.disk_result.insert(END, r.stdout or r.stderr or 'BCD rebuilt.')
        except Exception as e:
            self.show_error(f'Error rebuilding BCD: {e}')

    def check_bootsector(self):
        try:
            proc = subprocess.run('bootsect /nt60 all /force', shell=True, capture_output=True,
                                  creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            try:
                out = proc.stdout.decode('cp866')
            except:
                out = proc.stdout.decode('utf-8', errors='replace')
            try:
                err = proc.stderr.decode('cp866')
            except:
                err = proc.stderr.decode('utf-8', errors='replace')
            self.disk_result.delete(1.0, END)
            self.disk_result.insert(END, out or err or 'Boot sector check completed.')
        except Exception as e:
            self.show_error(f'Error checking boot sector: {e}')

    def run_chkdsk(self):
        try:
            r = run_command(['chkdsk', self.system_drive, '/f', '/r'], timeout=7200, capture_output=True, text=True)
            self.disk_result.delete(1.0, END)
            self.disk_result.insert(END, r.stdout or r.stderr or 'CHKDSK started.')
        except Exception as e:
            self.show_error(f'Error running CHKDSK: {e}')

    def run_sfc(self):
        try:
            offboot = self.system_drive.rstrip('\\')
            r = subprocess.run(f'sfc /scannow /offbootdir={offboot}\\ /offwindir={offboot}\\Windows',
                               shell=True, capture_output=True, text=True,
                               creationflags=subprocess.CREATE_NO_WINDOW, timeout=300)
            self.disk_result.delete(1.0, END)
            self.disk_result.insert(END, r.stdout or r.stderr or 'SFC completed.')
        except Exception as e:
            self.show_error(f'Error running SFC: {e}')

    def run_dism(self):
        try:
            offboot = self.system_drive.rstrip('\\')
            r = subprocess.run(f'dism /image:{offboot}\\ /cleanup-image /restorehealth',
                               shell=True, capture_output=True, text=True,
                               creationflags=subprocess.CREATE_NO_WINDOW, timeout=300)
            self.disk_result.delete(1.0, END)
            self.disk_result.insert(END, r.stdout or r.stderr or 'DISM completed.')
        except Exception as e:
            self.show_error(f'Error running DISM: {e}')

    def open_system_restore(self):
        try:
            if self.repair_mode:
                subprocess.Popen(['rstrui.exe', f'/offline:{self.system_drive}\Windows'])
            else:
                subprocess.Popen(['rstrui.exe'])
        except Exception as e:
            self.show_error(f'Cannot start System Restore: {e}')

    def setup_advanced_tab(self, parent):
        reg_group = ttk.LabelFrame(parent, text='Registry Editor')
        reg_group.pack(fill=BOTH, expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(reg_group)
        btn_frame.pack(fill=X)
        ttk.Button(btn_frame, text='Open Registry Editor', command=self.open_regedit).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Load Registry Hive', command=self.load_registry_hive).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Unload Registry Hive', command=self.unload_registry_hive).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Backup Registry', command=self.backup_registry).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text='Restore Registry', command=self.restore_registry).pack(side=LEFT, padx=2)
        passwd_group = ttk.LabelFrame(parent, text='Password Management')
        passwd_group.pack(fill=BOTH, expand=True, padx=5, pady=5)
        self.passwd_result = Text(passwd_group, wrap=WORD, height=5, font=('Consolas', 9))
        scrollbar = ttk.Scrollbar(passwd_group, orient=VERTICAL, command=self.passwd_result.yview)
        self.passwd_result.configure(yscrollcommand=scrollbar.set)
        self.passwd_result.pack(side=TOP, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)
        btn_frame2 = ttk.Frame(passwd_group)
        btn_frame2.pack(fill=X)
        ttk.Button(btn_frame2, text='List Users', command=self.list_users).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame2, text='Reset Password', command=self.reset_password).pack(side=LEFT, padx=2)
        gdi_group = ttk.LabelFrame(parent, text='GDI Effect Protection')
        gdi_group.pack(fill=BOTH, expand=True, padx=5, pady=5)
        warning_label = Label(gdi_group, text='This protection does not guarantee full security.', fg='red', font=('Segoe UI', 9, 'bold'))
        warning_label.pack(anchor=W, padx=5, pady=2)
        btn_frame3 = ttk.Frame(gdi_group)
        btn_frame3.pack(fill=X, pady=5)
        ttk.Button(btn_frame3, text='Enable block from temp folders (SRP)', command=self.enable_srp_temp_block).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame3, text='Disable block from temp folders', command=self.disable_srp_temp_block).pack(side=LEFT, padx=2)
        ToolTip(btn_frame3, 'Creates/deletes SRP policy blocking .exe from %TEMP% and %LOCALAPPDATA%\\Temp')
        startup_check_group = ttk.LabelFrame(parent, text='Startup Analysis (via Task Scheduler)')
        startup_check_group.pack(fill=BOTH, expand=True, padx=5, pady=5)
        instr_text = ("Instructions:\n"
                      "1. Click the button below. The program will create a scheduled task.\n"
                      "2. Reboot the computer.\n"
                      "3. After login, wait 30 seconds for analysis.\n"
                      "4. Result will be saved to startup_processes.log in the program folder.\n"
                      "5. The task will be deleted automatically after analysis.\n"
                      "If something goes wrong, delete the task manually via taskschd.msc or the button below.")
        instr_label = Label(startup_check_group, text=instr_text, justify=LEFT, font=('Segoe UI', 9))
        instr_label.pack(anchor=W, padx=5, pady=5)
        btn_frame4 = ttk.Frame(startup_check_group)
        btn_frame4.pack(fill=X, pady=5)
        ttk.Button(btn_frame4, text='Run check (create task)', command=self.enable_startup_check).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame4, text='Delete auto-check task', command=self.remove_startup_check_task).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame4, text='Open latest log', command=self.open_startup_log).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame4, text='Restore default Userinit', command=self.restore_default_userinit).pack(side=LEFT, padx=2)

    def open_regedit(self):
        try:
            subprocess.Popen(['regedit'], creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception as e:
            self.show_error(f'Cannot open regedit: {e}')

    def load_registry_hive(self):
        file_path = filedialog.askopenfilename(title='Select registry hive file', filetypes=[('Registry files', '*.dat;*.*')])
        if not file_path:
            return
        hive_name = simpledialog.askstring('Hive name', 'Enter name for the hive (e.g., MyHive):')
        if not hive_name:
            self.show_info('Hive name not specified.')
            return
        try:
            run_command(['reg', 'load', f'HKLM\{hive_name}', file_path], check=True,
                           creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            self.show_info(f'Hive {hive_name} loaded.')
        except Exception as e:
            self.show_error(f'Failed to load hive: {e}')

    def unload_registry_hive(self):
        hive_name = simpledialog.askstring('Hive name', 'Enter hive name to unload:')
        if not hive_name:
            return
        try:
            run_command(['reg', 'unload', f'HKLM\{hive_name}'], check=True,
                           creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            self.show_info(f'Hive {hive_name} unloaded.')
        except Exception as e:
            self.show_error(f'Failed to unload hive: {e}')

    def backup_registry(self):
        folder = filedialog.askdirectory(title='Select folder for registry backup')
        if not folder:
            return
        try:
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = os.path.join(folder, f'RegistryBackup_{timestamp}')
            os.makedirs(backup_path, exist_ok=True)
            run_command(['reg', 'export', f'HKLM\{self.system_root}', os.path.join(backup_path, 'SYSTEM.reg'), '/y'],
                           creationflags=subprocess.CREATE_NO_WINDOW, timeout=60)
            run_command(['reg', 'export', f'HKLM\{self.software_root}', os.path.join(backup_path, 'SOFTWARE.reg'), '/y'],
                           creationflags=subprocess.CREATE_NO_WINDOW, timeout=60)
            self.show_info(f'Backup created in {backup_path}')
        except Exception as e:
            self.show_error(f'Backup error: {e}')

    def restore_registry(self):
        file_path = filedialog.askopenfilename(title='Select registry file (.reg)', filetypes=[('Registration files', '*.reg')])
        if not file_path:
            return
        if messagebox.askyesno('Confirm', 'Restoring registry may cause system instability. Continue?'):
            try:
                run_command(['reg', 'import', file_path], check=True,
                               creationflags=subprocess.CREATE_NO_WINDOW, timeout=60)
                self.show_info('Registry restored from file.')
            except Exception as e:
                self.show_error(f'Restore error: {e}')

    def list_users(self):
        if self.repair_mode:
            self.show_error('User listing not supported in WinRE mode')
            return
        try:
            r = run_command(['net', 'user'], capture_output=True, text=True,
                               creationflags=subprocess.CREATE_NO_WINDOW, encoding='cp866', errors='ignore', timeout=30)
            self.passwd_result.delete(1.0, END)
            self.passwd_result.insert(END, r.stdout or r.stderr)
        except Exception as e:
            self.show_error(f'Error listing users: {e}')

    def reset_password(self):
        if self.repair_mode:
            self.show_error('Password reset not supported in WinRE mode')
            return
        username = simpledialog.askstring('Reset Password', 'Enter username:')
        if not username:
            return
        newpass = simpledialog.askstring('New Password', f'Enter new password for {username}:')
        if newpass is None:
            return
        try:
            run_command(['net', 'user', username, newpass], check=True,
                           creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            self.show_info('Password changed.')
        except Exception as e:
            self.show_error(f'Failed to reset password: {e}')

    def enable_srp_temp_block(self):
        srp_key = self.get_registry_path('SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers')
        try:
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, srp_key) as key:
                winreg.SetValueEx(key, 'TransparentEnabled', 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, 'AuthenticodeEnabled', 0, winreg.REG_DWORD, 0)
            paths_to_block = ['%TEMP%\\*.exe', '%TMP%\\*.exe', '%LOCALAPPDATA%\\Temp\\*.exe']
            for path_rule in paths_to_block:
                rule_key = srp_key + '\\0\\Paths\\{' + path_rule + '}'
                with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, rule_key) as rk:
                    winreg.SetValueEx(rk, 'Description', 0, winreg.REG_SZ, 'Block execution from temp folders')
                    winreg.SetValueEx(rk, 'SaferFlags', 0, winreg.REG_DWORD, 0)
                    winreg.SetValueEx(rk, 'ItemData', 0, winreg.REG_SZ, path_rule)
            self.show_info('Block from temp folders activated. Reboot required.')
            winsound.MessageBeep()
        except Exception as e:
            self.show_error(f'Error enabling SRP: {e}')

    def disable_srp_temp_block(self):
        srp_key = self.get_registry_path('SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers')
        paths_to_block = ['%TEMP%\\*.exe', '%TMP%\\*.exe', '%LOCALAPPDATA%\\Temp\\*.exe']
        try:
            for path_rule in paths_to_block:
                rule_key = srp_key + '\\0\\Paths\\{' + path_rule + '}'
                try:
                    winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, rule_key)
                except FileNotFoundError:
                    pass
            self.show_info('Block from temp folders disabled. Reboot required.')
            winsound.MessageBeep()
        except Exception as e:
            self.show_error(f'Error disabling SRP: {e}')

    def remove_startup_check_task(self):
        task_name = "WREART_StartupCheck"
        try:
            subprocess.run(f'schtasks /delete /tn "{task_name}" /f', shell=True,
                           creationflags=subprocess.CREATE_NO_WINDOW, check=True, timeout=30)
            self.show_info(f'Task "{task_name}" deleted successfully.')
        except subprocess.CalledProcessError:
            self.show_info(f'Task "{task_name}" not found or already deleted.')
        except Exception as e:
            self.show_error(f'Error deleting task: {e}')

    def enable_startup_check(self):
        exe_path = sys.executable
        if exe_path.lower().endswith('.py'):
            cmd = f'"{sys.executable}" "{os.path.abspath(__file__)}" --check-startup'
        else:
            cmd = f'"{exe_path}" --check-startup'
        task_name = "WREART_StartupCheck"
        try:
            subprocess.run(f'schtasks /delete /tn "{task_name}" /f', shell=True,
                           creationflags=subprocess.CREATE_NO_WINDOW, capture_output=True)
        except:
            pass
        create_cmd = (f'schtasks /create /tn "{task_name}" /tr "{cmd}" /sc ONLOGON /ru SYSTEM /rl HIGHEST /f')
        try:
            result = subprocess.run(create_cmd, shell=True, capture_output=True, text=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            if result.returncode == 0:
                self.show_info('Task created successfully. Reboot to run check. It will self-delete after analysis.')
            else:
                self.show_error(f'Error creating task: {result.stderr}')
        except Exception as e:
            self.show_error(f'Failed to create task: {e}')

    def restore_default_userinit(self):
        if not messagebox.askyesno('Restore Userinit', 'Set value to "C:\\Windows\\System32\\userinit.exe,". Continue?'):
            return
        try:
            winlogon_path = self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, winlogon_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, 'Userinit', 0, winreg.REG_SZ, 'C:\\Windows\\System32\\userinit.exe,')
            self.show_info('Userinit restored to default.')
            self.update_shell_values()
        except Exception as e:
            self.show_error(f'Error restoring Userinit: {e}')

    def open_startup_log(self):
        log_path = os.path.join(os.path.dirname(sys.executable), 'startup_processes.log')
        if os.path.exists(log_path):
            os.startfile(log_path)
        else:
            self.show_info('Log file not found. Run check first.')

    def setup_unlock_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        left_frame = ttk.LabelFrame(main_frame, text='Unlock Tools')
        left_frame.pack(side=LEFT, fill=BOTH, expand=True, padx=5, pady=5)
        unlock_tools = [
            ('Unlock Task Manager', self.unlock_taskmgr, 'Removes Task Manager restrictions'),
            ('Unlock Registry', self.unlock_registry, 'Removes Registry Editor restrictions'),
            ('Unlock CMD', self.unlock_cmd, 'Removes Command Prompt restrictions'),
            ('Unlock Control Panel', self.unlock_controlpanel, 'Removes Control Panel restrictions'),
            ('Reset all policies', self.reset_all_policies, 'Full reset of Group Policies'),
            ('Restore admin rights', self.restore_admin_rights, 'Restores administrator privileges'),
            ('Unlock EXE files', self.unlock_exe_files, 'Restores executable file associations'),
            ('Restore file associations', self.restore_file_associations, 'Restores common file associations'),
            ('Restore system fonts', self.restore_fonts, 'Resets font substitutes and cache'),
            ('Unlock Safe Mode', self.unlock_safe_mode, 'Restores Safe Mode boot options')
        ]
        for text, command, tip in unlock_tools:
            btn = ttk.Button(left_frame, text=text, command=command, style='Modern.TButton')
            btn.pack(fill=X, padx=5, pady=2)
            ToolTip(btn, tip)
        right_frame = ttk.LabelFrame(main_frame, text='Operation Log')
        right_frame.pack(side=RIGHT, fill=BOTH, expand=True, padx=5, pady=5)
        self.unlock_log = Text(right_frame, wrap=WORD, height=20, font=('Consolas', 9))
        scrollbar = ttk.Scrollbar(right_frame, orient=VERTICAL, command=self.unlock_log.yview)
        self.unlock_log.configure(yscrollcommand=scrollbar.set)
        self.unlock_log.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)
        log_buttons = ttk.Frame(right_frame)
        log_buttons.pack(fill=X, pady=5)
        ttk.Button(log_buttons, text='Clear log', command=lambda: self.unlock_log.delete(1.0, END)).pack(side=LEFT, padx=2)
        ttk.Button(log_buttons, text='Save log', command=self.save_unlock_log).pack(side=LEFT, padx=2)

    def log_unlock_action(self, message):
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        self.unlock_log.insert(END, f'[{timestamp}] {message}\n')
        self.unlock_log.see(END)

    def _delete_registry_value(self, hive, path, value_name):
        if self.repair_mode and hive == winreg.HKEY_CURRENT_USER:
            self.log_unlock_action(f'Skip HKCU operation in WinRE: {path} -> {value_name}')
            return
        try:
            full_path = self.get_registry_path(path) if hive == winreg.HKEY_LOCAL_MACHINE else path
            with winreg.OpenKey(hive, full_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, value_name)
                self.log_unlock_action(f'Deleted {value_name} from {path}')
        except FileNotFoundError:
            pass
        except Exception as e:
            self.log_unlock_action(f'Error in {path}: {e}')

    def unlock_taskmgr(self):
        paths = [r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System']
        for path in paths:
            self._delete_registry_value(winreg.HKEY_LOCAL_MACHINE, path, 'DisableTaskMgr')
            if not self.repair_mode:
                self._delete_registry_value(winreg.HKEY_CURRENT_USER, path, 'DisableTaskMgr')
        self.log_unlock_action('Task Manager unlocked')
        winsound.MessageBeep()

    def unlock_registry(self):
        paths = [r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System']
        for path in paths:
            self._delete_registry_value(winreg.HKEY_LOCAL_MACHINE, path, 'DisableRegistryTools')
            if not self.repair_mode:
                self._delete_registry_value(winreg.HKEY_CURRENT_USER, path, 'DisableRegistryTools')
        self.log_unlock_action('Registry Editor unlocked')
        winsound.MessageBeep()

    def unlock_cmd(self):
        paths = [r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System']
        for path in paths:
            self._delete_registry_value(winreg.HKEY_LOCAL_MACHINE, path, 'DisableCMD')
            if not self.repair_mode:
                self._delete_registry_value(winreg.HKEY_CURRENT_USER, path, 'DisableCMD')
        self.log_unlock_action('Command Prompt unlocked')
        winsound.MessageBeep()

    def unlock_controlpanel(self):
        paths = [r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer']
        values = ['NoControlPanel', 'NoSettingsPage', 'NoSetFolders']
        for path in paths:
            for val in values:
                self._delete_registry_value(winreg.HKEY_LOCAL_MACHINE, path, val)
                if not self.repair_mode:
                    self._delete_registry_value(winreg.HKEY_CURRENT_USER, path, val)
        self.log_unlock_action('Control Panel unlocked')
        winsound.MessageBeep()

    def reset_all_policies(self):
        for path in POLICY_PATHS:
            for val in POLICY_VALUES:
                self._delete_registry_value(winreg.HKEY_LOCAL_MACHINE, path, val)
                if not self.repair_mode:
                    self._delete_registry_value(winreg.HKEY_CURRENT_USER, path, val)
        self.log_unlock_action('All policies reset')
        winsound.MessageBeep()

    def restore_admin_rights(self):
        if self.repair_mode:
            self.log_unlock_action('Admin rights restoration not available in WinRE')
            return
        try:
            run_command(['net', 'user', 'administrator', '/active:yes'], capture_output=True,
                           creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            self.log_unlock_action('Built-in administrator account activated')
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                self.get_registry_path('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'),
                                0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, 'EnableLUA', 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, 'ConsentPromptBehaviorAdmin', 0, winreg.REG_DWORD, 5)
            self.log_unlock_action('UAC settings reset')
            winsound.MessageBeep()
        except Exception as e:
            self.log_unlock_action(f'Error restoring admin rights: {e}')

    def unlock_exe_files(self):
        if self.repair_mode:
            self.log_unlock_action('EXE unlock not available in WinRE')
            return
        try:
            subprocess.run('assoc .exe=exefile', shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            subprocess.run('ftype exefile="%1" %*', shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            self.log_unlock_action('EXE associations restored')
            winsound.MessageBeep()
        except Exception as e:
            self.log_unlock_action(f'Error unlocking EXE: {e}')

    def restore_file_associations(self):
        if self.repair_mode:
            self.log_unlock_action('File association restore not available in WinRE')
            return
        associations = [('.exe', 'exefile', '"%1" %*'), ('.com', 'comfile', '"%1" %*'),
                        ('.bat', 'batfile', '"%1" %*'), ('.cmd', 'cmdfile', '"%1" %*'),
                        ('.scr', 'scrfile', '"%1" /S'), ('.reg', 'regfile', 'regedit.exe "%1"')]
        for ext, filetype, command in associations:
            try:
                subprocess.run(f'assoc {ext}={filetype}', shell=True, capture_output=True,
                               creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
                subprocess.run(f'ftype {filetype}={command}', shell=True, capture_output=True,
                               creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
                self.log_unlock_action(f'Restored association {ext}')
            except Exception as e:
                self.log_unlock_action(f'Error for {ext}: {e}')
        winsound.MessageBeep()

    def restore_fonts(self):
        if self.repair_mode:
            self.log_unlock_action('Font restore not available in WinRE')
            return
        try:
            try:
                subprocess.run('reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" /f',
                               shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            except:
                pass
            try:
                subprocess.run('reg delete "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" /f',
                               shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
            except:
                pass
            font_cache = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Windows', 'Fonts', 'fontcache.dat')
            if os.path.exists(font_cache):
                os.remove(font_cache)
            self.log_unlock_action('System fonts restored (reboot required)')
            winsound.MessageBeep()
        except Exception as e:
            self.log_unlock_action(f'Error restoring fonts: {e}')

    def unlock_safe_mode(self):
        try:
            safe_boot_path = self.get_registry_path("SYSTEM\\CurrentControlSet\\Control\\SafeBoot")
            keys_to_create = [
                safe_boot_path,
                f"{safe_boot_path}\\Minimal",
                f"{safe_boot_path}\\Network",
                f"{safe_boot_path}\\Minimal\\MSIServer",
                f"{safe_boot_path}\\Network\\MSIServer"
            ]
            for key_path in keys_to_create:
                try:
                    winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    self.log_unlock_action(f"Created key: {key_path}")
                except Exception as e:
                    self.log_unlock_action(f"Error creating key {key_path}: {e}")
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, safe_boot_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "OptionValue", 0, winreg.REG_DWORD, 1)
                    self.log_unlock_action("Set OptionValue = 1")
            except Exception as e:
                self.log_unlock_action(f"Error setting OptionValue: {e}")
            msiserver_keys = [
                f"{safe_boot_path}\\Minimal\\MSIServer",
                f"{safe_boot_path}\\Network\\MSIServer"
            ]
            for msi_key in msiserver_keys:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, msi_key, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "Service")
                        self.log_unlock_action(f"Set default value for {msi_key}")
                except Exception as e:
                    self.log_unlock_action(f"Error setting MSIServer value: {e}")
            self.show_info('Safe Mode successfully restored. Reboot may be required.')
            winsound.MessageBeep()
        except Exception as e:
            error_msg = f"Error restoring Safe Mode: {e}"
            self.log_unlock_action(error_msg)
            self.show_error(error_msg)

    def save_unlock_log(self):
        file_path = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text files', '*.txt'), ('All files', '*.*')], title='Save unlock log')
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.unlock_log.get(1.0, END))
                self.log_unlock_action(f'Log saved: {file_path}')
            except Exception as e:
                self.log_unlock_action(f'Save error: {e}')

    def setup_virus_removal_tab(self, parent):
        main_frame = ttk.LabelFrame(parent, text='Malware Removal Scripts (bat)')
        main_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        instr = ("Copy bat files into 'scripts' folder next to the program.\n"
                 "Each script will run in a separate command prompt window.")
        instr_label = Label(main_frame, text=instr, font=('Segoe UI', 9), justify=LEFT)
        instr_label.pack(anchor=W, padx=5, pady=5)
        self.script_buttons = {}
        for name in SCRIPT_NAMES:
            frm = ttk.Frame(main_frame)
            frm.pack(fill=X, padx=5, pady=2)
            label = ttk.Label(frm, text=f'{name}.bat', width=15)
            label.pack(side=LEFT)
            btn = ttk.Button(frm, text='Run', command=lambda n=name: self.run_virus_script(n))
            btn.pack(side=LEFT, padx=5)
            status_label = ttk.Label(frm, text='', foreground='gray')
            status_label.pack(side=LEFT, padx=5)
            self.script_buttons[name] = {'button': btn, 'status': status_label}
        ctrl_frame = ttk.Frame(main_frame)
        ctrl_frame.pack(fill=X, pady=10)
        ttk.Button(ctrl_frame, text='Run all scripts', command=self.run_all_scripts).pack(side=LEFT, padx=5)
        ttk.Button(ctrl_frame, text='Check presence', command=self.check_scripts_presence).pack(side=LEFT, padx=5)
        self.after(100, self.check_scripts_presence)

    def get_scripts_folder(self):
        try:
            base_dir = os.path.dirname(sys.executable)
        except:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base_dir, 'scripts')

    def check_scripts_presence(self):
        scripts_folder = self.get_scripts_folder()
        for name in SCRIPT_NAMES:
            file_path = os.path.join(scripts_folder, f'{name}.bat')
            if os.path.isfile(file_path):
                self.script_buttons[name]['status'].config(text='Available', foreground='green')
                self.script_buttons[name]['button'].config(state='normal')
            else:
                self.script_buttons[name]['status'].config(text='Missing', foreground='red')
                self.script_buttons[name]['button'].config(state='disabled')

    def run_virus_script(self, name):
        scripts_folder = self.get_scripts_folder()
        bat_path = os.path.join(scripts_folder, f'{name}.bat')
        if not os.path.isfile(bat_path):
            messagebox.showerror('Error', f'File {bat_path} not found.')
            return
        try:
            subprocess.Popen(f'cmd /k "{bat_path}"', cwd=scripts_folder, creationflags=subprocess.CREATE_NEW_CONSOLE)
            messagebox.showinfo('Run', f'Script {name}.bat started. Close its window when done.')
        except Exception as e:
            messagebox.showerror('Error', f'Cannot run script: {e}')

    def run_all_scripts(self):
        scripts_folder = self.get_scripts_folder()
        missing = [f'{name}.bat' for name in SCRIPT_NAMES if not os.path.isfile(os.path.join(scripts_folder, f'{name}.bat'))]
        if missing:
            if not messagebox.askyesno('Missing files', f'Files not found: {", ".join(missing)}\nContinue with others?'):
                return
        for name in SCRIPT_NAMES:
            bat_path = os.path.join(scripts_folder, f'{name}.bat')
            if os.path.isfile(bat_path):
                subprocess.Popen(f'cmd /k "{bat_path}"', cwd=scripts_folder, creationflags=subprocess.CREATE_NEW_CONSOLE)
                time.sleep(0.5)
        messagebox.showinfo('Done', 'All available scripts launched.')

    def show_error(self, message):
        messagebox.showerror('Error', message)

    def show_info(self, message):
        messagebox.showinfo('Information', message)


if __name__ == '__main__':
    app = WindowsREHelperPro()
    app.mainloop()