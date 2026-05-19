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
from tkinter import *
from tkinter import ttk, messagebox, filedialog, simpledialog
import winsound

CONFIG_PATH = os.path.join(tempfile.gettempdir(), 'winrehelperpro_cfg.json')
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
                  'userinit.exe'}
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
            subprocess.check_output('tasklist /fi "imagename eq explorer.exe"', shell=True,
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
            output = subprocess.check_output('tasklist /v /fo csv', shell=True, text=True,
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
    task_name = "WinREHelperPro_StartupCheck"
    try:
        subprocess.run(f'schtasks /delete /tn "{task_name}" /f', shell=True,
                       creationflags=subprocess.CREATE_NO_WINDOW, capture_output=True)
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
                    relief=SOLID, borderwidth=1, font=('Arial', 9))
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
        self.label = Label(self, text=title, font=('Arial', 9))
        self.label.pack(pady=5)
        self.progress.start()
    def close(self):
        self.progress.stop()
        self.destroy()

class WindowsREHelperPro(Tk):
    def __init__(self):
        super().__init__()
        self.title('Windows RE Advanced Repair Tool v2')
        self.geometry('1300x850')
        self.minsize(1100, 750)
        self.option_add('*Font', 'Arial 9')
        self.setup_styles()
        self.repair_mode = self.detect_winre_environment()
        self.system_drive = self.detect_or_prompt_system_drive()
        self.system_root = 'SYSTEM'
        self.software_root = 'SOFTWARE'
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
        status_bar = Frame(self, bd=1, relief=SUNKEN, bg='#f0f0f0')
        status_bar.pack(side=BOTTOM, fill=X)
        status_label = Label(status_bar, textvariable=self.status_var, anchor=W, bg='#f0f0f0', font=('Arial', 9))
        status_label.pack(side=LEFT, fill=X, expand=True, padx=2)
        disclaimer = Label(status_bar, text="⚠️ Provided AS-IS, no warranties.", fg='red', bg='#f0f0f0', font=('Arial', 8, 'bold'))
        disclaimer.pack(side=LEFT, padx=10)
        ttk.Button(status_bar, text='Change drive', command=self.change_system_drive).pack(side=RIGHT, padx=4)
        ttk.Button(status_bar, text='Auto-detect', command=self.auto_detect_drive).pack(side=RIGHT)
        ttk.Button(status_bar, text='Refresh all', command=self.initial_load).pack(side=RIGHT, padx=4)
        self.update_status()
        self.after(100, self.initial_load)

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook.Tab', font=('Arial', 9, 'bold'))
        style.configure('TLabelframe.Label', font=('Arial', 9, 'bold'))
        style.configure('TButton', font=('Arial', 9))
        style.configure('TLabel', font=('Arial', 9))
        style.configure('TEntry', font=('Arial', 9))
        style.configure('TCombobox', font=('Arial', 9))
        style.configure('Treeview', font=('Arial', 9))
        style.configure('Treeview.Heading', font=('Arial', 9, 'bold'))

    def load_system_hives(self):
        system_hive = os.path.join(self.system_drive, 'Windows', 'System32', 'config', 'SYSTEM')
        software_hive = os.path.join(self.system_drive, 'Windows', 'System32', 'config', 'SOFTWARE')
        sam_hive = os.path.join(self.system_drive, 'Windows', 'System32', 'config', 'SAM')
        security_hive = os.path.join(self.system_drive, 'Windows', 'System32', 'config', 'SECURITY')
        if not os.path.exists(system_hive) or not os.path.exists(software_hive):
            raise FileNotFoundError('SYSTEM/SOFTWARE hives not found.')
        subprocess.run(f'reg load HKLM\\MainSystem "{system_hive}"', shell=True, check=True,
                       creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(f'reg load HKLM\\MainSoftware "{software_hive}"', shell=True, check=True,
                       creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            subprocess.run(f'reg load HKLM\\MainSAM "{sam_hive}"', shell=True, check=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(f'reg load HKLM\\MainSecurity "{security_hive}"', shell=True, check=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        except:
            pass
        self.system_root = 'MainSystem'
        self.software_root = 'MainSoftware'

    def unload_hives(self):
        try:
            subprocess.run('reg unload HKLM\\MainSystem', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run('reg unload HKLM\\MainSoftware', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run('reg unload HKLM\\MainSAM', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run('reg unload HKLM\\MainSecurity', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except:
            pass

    def get_registry_path(self, base_path):
        if self.repair_mode and self.software_root != 'SOFTWARE':
            return base_path.replace('SOFTWARE', self.software_root).replace('SYSTEM', self.system_root)
        return base_path

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
        ttk.Label(win, text='Press OK to select system volume:', font=('Arial', 9)).pack(anchor=W, padx=10, pady=6)
        columns = ('Letter', 'Label/FS/Size', 'Windows')
        tree = ttk.Treeview(win, columns=columns, show='headings', height=12)
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, anchor=W, width=150 if col == 'Label/FS/Size' else 70)
        tree.pack(fill=BOTH, expand=True, padx=10, pady=5)
        for d in drives:
            info = pretty_drive_name(d)
            iswin = '✓' if self.is_valid_system_drive(d) else ''
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
            ('IFEO', self.setup_ifeo_tab),
            ('Policies', self.setup_gp_tab),
            ('Shell/Userinit', self.setup_shell_tab),
            ('Services', self.setup_services_tab),
            ('Task Scheduler', self.setup_taskscheduler_tab),
            ('Boot/Disk', self.setup_mbr_tab),
            ('Advanced', self.setup_advanced_tab),
            ('Unlock', self.setup_unlock_tab),
            ('Virus Removal', self.setup_virus_removal_tab)
        ]
        for name, maker in tabs:
            frame = ttk.Frame(notebook)
            maker(frame)
            notebook.add(frame, text=name)

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
            self.adv_autostart_tree.heading(col, text=col)
        self.adv_autostart_tree.column('Section', width=250)
        self.adv_autostart_tree.column('Parameter', width=200)
        self.adv_autostart_tree.column('Value', width=500)
        self.adv_autostart_tree.column('Type', width=80)
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
        status_label = Label(main_frame, textvariable=self.adv_status, anchor=W, font=('Arial', 8))
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
        self.adv_status.set('Collecting data...')
        locations = [
            (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SYSTEM\\Setup'), 'Setup Parameters'),
            (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SYSTEM\\CurrentControlSet\\Control\\Session Manager'), 'Session Manager'),
            (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows'), 'AppInit'),
            (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SOFTWARE\\Microsoft\\Active Setup\\Installed Components'), 'Active Setup (HKLM)'),
            (winreg.HKEY_CURRENT_USER, 'Software\\Microsoft\\Active Setup\\Installed Components', 'Active Setup (HKCU)'),
            (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices'), 'RunServices (HKLM)'),
            (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce'), 'RunServicesOnce (HKLM)'),
            (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs'), 'KnownDLLs'),
            (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify'), 'Winlogon Notify'),
        ]
        for hive, subkey, section_name in locations:
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    i = 0
                    while True:
                        try:
                            name, value, typ = winreg.EnumValue(key, i)
                            typ_str = self._reg_type_to_str(typ)
                            val_str = str(value)
                            if len(val_str) > 200:
                                val_str = val_str[:200] + '…'
                            self.adv_autostart_tree.insert('', 'end', values=(section_name, name, val_str, typ_str))
                            i += 1
                        except OSError:
                            break
            except FileNotFoundError:
                pass
            except Exception as e:
                self.adv_status.set(f'Error in {section_name}: {e}')
        specials = [
            (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SYSTEM\\Setup'), 'CmdLine', 'CmdLine (Setup)'),
            (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SYSTEM\\Setup'), 'SetupType', 'SetupType'),
            (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SYSTEM\\Setup'), 'SystemPartition', 'SystemPartition'),
            (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SYSTEM\\CurrentControlSet\\Control\\Session Manager'), 'BootExecute', 'BootExecute'),
            (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows'), 'AppInit_DLLs', 'AppInit_DLLs'),
            (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows'), 'LoadAppInit_DLLs', 'LoadAppInit_DLLs'),
            (winreg.HKEY_LOCAL_MACHINE, self.get_registry_path('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows'), 'RequireSignedAppInit_DLLs', 'RequireSignedAppInit_DLLs'),
        ]
        for hive, subkey, value_name, display_name in specials:
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    val, typ = winreg.QueryValueEx(key, value_name)
                    typ_str = self._reg_type_to_str(typ)
                    val_str = str(val)
                    if len(val_str) > 200:
                        val_str = val_str[:200] + '…'
                    self.adv_autostart_tree.insert('', 'end', values=(display_name, value_name, val_str, typ_str))
            except FileNotFoundError:
                pass
            except:
                pass
        self.adv_status.set(f'Loaded entries: {len(self.adv_autostart_tree.get_children())}')

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
        task_status_label = Label(main_frame, textvariable=self.task_status, anchor=W, font=('Arial', 8))
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
                    creationflags=subprocess.CREATE_NO_WINDOW, encoding='utf-8', errors='ignore'
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
                subprocess.run(cmd, shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
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
                subprocess.run(f'schtasks /delete /tn "{shlex.quote(task_name)}" /f', shell=True, check=True,
                               creationflags=subprocess.CREATE_NO_WINDOW)
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
                                self.autostart_tree.insert('', 'end', values=('Winlogon', key_name, value, 'Active', winlogon_path))
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
                                    self.autostart_tree.insert('', 'end', values=(desc, name, value, 'Active', path))
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
                            self.autostart_tree.insert('', 'end', values=('Startup Folder', file, full_path, 'Active', desc))
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
                                                 encoding='cp866', errors='ignore')
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
                                                         encoding='cp866', errors='ignore')
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
                                                              encoding='cp866', errors='ignore')
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
                subprocess.run(f'net start "{svc}"', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            elif action == 'stop':
                subprocess.run(f'net stop "{svc}"', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            elif action == 'delete':
                subprocess.run(f'sc delete "{svc}"', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
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
            subprocess.run(f'sc config "{svc}" start= {start_arg}', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            self.show_info(f'Start type of {svc} changed to {new_type}')
            self.populate_services()
        except Exception as e:
            self.show_error(f'Error changing start type: {e}')

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
                                 creationflags=subprocess.CREATE_NO_WINDOW)
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
                                   creationflags=subprocess.CREATE_NO_WINDOW)
                self.disk_result.insert(END, f'{cmd}:\n{r.stdout}\n{r.stderr}\n')
            self.show_info('Bootloader recovery completed.')
        except Exception as e:
            self.show_error(f'Error recovering bootloader: {e}')

    def rebuild_bcd(self):
        try:
            r = subprocess.run('bootrec /rebuildbcd', shell=True, capture_output=True, text=True,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            self.disk_result.delete(1.0, END)
            self.disk_result.insert(END, r.stdout or r.stderr or 'BCD rebuilt.')
        except Exception as e:
            self.show_error(f'Error rebuilding BCD: {e}')

    def check_bootsector(self):
        try:
            proc = subprocess.run('bootsect /nt60 all /force', shell=True, capture_output=True,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
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
            r = subprocess.run(f'chkdsk {self.system_drive} /f /r', shell=True, capture_output=True, text=True,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            self.disk_result.delete(1.0, END)
            self.disk_result.insert(END, r.stdout or r.stderr or 'CHKDSK started.')
        except Exception as e:
            self.show_error(f'Error running CHKDSK: {e}')

    def run_sfc(self):
        try:
            offboot = self.system_drive.rstrip('\\')
            r = subprocess.run(f'sfc /scannow /offbootdir={offboot}\\ /offwindir={offboot}\\Windows',
                               shell=True, capture_output=True, text=True,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            self.disk_result.delete(1.0, END)
            self.disk_result.insert(END, r.stdout or r.stderr or 'SFC completed.')
        except Exception as e:
            self.show_error(f'Error running SFC: {e}')

    def run_dism(self):
        try:
            offboot = self.system_drive.rstrip('\\')
            r = subprocess.run(f'dism /image:{offboot}\\ /cleanup-image /restorehealth',
                               shell=True, capture_output=True, text=True,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            self.disk_result.delete(1.0, END)
            self.disk_result.insert(END, r.stdout or r.stderr or 'DISM completed.')
        except Exception as e:
            self.show_error(f'Error running DISM: {e}')

    def open_system_restore(self):
        try:
            if self.repair_mode:
                subprocess.Popen(f'rstrui.exe /offline:{self.system_drive}\\Windows', shell=True)
            else:
                subprocess.Popen('rstrui.exe', shell=True)
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
        warning_label = Label(gdi_group, text='⚠️ This protection does not guarantee full security.', fg='red', font=('Arial', 9, 'bold'))
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
                      "⚠️ If something goes wrong, delete the task manually via taskschd.msc or the button below.")
        instr_label = Label(startup_check_group, text=instr_text, justify=LEFT, font=('Arial', 9))
        instr_label.pack(anchor=W, padx=5, pady=5)
        btn_frame4 = ttk.Frame(startup_check_group)
        btn_frame4.pack(fill=X, pady=5)
        ttk.Button(btn_frame4, text='Run check (create task)', command=self.enable_startup_check).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame4, text='Delete auto-check task', command=self.remove_startup_check_task).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame4, text='Open latest log', command=self.open_startup_log).pack(side=LEFT, padx=2)
        ttk.Button(btn_frame4, text='Restore default Userinit', command=self.restore_default_userinit).pack(side=LEFT, padx=2)

    def open_regedit(self):
        try:
            subprocess.Popen('regedit', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
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
            subprocess.run(f'reg load HKLM\\{hive_name} "{file_path}"', shell=True, check=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
            self.show_info(f'Hive {hive_name} loaded.')
        except Exception as e:
            self.show_error(f'Failed to load hive: {e}')

    def unload_registry_hive(self):
        hive_name = simpledialog.askstring('Hive name', 'Enter hive name to unload:')
        if not hive_name:
            return
        try:
            subprocess.run(f'reg unload HKLM\\{hive_name}', shell=True, check=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
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
            subprocess.run(f'reg export HKLM\\{self.system_root} "{backup_path}\\SYSTEM.reg" /y', shell=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(f'reg export HKLM\\{self.software_root} "{backup_path}\\SOFTWARE.reg" /y', shell=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
            self.show_info(f'Backup created in {backup_path}')
        except Exception as e:
            self.show_error(f'Backup error: {e}')

    def restore_registry(self):
        file_path = filedialog.askopenfilename(title='Select registry file (.reg)', filetypes=[('Registration files', '*.reg')])
        if not file_path:
            return
        if messagebox.askyesno('Confirm', 'Restoring registry may cause system instability. Continue?'):
            try:
                subprocess.run(f'reg import "{file_path}"', shell=True, check=True,
                               creationflags=subprocess.CREATE_NO_WINDOW)
                self.show_info('Registry restored from file.')
            except Exception as e:
                self.show_error(f'Restore error: {e}')

    def list_users(self):
        if self.repair_mode:
            self.show_error('User listing not supported in WinRE mode')
            return
        try:
            r = subprocess.run('net user', shell=True, capture_output=True, text=True,
                               creationflags=subprocess.CREATE_NO_WINDOW, encoding='cp866', errors='ignore')
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
            subprocess.run(f'net user "{username}" "{newpass}"', shell=True, check=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
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
        task_name = "WinREHelperPro_StartupCheck"
        try:
            subprocess.run(f'schtasks /delete /tn "{task_name}" /f', shell=True,
                           creationflags=subprocess.CREATE_NO_WINDOW, check=True)
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
        task_name = "WinREHelperPro_StartupCheck"
        try:
            subprocess.run(f'schtasks /delete /tn "{task_name}" /f', shell=True,
                           creationflags=subprocess.CREATE_NO_WINDOW, capture_output=True)
        except:
            pass
        create_cmd = (f'schtasks /create /tn "{task_name}" /tr "{cmd}" /sc ONLOGON /ru SYSTEM /rl HIGHEST /f')
        try:
            result = subprocess.run(create_cmd, shell=True, capture_output=True, text=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
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
            ('Restore system fonts', self.restore_fonts, 'Resets font substitutes and cache')
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
        paths = [r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                 r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System']
        for path in paths:
            self._delete_registry_value(winreg.HKEY_LOCAL_MACHINE, path, 'DisableTaskMgr')
            if not self.repair_mode:
                self._delete_registry_value(winreg.HKEY_CURRENT_USER, path, 'DisableTaskMgr')
        self.log_unlock_action('Task Manager unlocked')
        winsound.MessageBeep()

    def unlock_registry(self):
        paths = [r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                 r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System']
        for path in paths:
            self._delete_registry_value(winreg.HKEY_LOCAL_MACHINE, path, 'DisableRegistryTools')
            if not self.repair_mode:
                self._delete_registry_value(winreg.HKEY_CURRENT_USER, path, 'DisableRegistryTools')
        self.log_unlock_action('Registry Editor unlocked')
        winsound.MessageBeep()

    def unlock_cmd(self):
        paths = [r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                 r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System']
        for path in paths:
            self._delete_registry_value(winreg.HKEY_LOCAL_MACHINE, path, 'DisableCMD')
            if not self.repair_mode:
                self._delete_registry_value(winreg.HKEY_CURRENT_USER, path, 'DisableCMD')
        self.log_unlock_action('Command Prompt unlocked')
        winsound.MessageBeep()

    def unlock_controlpanel(self):
        paths = [r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
                 r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer']
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
            subprocess.run('net user administrator /active:yes', shell=True, capture_output=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
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
            subprocess.run('assoc .exe=exefile', shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run('ftype exefile="%1" %*', shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
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
                               creationflags=subprocess.CREATE_NO_WINDOW)
                subprocess.run(f'ftype {filetype}={command}', shell=True, capture_output=True,
                               creationflags=subprocess.CREATE_NO_WINDOW)
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
                               shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            except:
                pass
            try:
                subprocess.run('reg delete "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" /f',
                               shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            except:
                pass
            font_cache = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Windows', 'Fonts', 'fontcache.dat')
            if os.path.exists(font_cache):
                os.remove(font_cache)
            self.log_unlock_action('System fonts restored (reboot required)')
            winsound.MessageBeep()
        except Exception as e:
            self.log_unlock_action(f'Error restoring fonts: {e}')

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
        instr_label = Label(main_frame, text=instr, font=('Arial', 9), justify=LEFT)
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