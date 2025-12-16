import os
import subprocess
import re
import pdfkit
import tempfile
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import sys
import time
import math

results = []

# ==================== RATIONALE DICTIONARY ====================
RATIONALE_DICT = {
    # 1.2 Package Management
    "1.2.1.1": "It is important to ensure that updates are obtained from a valid source to protect against spoofing...",
    "1.2.1.2": "If a system's package repositories are misconfigured important patches may not be identified...",
    "1.2.2.1": "Use the latest software patches to benefit from security enhancements and new features, while ensuring compatibility and supportability of additional software.",
    
    # 1.3 AppArmor
    "1.3.1.1": "Without a Mandatory Access Control system installed only the default Discretionary Access Control...",
    "1.3.1.2": "AppArmor is a security mechanism and disabling it is not recommended.",
    "1.3.1.3": "Security configuration requirements vary from site to site...",
    "1.3.1.4": "Security configuration requirements vary from site to site...",
    
    # 1.6 Message of the Day
    "1.6.4": "If the /etc/motd file does not have the correct access configured...",
    "1.6.5": "If the /etc/issue file does not have the correct access configured...",
    "1.6.6": "If the /etc/issue.net file does not have the correct access configured...",
    
    # 2.4 Cron
    "2.4.1.2": "This file contains information on what system jobs are run by cron...",
    "2.4.1.3": "Granting write access to this directory for non-privileged users...",
    "2.4.1.4": "Granting write access to this directory for non-privileged users...",
    "2.4.1.5": "Granting write access to this directory for non-privileged users...",
    "2.4.1.6": "Granting write access to this directory for non-privileged users...",
    "2.4.1.7": "Granting write access to this directory for non-privileged users...",
    "2.4.1.8": "Granting write access to this directory for non-privileged users...",
    "2.4.1.9": "On many systems, only the system administrator is authorized to schedule cron jobs...",
    "2.4.2.1": "On many systems, only the system administrator is authorized to schedule at jobs...",
    
    # 5.1 SSH
    "5.1.1": "Configuration specifications for sshd need to be protected from unauthorized changes...",
    "5.1.2": "If an unauthorized user obtains the private SSH host key file, the host could be impersonated.",
    "5.1.3": "If a public host key file is modified by an unauthorized user, the SSH service may be compromised.",
    
    # 5.3 PAM
    "5.3.1.3": "Strong passwords reduce the risk of systems being hacked through brute force methods...",
    "5.3.2.1": "The system should only provide access after performing authentication of a user.",
    "5.3.2.2": "Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force...",
    "5.3.2.3": "Use of a unique, complex passwords helps to increase the time and resources required...",
    "5.3.2.4": "Use of a unique, complex passwords helps to increase the time and resources required...",
    "5.3.3.1.1": "Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force...",
    "5.3.3.1.2": "Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force...",
    "5.3.3.1.3": "Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force...",
    "5.3.3.2.2": "Strong passwords help protect systems from password attacks...",
    "5.3.3.3.1": "Requiring users not to reuse their passwords make it less likely that an attacker...",
    "5.3.3.4.1": "Using a strong password is essential to helping protect personal and sensitive information...",
    
    # 5.4 User Accounts
    "5.4.1.1": "The window of opportunity for an attacker to leverage compromised credentials...",
    "5.4.1.2": "Users may have favorite passwords that they like to use because they are easy to remember...",
    "5.4.1.3": "Providing an advance warning that a password will be expiring gives users time to think...",
    "5.4.1.4": "The SHA-512 and yescrypt algorithms provide a stronger hash than other algorithms...",
    "5.4.1.5": "Inactive accounts pose a threat to system security since the users are not logging in...",
    "5.4.2.1": "Any account with UID 0 has superuser privileges on the system...",
    "5.4.2.2": "Using GID 0 for the root account helps prevent root-owned files from accidentally...",
    "5.4.2.3": "Using GID 0 for the root group helps prevent root group owned files from accidentally...",
    "5.4.2.4": "Access to root should be secured at all times.",
    "5.4.2.7": "It is important to make sure that accounts that are not being used by regular users...",
    "5.4.2.8": "It is important to make sure that accounts that are not being used by regular users...",
    
    # 6.1 Logging
    "6.1.1.2": "It is important to ensure that log files have the correct permissions...",
    "6.1.2.4": "It is important to ensure that log files have the correct permissions...",
    "6.1.3.1": "It is important that log files have the correct permissions to ensure that sensitive data...",
    
    # 6.2 Audit
    "6.2.4.1": "It is important that log files have the correct permissions to ensure that sensitive data...",
    "6.2.4.2": "Access to audit records can reveal system and configuration data to attackers...",
    "6.2.4.3": "Access to audit records can reveal system and configuration data to attackers...",
    "6.2.4.4": "Audit information includes all information including: audit records, audit settings...",
    "6.2.4.5": "Access to the audit configuration files could allow unauthorized personnel...",
    "6.2.4.6": "Access to the audit configuration files could allow unauthorized personnel...",
    "6.2.4.7": "Access to the audit configuration files could allow unauthorized personnel...",
    "6.2.4.8": "Protecting audit information includes identifying and protecting the tools...",
    "6.2.4.9": "Protecting audit information includes identifying and protecting the tools...",
    "6.2.4.10": "Protecting audit information includes identifying and protecting the tools...",
    
    # 7.1 File Permissions
    "7.1.1": "It is critical to ensure that the /etc/passwd file is protected from unauthorized write access.",
    "7.1.2": "It is critical to ensure that the /etc/passwd- file is protected from unauthorized access.",
    "7.1.3": "The /etc/group file needs to be protected from unauthorized changes by non-privileged users.",
    "7.1.4": "It is critical to ensure that the /etc/group- file is protected from unauthorized access.",
    "7.1.5": "If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking...",
    "7.1.6": "If attackers can gain read access to the /etc/shadow- file, they can easily run a password cracking...",
    "7.1.7": "If attackers can gain read access to the /etc/gshadow file, they can easily run a password cracking...",
    "7.1.8": "If attackers can gain read access to the /etc/gshadow- file, they can easily run a password cracking...",
    "7.1.9": "It is critical to ensure that the /etc/shells file is protected from unauthorized access.",
    "7.1.10": "It is critical to ensure that /etc/security/opasswd is protected from unauthorized access.",
    "7.1.11": "Data in world-writable files can be modified and compromised by any user on the system...",
    "7.1.12": "A new user or group who is assigned a deleted user's user ID or group ID...",
    "7.1.13": "There are valid reasons for SUID and SGID programs, but it is important to identify...",
    "7.2.9": "Since the user is accountable for files stored in the user home directory...",
    
    # Additional checks
    "4.1.1": "A firewall is essential for controlling the incoming and outgoing network traffic based on predetermined security rules. Without a configured firewall, the system is vulnerable to unauthorized access and network attacks.",
}

# ==================== UTILITY FUNCTIONS ====================
def run_cmd(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        return e.output.decode('utf-8').strip()
    except Exception as e:
        return f"Error: {str(e)}"

def get_file_content(filepath):
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                return f.read()
        except:
            return None
    return None

def get_rationale(cis_id):
    return RATIONALE_DICT.get(cis_id, "Security best practice as per CIS Benchmark guidelines.")

def audit_check(cis_id, title, description, severity, check_func, fix_cmd):
    print(f"[*] Checking {cis_id}...", end=" ")
    try:
        status, actual_evidence = check_func()
    except Exception as e:
        status = "ERROR"
        actual_evidence = f"Script Error: {str(e)}"
    
    if status == "FAIL":
        print(f"\033[91m[FAIL]\033[0m")
    elif status == "PASS":
        print(f"\033[92m[PASS]\033[0m")
    elif status == "MANUAL":
        print(f"\033[93m[MANUAL]\033[0m")
    elif status == "SKIP":
        print(f"\033[94m[SKIP]\033[0m")
    else:
        print(f"\033[93m[{status}]\033[0m")
    
    results.append({
        "id": cis_id,
        "title": title,
        "description": description,
        "rationale": get_rationale(cis_id),
        "severity": severity,
        "status": status,
        "actual": actual_evidence,
        "remediation": fix_cmd
    })

def check_file_permission(filepath, expected_mode, expected_owner="root", expected_group="root"):
    try:
        stat_out = run_cmd(f"stat -Lc '%a %U %G' {filepath} 2>/dev/null")
        if not stat_out:
            return "MANUAL", f"File {filepath} does not exist or cannot be accessed"
        
        mode, owner, group = stat_out.split()
        mode_int = int(mode, 8)
        expected_int = int(expected_mode, 8)
        
        issues = []
        if mode_int > expected_int:
            issues.append(f"Mode {mode} > expected {expected_mode}")
        if owner != expected_owner:
            issues.append(f"Owner {owner} != expected {expected_owner}")
        if group != expected_group:
            issues.append(f"Group {group} != expected {expected_group}")
        
        if issues:
            return "FAIL", f"File: {filepath}\nIssues: {', '.join(issues)}"
        return "PASS", f"File: {filepath}\nMode: {mode}, Owner: {owner}, Group: {group}"
    except:
        return "ERROR", f"Error checking {filepath}"

def check_cron_dir_perms(directory, expected_mode="700"):
    if not os.path.exists(directory):
        return "PASS", f"Directory {directory} does not exist (cron may not be installed)"
    return check_file_permission(directory, expected_mode)

# ==================== CHECK FUNCTIONS - GROUPED BY CIS SECTIONS ====================

# --- Section 1.2 Package Management ---
def check_gpg_keys():
    apt_key_out = run_cmd("apt-key list 2>/dev/null | head -20")
    gpg_files = run_cmd("ls -la /etc/apt/trusted.gpg.d/ 2>/dev/null | wc -l")
    
    if "deprecated" in apt_key_out.lower() or int(gpg_files or 0) <= 1:
        return "FAIL", f"GPG keys may not be properly configured\napt-key output: {apt_key_out[:200]}\nGPG files: {gpg_files}"
    return "PASS", "GPG keys appear to be configured"

def check_package_repos():
    out = run_cmd("apt-cache policy")
    if "http" in out or "https" in out:
        return "PASS", "Package repositories configured"
    return "FAIL", "No valid repositories found"

def check_updates_installed():
    run_cmd("apt update > /dev/null 2>&1")
    out = run_cmd("apt -s upgrade 2>/dev/null | grep -E 'upgraded|installed'")
    
    if "0 upgraded" in out and "0 newly installed" in out:
        return "PASS", "All updates are installed"
    return "FAIL", f"Updates available:\n{out}"

# --- Section 1.3 AppArmor ---
def check_apparmor_installed():
    apparmor = run_cmd("dpkg-query -s apparmor 2>/dev/null | grep Status")
    apparmor_utils = run_cmd("dpkg-query -s apparmor-utils 2>/dev/null | grep Status")
    
    if "install ok installed" in apparmor and "install ok installed" in apparmor_utils:
        return "PASS", "AppArmor packages are installed"
    return "FAIL", f"AppArmor status: {apparmor}\nAppArmor-utils status: {apparmor_utils}"

def check_apparmor_enabled():
    out = run_cmd("grep '^\s*linux' /boot/grub/grub.cfg 2>/dev/null | grep -v 'apparmor=0' | wc -l")
    if int(out or 0) > 0:
        return "PASS", "AppArmor is enabled in GRUB"
    return "FAIL", "AppArmor may be disabled in GRUB configuration"

def check_apparmor_profiles():
    out = run_cmd("apparmor_status 2>/dev/null")
    if out and "profiles are loaded" in out and "0 profiles are in complain mode" not in out:
        return "PASS", "AppArmor profiles are loaded"
    return "MANUAL", "Check AppArmor profiles manually:\n" + (out[:500] if out else "No output")

def check_apparmor_enforcing():
    out = run_cmd("apparmor_status 2>/dev/null")
    if out and "profiles are in enforce mode" in out:
        profiles = re.search(r'(\d+) profiles are in enforce mode', out)
        if profiles and int(profiles.group(1)) > 0:
            return "PASS", "AppArmor profiles are in enforce mode"
    return "MANUAL", "Check AppArmor enforcing mode:\n" + (out[:500] if out else "No output")

# --- Section 1.6 MOTD ---
def check_motd():
    return check_file_permission("/etc/motd", "644")

def check_issue():
    return check_file_permission("/etc/issue", "644")

def check_issue_net():
    return check_file_permission("/etc/issue.net", "644")

# --- Section 2.4 Cron ---
def check_crontab_perms():
    return check_file_permission("/etc/crontab", "600")

def check_cron_hourly():
    return check_cron_dir_perms("/etc/cron.hourly")

def check_cron_daily():
    return check_cron_dir_perms("/etc/cron.daily")

def check_cron_weekly():
    return check_cron_dir_perms("/etc/cron.weekly")

def check_cron_monthly():
    return check_cron_dir_perms("/etc/cron.monthly")

def check_cron_yearly():
    return check_cron_dir_perms("/etc/cron.yearly")

def check_cron_d():
    return check_cron_dir_perms("/etc/cron.d")

def check_cron_allow():
    allow_check = check_file_permission("/etc/cron.allow", "640")
    deny_check = check_file_permission("/etc/cron.deny", "640")
    
    if "FAIL" in allow_check[0] or "FAIL" in deny_check[0]:
        return "FAIL", f"cron.allow: {allow_check[1]}\ncron.deny: {deny_check[1]}"
    return "PASS", "cron.allow and cron.deny permissions are correct"

def check_at_cron_restricted():
    allow_check = check_file_permission("/etc/at.allow", "640", "root", "daemon")
    deny_check = check_file_permission("/etc/at.deny", "640", "root", "daemon")
    
    if "FAIL" in allow_check[0] or "FAIL" in deny_check[0]:
        return "FAIL", f"at.allow: {allow_check[1]}\nat.deny: {deny_check[1]}"
    return "PASS", "at.allow and at.deny permissions are correct"

# --- Section 5.1 SSH ---
def check_sshd_config():
    return check_file_permission("/etc/ssh/sshd_config", "600")

def check_ssh_private_keys():
    keys = run_cmd("find /etc/ssh -name '*key' -type f 2>/dev/null")
    if not keys:
        return "PASS", "No SSH private keys found"
    
    issues = []
    for key in keys.split('\n'):
        if key and 'pub' not in key:
            check = check_file_permission(key.strip(), "600")
            if check[0] == "FAIL":
                issues.append(check[1])
    
    if issues:
        return "FAIL", "\n".join(issues[:5])
    return "PASS", "SSH private key permissions are correct"

def check_ssh_public_keys():
    keys = run_cmd("find /etc/ssh -name '*.pub' -type f 2>/dev/null")
    if not keys:
        return "PASS", "No SSH public keys found"
    
    issues = []
    for key in keys.split('\n'):
        if key:
            check = check_file_permission(key.strip(), "644")
            if check[0] == "FAIL":
                issues.append(check[1])
    
    if issues:
        return "FAIL", "\n".join(issues[:5])
    return "PASS", "SSH public key permissions are correct"

# --- Section 5.3 PAM ---
def check_pam_pwquality():
    out = run_cmd("dpkg-query -s libpam-pwquality 2>/dev/null | grep Status")
    if "install ok installed" in out:
        return "PASS", "libpam-pwquality is installed"
    return "FAIL", "libpam-pwquality is not installed"

def check_pam_unix():
    out = run_cmd("grep -l 'pam_unix.so' /etc/pam.d/* 2>/dev/null | wc -l")
    if int(out or 0) > 0:
        return "PASS", "pam_unix module is enabled"
    return "FAIL", "pam_unix module not found in PAM configuration"

def check_pam_faillock():
    out = run_cmd("grep -l 'pam_faillock.so' /etc/pam.d/* 2>/dev/null | wc -l")
    if int(out or 0) > 0:
        return "PASS", "pam_faillock module is enabled"
    return "FAIL", "pam_faillock module not found in PAM configuration"

def check_pam_pwquality_enabled():
    out = run_cmd("grep -P -- '\\bpam_pwquality\\.so\\b' /etc/pam.d/common-password")
    if out and "pam_pwquality.so" in out:
        return "PASS", "pam_pwquality module is enabled"
    return "FAIL", "pam_pwquality module is not enabled in /etc/pam.d/common-password"

def check_pam_pwhistory_enabled():
    out = run_cmd("grep -P -- '\\bpam_pwhistory\\.so\\b' /etc/pam.d/common-password")
    if out and "pam_pwhistory.so" in out:
        return "PASS", "pam_pwhistory module is enabled"
    return "FAIL", "pam_pwhistory module is not enabled in /etc/pam.d/common-password"

def check_password_lockout_configured():
    """CIS 5.3.3.1.1: Ensure password failed attempts lockout is configured (deny=1-5)"""
    deny_value = None
    
    # Kiểm tra trong /etc/security/faillock.conf
    if os.path.exists("/etc/security/faillock.conf"):
        with open("/etc/security/faillock.conf", 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('deny'):
                    try:
                        parts = line.split('=')
                        if len(parts) > 1:
                            deny_value = int(parts[1].strip())
                            break
                    except (ValueError, IndexError):
                        continue
    
    # Nếu không tìm thấy, thử tìm trong PAM
    if deny_value is None:
        out = run_cmd("grep -P -- 'pam_faillock\\.so.*deny=' /etc/pam.d/common-auth")
        if out:
            match = re.search(r'deny\s*=\s*(\d+)', out)
            if match:
                deny_value = int(match.group(1))
    
    if deny_value is not None:
        if 1 <= deny_value <= 5:
            return "PASS", f"Password lockout configured with deny={deny_value}"
        else:
            return "FAIL", f"Password lockout deny value is {deny_value}, should be between 1 and 5"
    else:
        return "FAIL", "Password failed attempts lockout not properly configured (deny not set)"

def check_password_unlock_time():
    """CIS 5.3.3.1.2: Ensure password unlock time is configured (0 or >=900)"""
    unlock_value = None
    
    # Kiểm tra trong /etc/security/faillock.conf
    if os.path.exists("/etc/security/faillock.conf"):
        with open("/etc/security/faillock.conf", 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('unlock_time'):
                    try:
                        parts = line.split('=')
                        if len(parts) > 1:
                            unlock_value = int(parts[1].strip())
                            break
                    except (ValueError, IndexError):
                        continue
    
    # Nếu không tìm thấy, thử tìm trong PAM
    if unlock_value is None:
        out = run_cmd("grep -P -- 'pam_faillock\\.so.*unlock_time=' /etc/pam.d/common-auth")
        if out:
            match = re.search(r'unlock_time\s*=\s*(\d+)', out)
            if match:
                unlock_value = int(match.group(1))
    
    if unlock_value is not None:
        # CIS chấp nhận 0 (never) hoặc >= 900 (15 phút)
        if unlock_value == 0 or unlock_value >= 900:
            return "PASS", f"Password unlock time configured: {unlock_value} seconds"
        else:
            return "FAIL", f"Password unlock time is {unlock_value} seconds, should be 0 (never) or >=900 seconds (15 minutes)"
    else:
        # Giá trị mặc định là 600
        return "MANUAL", "unlock_time not configured, default is 600 seconds. Check /etc/security/faillock.conf"

def check_password_history():
    out = run_cmd("grep -i 'even_deny_root' /etc/security/faillock.conf 2>/dev/null")
    if "even_deny_root" in out:
        return "PASS", "Root account is included in password lockout"
    return "MANUAL", "Check /etc/security/faillock.conf for even_deny_root setting"

def check_password_length():
    out = run_cmd("grep -i 'minlen' /etc/security/pwquality.conf 2>/dev/null")
    if "minlen" in out:
        match = re.search(r'minlen\s*=\s*(\d+)', out)
        if match and int(match.group(1)) >= 14:
            return "PASS", f"Minimum password length: {match.group(1)}"
    return "MANUAL", "Check /etc/security/pwquality.conf for minlen setting"

def check_password_history_remember():
    out = run_cmd("grep -P -- 'pam_pwhistory\\.so.*remember=' /etc/pam.d/common-password")
    if out:
        match = re.search(r'remember\s*=\s*(\d+)', out)
        if match and int(match.group(1)) >= 24:
            return "PASS", f"Password history remember configured: {out.strip()[:100]}"
        elif match:
            return "FAIL", f"Password history remember too low: {match.group(1)} (should be >=24)"
    
    return "MANUAL", "Password history remember not configured or check manually"

def check_pam_unix_nullok():
    out = run_cmd("grep -P -- 'pam_unix\\.so.*nullok' /etc/pam.d/common-password")
    if out:
        return "FAIL", f"nullok parameter found: {out.strip()[:100]}"
    
    auth_out = run_cmd("grep -P -- 'pam_unix\\.so.*nullok' /etc/pam.d/common-auth")
    if auth_out:
        return "FAIL", f"nullok parameter found in common-auth: {auth_out.strip()[:100]}"
    
    return "PASS", "pam_unix.so does not include nullok parameter"

# --- Section 5.4 User Accounts ---
def check_password_expiration():
    out = run_cmd("grep -i 'PASS_MAX_DAYS' /etc/login.defs 2>/dev/null")
    if "PASS_MAX_DAYS" in out:
        match = re.search(r'PASS_MAX_DAYS\s+(\d+)', out)
        if match and int(match.group(1)) <= 365:
            return "PASS", f"Password max days: {match.group(1)}"
    return "MANUAL", "Check /etc/login.defs for PASS_MAX_DAYS setting"

def check_minimum_password_days():
    """CIS 5.4.1.2: Ensure minimum password days is configured (>=1)"""
    min_days_value = None
    
    # Kiểm tra trong /etc/login.defs
    if os.path.exists("/etc/login.defs"):
        with open("/etc/login.defs", 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('PASS_MIN_DAYS'):
                    try:
                        parts = line.split()
                        if len(parts) > 1:
                            min_days_value = int(parts[1])
                            break
                    except (ValueError, IndexError):
                        continue
    
    # Kiểm tra từng user trong /etc/shadow (cột thứ 4)
    user_issues = []
    if os.path.exists("/etc/shadow"):
        with open("/etc/shadow", 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split(':')
                if len(parts) < 4:
                    continue
                
                username = parts[0]
                min_days_str = parts[3]
                
                if min_days_str:
                    try:
                        user_min_days = int(min_days_str)
                        if user_min_days < 1:
                            user_issues.append(f"User '{username}' has PASS_MIN_DAYS={user_min_days}")
                    except ValueError:
                        continue
    
    if min_days_value is not None:
        if min_days_value >= 1:
            if user_issues:
                return "FAIL", f"PASS_MIN_DAYS in /etc/login.defs is {min_days_value} (OK), but users with issues:\n" + "\n".join(user_issues[:5])
            return "PASS", f"PASS_MIN_DAYS is {min_days_value} (should be >=1)"
        else:
            return "FAIL", f"PASS_MIN_DAYS is {min_days_value} (should be >=1)"
    elif user_issues:
        return "FAIL", "Users with PASS_MIN_DAYS < 1:\n" + "\n".join(user_issues[:5])
    else:
        return "MANUAL", "PASS_MIN_DAYS not configured and no users found with invalid minimum days"

def check_password_warning_days():
    """CIS 5.4.1.3: Ensure password expiration warning days is configured (>=7)"""
    warn_days_value = None
    
    # Kiểm tra trong /etc/login.defs
    if os.path.exists("/etc/login.defs"):
        with open("/etc/login.defs", 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('PASS_WARN_AGE'):
                    try:
                        parts = line.split()
                        if len(parts) > 1:
                            warn_days_value = int(parts[1])
                            break
                    except (ValueError, IndexError):
                        continue
    
    # Kiểm tra từng user trong /etc/shadow (cột thứ 6)
    user_issues = []
    if os.path.exists("/etc/shadow"):
        with open("/etc/shadow", 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split(':')
                if len(parts) < 6:
                    continue
                
                username = parts[0]
                warn_days_str = parts[5]
                
                if warn_days_str:
                    try:
                        user_warn_days = int(warn_days_str)
                        if user_warn_days < 7:
                            user_issues.append(f"User '{username}' has PASS_WARN_AGE={user_warn_days}")
                    except ValueError:
                        continue
    
    if warn_days_value is not None:
        if warn_days_value >= 7:
            if user_issues:
                return "FAIL", f"PASS_WARN_AGE in /etc/login.defs is {warn_days_value} (OK), but users with issues:\n" + "\n".join(user_issues[:5])
            return "PASS", f"PASS_WARN_AGE is {warn_days_value} (should be >=7)"
        else:
            return "FAIL", f"PASS_WARN_AGE is {warn_days_value} (should be >=7)"
    elif user_issues:
        return "FAIL", "Users with PASS_WARN_AGE < 7:\n" + "\n".join(user_issues[:5])
    else:
        return "MANUAL", "PASS_WARN_AGE not configured and no users found with invalid warning days"

def check_password_hashing_algorithm():
    out = run_cmd("grep -i 'ENCRYPT_METHOD' /etc/login.defs 2>/dev/null")
    if "ENCRYPT_METHOD SHA512" in out or "ENCRYPT_METHOD YESCRYPT" in out:
        return "PASS", "Strong password hashing algorithm is configured"
    return "MANUAL", "Check /etc/login.defs for ENCRYPT_METHOD setting"

def check_inactive_password_lock():
    """CIS 5.4.1.5: Ensure inactive password lock is configured (<=45 days)"""
    inactive_value = None
    
    # Kiểm tra giá trị mặc định
    out = run_cmd("useradd -D | grep INACTIVE")
    if out:
        match = re.search(r'INACTIVE=(\d+)', out)
        if match:
            inactive_value = int(match.group(1))
    
    # Kiểm tra từng user trong /etc/shadow (cột thứ 7)
    user_issues = []
    if os.path.exists("/etc/shadow"):
        with open("/etc/shadow", 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split(':')
                if len(parts) < 8:
                    continue
                
                username = parts[0]
                inactive_str = parts[6]
                
                if inactive_str:
                    try:
                        user_inactive = int(inactive_str)
                        if user_inactive > 45:
                            user_issues.append(f"User '{username}' has INACTIVE={user_inactive} days")
                        elif user_inactive == -1:
                            user_issues.append(f"User '{username}' has INACTIVE=-1 (disabled)")
                    except ValueError:
                        continue
    
    if inactive_value is not None:
        if inactive_value <= 45 and inactive_value >= 0:
            if user_issues:
                return "FAIL", f"Default INACTIVE is {inactive_value} days (OK), but users with issues:\n" + "\n".join(user_issues[:5])
            return "PASS", f"Default inactive lock is {inactive_value} days (should be <=45)"
        elif inactive_value == -1:
            return "FAIL", f"Default INACTIVE is -1 (disabled)"
        else:
            return "FAIL", f"Default inactive lock is {inactive_value} days (should be <=45)"
    elif user_issues:
        return "FAIL", "Users with inactive password lock issues:\n" + "\n".join(user_issues[:5])
    else:
        return "MANUAL", "INACTIVE not configured and no users found with invalid inactive days"

def check_last_password_change():
    """CIS 5.4.1.6: Ensure all users last password change date is in the past"""
    try:
        issues = []
        
        # Lấy số ngày hiện tại tính từ 1970-01-01
        current_time = time.time()
        current_days = int(current_time / 86400)  # 86400 giây = 1 ngày
        
        with open('/etc/shadow', 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split(':')
                if len(parts) < 3:
                    continue
                
                username = parts[0]
                password = parts[1]
                last_change_str = parts[2]
                
                # Bỏ qua tài khoản không có mật khẩu
                if password in ['', '*', '!', '!!']:
                    continue
                
                # Bỏ qua nếu trường last_change trống
                if not last_change_str:
                    continue
                
                try:
                    last_change_days = int(last_change_str)
                    
                    # Kiểm tra nếu ngày đổi mật khẩu trong tương lai
                    if last_change_days > current_days:
                        issues.append(f"User '{username}' has last password change in the future (day {last_change_days}, current: {current_days})")
                except ValueError:
                    continue
        
        if issues:
            return "FAIL", "\n".join(issues[:10])
        else:
            return "PASS", "All users have last password change date in the past"
            
    except FileNotFoundError:
        return "ERROR", "/etc/shadow file not found"
    except PermissionError:
        return "ERROR", "Permission denied when reading /etc/shadow"
    except Exception as e:
        return "ERROR", f"Error checking last password change: {str(e)}"

def check_only_root_uid0():
    out = run_cmd("awk -F: '($3 == 0) { print $1 }' /etc/passwd")
    users = [u.strip() for u in out.split('\n') if u.strip()]
    
    if len(users) == 1 and users[0] == 'root':
        return "PASS", "Only root has UID 0"
    return "FAIL", f"Accounts with UID 0: {', '.join(users)}"

def check_only_root_gid0():
    out = run_cmd("awk -F: '($4 == \"0\") { print $1\":\"$4 }' /etc/passwd")
    users = [line.strip() for line in out.split('\n') if line.strip()]
    
    allowed_users = ['root:0', 'sync:0', 'shutdown:0', 'halt:0', 'operator:0']
    for user in users:
        if user not in allowed_users:
            return "FAIL", f"Non-root account with GID 0: {user}"
    
    return "PASS", "Only root (and allowed system accounts) have GID 0 as primary GID"

def check_only_root_group_gid0():
    out = run_cmd("awk -F: '($3 == \"0\") { print $1\":\"$3 }' /etc/group")
    groups = [line.strip() for line in out.split('\n') if line.strip()]
    
    if len(groups) == 1 and groups[0] == 'root:0':
        return "PASS", "Only root group has GID 0"
    elif len(groups) > 1:
        return "FAIL", f"Multiple groups with GID 0: {', '.join(groups)}"
    
    return "FAIL", "No group with GID 0 found (root group missing?)"

def check_root_password():
    out = run_cmd("passwd -S root 2>/dev/null")
    if "Password set" in out or "Password locked" in out:
        return "PASS", "Root password is set or locked"
    return "FAIL", "Root password may not be properly secured"

def check_system_accounts_shell():
    out = run_cmd("awk -F: '$1 !~ /^(root|halt|sync|shutdown)$/ && $3 < 1000 && $7 !~ /nologin/ {print $1}' /etc/passwd")
    accounts = [a.strip() for a in out.split('\n') if a.strip()]
    
    if not accounts:
        return "PASS", "System accounts have nologin shell"
    return "FAIL", f"System accounts with login shell: {', '.join(accounts)}"

def check_accounts_without_shell_locked():
    out = run_cmd("awk -F: '$1 != \"root\" && $7 !~ /nologin|false/ {print $1}' /etc/passwd")
    accounts = [acc.strip() for acc in out.split('\n') if acc.strip()]
    
    issues = []
    for account in accounts:
        status = run_cmd(f"passwd -S {account} 2>/dev/null | awk '{{print $2}}'")
        if status and "L" not in status:
            issues.append(f"Account '{account}' has invalid shell but not locked")
    
    if issues:
        return "FAIL", f"Issues found:\n" + "\n".join(issues[:5])
    
    return "PASS", "Accounts without valid login shell are properly locked"

# --- Section 6.1 Logging ---
def check_journald_logs():
    out = run_cmd("stat -c '%a' /var/log/journal 2>/dev/null || echo '750'")
    if out and int(out) <= 750:
        return "PASS", f"Journal directory permissions: {out}"
    return "MANUAL", f"Check /var/log/journal permissions (current: {out})"

def check_rsyslog_perms():
    out = run_cmd("grep -i '\\$FileCreateMode' /etc/rsyslog.conf 2>/dev/null")
    if "0640" in out or "0600" in out:
        return "PASS", "rsyslog FileCreateMode is configured"
    return "MANUAL", "Check /etc/rsyslog.conf for $FileCreateMode setting"

def check_log_files_perms():
    log_files = [
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/kern.log",
        "/var/log/secure"
    ]
    
    issues = []
    for log_file in log_files:
        if os.path.exists(log_file):
            check = check_file_permission(log_file, "640", "syslog", "adm")
            if check[0] == "FAIL":
                issues.append(f"{log_file}: {check[1]}")
    
    if issues:
        return "MANUAL", "Log file permission issues:\n" + "\n".join(issues[:3])
    return "PASS", "Log file permissions appear correct"

# --- Section 6.2 Audit ---
def check_audit_log_perms():
    audit_status = run_cmd("systemctl is-active auditd 2>/dev/null || echo 'inactive'")
    if "inactive" in audit_status:
        return "SKIP", "auditd is not active"
    
    out = run_cmd("stat -c '%a' /var/log/audit/ 2>/dev/null")
    if out and int(out) <= 750:
        return "PASS", f"Audit log directory permissions: {out}"
    return "MANUAL", f"Check /var/log/audit/ permissions (current: {out})"

def check_audit_log_owner():
    if not os.path.exists("/etc/audit/auditd.conf"):
        return "SKIP", "auditd not installed or configured"
    
    log_dir = run_cmd("awk -F= '/^\\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs dirname 2>/dev/null")
    if not log_dir or not os.path.exists(log_dir):
        return "MANUAL", "Cannot determine audit log directory"
    
    out = run_cmd(f"find {log_dir} -maxdepth 1 -type f ! -user root 2>/dev/null | wc -l")
    if out and int(out) > 0:
        files = run_cmd(f"find {log_dir} -maxdepth 1 -type f ! -user root 2>/dev/null | head -5")
        return "FAIL", f"Audit log files not owned by root:\n{files}"
    
    return "PASS", "All audit log files are owned by root"

def check_audit_log_group():
    if not os.path.exists("/etc/audit/auditd.conf"):
        return "SKIP", "auditd not installed or configured"
    
    log_dir = run_cmd("awk -F= '/^\\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs dirname 2>/dev/null")
    if not log_dir or not os.path.exists(log_dir):
        return "MANUAL", "Cannot determine audit log directory"
    
    config = run_cmd("grep -Pi '^\\h*log_group\\h*=' /etc/audit/auditd.conf")
    if config and ('adm' in config.lower() or 'root' in config.lower()):
        out = run_cmd(f"find {log_dir} -maxdepth 1 -type f ! -group adm ! -group root 2>/dev/null | wc -l")
        if out and int(out) > 0:
            files = run_cmd(f"find {log_dir} -maxdepth 1 -type f ! -group adm ! -group root 2>/dev/null | head -5")
            return "FAIL", f"Audit log files not owned by adm or root group:\n{files}"
        return "PASS", "Audit log files group ownership is correct"
    
    return "MANUAL", "log_group not properly configured in /etc/audit/auditd.conf"

def check_audit_log_dir_mode():
    if not os.path.exists("/etc/audit/auditd.conf"):
        return "SKIP", "auditd not installed or configured"
    
    log_dir = run_cmd("awk -F= '/^\\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs dirname 2>/dev/null")
    if not log_dir or not os.path.exists(log_dir):
        return "MANUAL", "Cannot determine audit log directory"
    
    mode = run_cmd(f"stat -c '%a' {log_dir} 2>/dev/null")
    if mode and int(mode) <= 750:
        return "PASS", f"Audit log directory mode: {mode}"
    
    return "FAIL", f"Audit log directory mode too permissive: {mode} (should be 750 or less)"

def check_audit_config_mode():
    if not os.path.exists("/etc/audit"):
        return "SKIP", "auditd not installed"
    
    out = run_cmd("find /etc/audit -type f \\( -name '*.conf' -o -name '*.rules' \\) -perm /0137 2>/dev/null | wc -l")
    if out and int(out) > 0:
        files = run_cmd("find /etc/audit -type f \\( -name '*.conf' -o -name '*.rules' \\) -perm /0137 2>/dev/null | head -5")
        return "FAIL", f"Audit config files with permissive permissions:\n{files}"
    
    return "PASS", "Audit configuration files have proper permissions (0640 or more restrictive)"

def check_audit_config_owner():
    if not os.path.exists("/etc/audit"):
        return "SKIP", "auditd not installed"
    
    out = run_cmd("find /etc/audit -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -user root 2>/dev/null | wc -l")
    if out and int(out) > 0:
        files = run_cmd("find /etc/audit -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -user root 2>/dev/null | head -5")
        return "FAIL", f"Audit config files not owned by root:\n{files}"
    
    return "PASS", "All audit configuration files are owned by root"

def check_audit_config_group():
    if not os.path.exists("/etc/audit"):
        return "SKIP", "auditd not installed"
    
    out = run_cmd("find /etc/audit -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -group root 2>/dev/null | wc -l")
    if out and int(out) > 0:
        files = run_cmd("find /etc/audit -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -group root 2>/dev/null | head -5")
        return "FAIL", f"Audit config files not owned by root group:\n{files}"
    
    return "PASS", "All audit configuration files are owned by root group"

def check_audit_tools_mode():
    audit_tools = [
        "/sbin/auditctl",
        "/sbin/aureport", 
        "/sbin/ausearch",
        "/sbin/autrace",
        "/sbin/auditd",
        "/sbin/augenrules"
    ]
    
    issues = []
    for tool in audit_tools:
        if os.path.exists(tool):
            mode = run_cmd(f"stat -c '%a' {tool} 2>/dev/null")
            if mode and int(mode) > 755:
                issues.append(f"{tool}: mode {mode} (should be 755 or less)")
    
    if issues:
        return "FAIL", "Audit tools with permissive permissions:\n" + "\n".join(issues[:5])
    return "PASS", "Audit tools have proper permissions (755 or more restrictive)"

def check_audit_tools_owner():
    audit_tools = [
        "/sbin/auditctl",
        "/sbin/aureport",
        "/sbin/ausearch",
        "/sbin/autrace",
        "/sbin/auditd",
        "/sbin/augenrules"
    ]
    
    issues = []
    for tool in audit_tools:
        if os.path.exists(tool):
            owner = run_cmd(f"stat -c '%U' {tool} 2>/dev/null")
            if owner and owner != "root":
                issues.append(f"{tool}: owned by {owner} (should be root)")
    
    if issues:
        return "FAIL", "Audit tools not owned by root:\n" + "\n".join(issues[:5])
    return "PASS", "All audit tools are owned by root"

def check_audit_tools_group():
    audit_tools = [
        "/sbin/auditctl",
        "/sbin/aureport",
        "/sbin/ausearch",
        "/sbin/autrace",
        "/sbin/auditd",
        "/sbin/augenrules"
    ]
    
    issues = []
    for tool in audit_tools:
        if os.path.exists(tool):
            group = run_cmd(f"stat -c '%G' {tool} 2>/dev/null")
            if group and group != "root":
                issues.append(f"{tool}: group owned by {group} (should be root)")
    
    if issues:
        return "FAIL", "Audit tools not owned by root group:\n" + "\n".join(issues[:5])
    return "PASS", "All audit tools are owned by root group"

# --- Section 7.1 File Permissions ---
def check_passwd_perms():
    return check_file_permission("/etc/passwd", "644")

def check_passwd_backup_perms():
    return check_file_permission("/etc/passwd-", "644")

def check_group_perms():
    return check_file_permission("/etc/group", "644")

def check_group_backup_perms():
    return check_file_permission("/etc/group-", "644")

def check_shadow_perms():
    return check_file_permission("/etc/shadow", "640", "root", "shadow")

def check_shadow_backup_perms():
    return check_file_permission("/etc/shadow-", "640", "root", "shadow")

def check_gshadow_perms():
    return check_file_permission("/etc/gshadow", "640", "root", "shadow")

def check_gshadow_backup_perms():
    return check_file_permission("/etc/gshadow-", "640", "root", "shadow")

def check_shells_perms():
    return check_file_permission("/etc/shells", "644")

def check_opasswd_perms():
    files_to_check = ["/etc/security/opasswd", "/etc/security/opasswd.old"]
    
    issues = []
    for filepath in files_to_check:
        if os.path.exists(filepath):
            check = check_file_permission(filepath, "600")
            if check[0] == "FAIL":
                issues.append(f"{filepath}: {check[1]}")
    
    if issues:
        return "FAIL", "\n".join(issues)
    
    return "PASS", "/etc/security/opasswd files have proper permissions (600 or not present)"

def check_world_writable():
    files = run_cmd("find / -xdev -type f -perm -0002 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -10")
    dirs = run_cmd("find / -xdev -type d -perm -0002 ! -perm -1000 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -10")
    
    issues = []
    if files:
        file_list = files.split('\n')
        file_count = len([f for f in file_list if f.strip()])
        if file_count > 0:
            issues.append(f"World-writable files found: {file_count}")
    if dirs:
        dir_list = dirs.split('\n')
        dir_count = len([d for d in dir_list if d.strip()])
        if dir_count > 0:
            issues.append(f"World-writable directories without sticky bit: {dir_count}")
    
    if issues:
        return "MANUAL", "Check world-writable objects:\n" + "\n".join(issues)
    return "PASS", "No insecure world-writable objects found"

def check_unowned_files():
    files = run_cmd("find / -xdev -nouser -o -nogroup 2>/dev/null | head -5")
    if files:
        file_list = files.split('\n')
        file_count = len([f for f in file_list if f.strip()])
        if file_count > 0:
            return "MANUAL", f"Found {file_count} unowned files/groups:\n{files[:500]}"
    return "PASS", "No unowned files or directories"

def check_suid_sgid():
    suid = run_cmd("find / -xdev -type f -perm -4000 2>/dev/null | wc -l")
    sgid = run_cmd("find / -xdev -type f -perm -2000 2>/dev/null | wc -l")
    
    suid_count = int(suid or 0)
    sgid_count = int(sgid or 0)
    
    if suid_count > 50 or sgid_count > 50:
        return "MANUAL", f"SUID files: {suid_count}, SGID files: {sgid_count}. Review manually."
    return "PASS", f"SUID files: {suid_count}, SGID files: {sgid_count}"

def check_home_dirs():
    users = run_cmd("awk -F: '$3 >= 1000 && $7 !~ /nologin/ {print $1 \":\" $6}' /etc/passwd")
    issues = []
    
    for line in users.split('\n'):
        if ':' in line:
            user, home = line.split(':', 1)
            if not os.path.exists(home):
                issues.append(f"User {user}: home directory {home} does not exist")
            else:
                stat = run_cmd(f"stat -c '%U %a' {home} 2>/dev/null")
                if stat:
                    owner, mode = stat.split()
                    if owner != user:
                        issues.append(f"User {user}: home owned by {owner}")
                    if int(mode, 8) & 0o022:
                        issues.append(f"User {user}: home is world/group writable")
    
    if issues:
        return "MANUAL", "Home directory issues:\n" + "\n".join(issues[:5])
    return "PASS", "User home directories are properly configured"

# --- Section 4.1.1 Firewall ---
def check_ufw_status():
    # Kiểm tra UFW có được cài đặt không
    install_check = run_cmd("dpkg-query -W -f='${Status}' ufw 2>/dev/null | grep -o 'installed'")
    if install_check != 'installed':
        return "FAIL", "UFW is not installed"
    
    # Kiểm tra trạng thái UFW
    out = run_cmd("ufw status 2>/dev/null")
    if "Status: active" in out:
        return "PASS", "UFW is installed and active"
    return "FAIL", "UFW is installed but not active"

# ==================== MAIN EXECUTION ====================

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: Run as root (sudo python3 ubuntu_cis_audit.py)")
        exit(1)
    
    print("=" * 60)
    print("CIS Ubuntu 22.04 Security Audit - COMPLETE CHECKLIST")
    print("=" * 60)
    
    checks = [
        # 1.2 Package Management
        ("1.2.1.1", "GPG Keys Configuration", "Verify GPG keys are configured for package manager", "Medium", check_gpg_keys, "Configure GPG keys in /etc/apt/trusted.gpg.d/"),
        ("1.2.1.2", "Package Repository Configuration", "Verify package repositories are correctly configured", "Medium", check_package_repos, "Configure repositories in /etc/apt/sources.list"),
        ("1.2.2.1", "System Updates", "Ensure updates and security patches are installed", "High", check_updates_installed, "Run: apt update && apt upgrade"),
        
        # 1.3 AppArmor
        ("1.3.1.1", "AppArmor Installation", "Ensure AppArmor packages are installed", "High", check_apparmor_installed, "apt install apparmor apparmor-utils"),
        ("1.3.1.2", "AppArmor Enablement", "Ensure AppArmor is enabled in GRUB", "High", check_apparmor_enabled, "Edit /etc/default/grub to enable AppArmor"),
        ("1.3.1.3", "AppArmor Profiles", "Ensure all AppArmor profiles are loaded", "Medium", check_apparmor_profiles, "Check apparmor_status and configure profiles"),
        ("1.3.1.4", "AppArmor Enforcement", "Ensure AppArmor profiles are enforcing", "Medium", check_apparmor_enforcing, "Set profiles to enforce mode: aa-enforce"),
        
        # 1.6 MOTD
        ("1.6.4", "/etc/motd Permissions", "Ensure access to /etc/motd is configured", "Low", check_motd, "chmod 644 /etc/motd && chown root:root /etc/motd"),
        ("1.6.5", "/etc/issue Permissions", "Ensure access to /etc/issue is configured", "Low", check_issue, "chmod 644 /etc/issue && chown root:root /etc/issue"),
        ("1.6.6", "/etc/issue.net Permissions", "Ensure access to /etc/issue.net is configured", "Low", check_issue_net, "chmod 644 /etc/issue.net && chown root:root /etc/issue.net"),
        
        # 2.4 Cron
        ("2.4.1.2", "/etc/crontab Permissions", "Ensure access to /etc/crontab is configured", "Medium", check_crontab_perms, "chmod 600 /etc/crontab && chown root:root /etc/crontab"),
        ("2.4.1.3", "/etc/cron.hourly Permissions", "Ensure access to /etc/cron.hourly is configured", "Medium", check_cron_hourly, "chmod 700 /etc/cron.hourly && chown root:root /etc/cron.hourly"),
        ("2.4.1.4", "/etc/cron.daily Permissions", "Ensure access to /etc/cron.daily is configured", "Medium", check_cron_daily, "chmod 700 /etc/cron.daily && chown root:root /etc/cron.daily"),
        ("2.4.1.5", "/etc/cron.weekly Permissions", "Ensure access to /etc/cron.weekly is configured", "Medium", check_cron_weekly, "chmod 700 /etc/cron.weekly && chown root:root /etc/cron.weekly"),
        ("2.4.1.6", "/etc/cron.monthly Permissions", "Ensure access to /etc/cron.monthly is configured", "Medium", check_cron_monthly, "chmod 700 /etc/cron.monthly && chown root:root /etc/cron.monthly"),
        ("2.4.1.7", "/etc/cron.yearly Permissions", "Ensure access to /etc/cron.yearly is configured", "Medium", check_cron_yearly, "chmod 700 /etc/cron.yearly && chown root:root /etc/cron.yearly"),
        ("2.4.1.8", "/etc/cron.d Permissions", "Ensure access to /etc/cron.d is configured", "Medium", check_cron_d, "chmod 700 /etc/cron.d && chown root:root /etc/cron.d"),
        ("2.4.1.9", "cron.allow/cron.deny", "Ensure access to crontab is configured", "Medium", check_cron_allow, "chmod 640 /etc/cron.allow /etc/cron.deny"),
        ("2.4.2.1", "at/cron Restricted", "Ensure access to at is configured", "Medium", check_at_cron_restricted, "chmod 640 /etc/at.allow /etc/at.deny"),
        
        # 5.1 SSH
        ("5.1.1", "SSHD Config Permissions", "Ensure access to /etc/ssh/sshd_config is configured", "High", check_sshd_config, "chmod 600 /etc/ssh/sshd_config"),
        ("5.1.2", "SSH Private Key Permissions", "Ensure access to SSH private host key files is configured", "High", check_ssh_private_keys, "chmod 600 /etc/ssh/*key"),
        ("5.1.3", "SSH Public Key Permissions", "Ensure access to SSH public host key files is configured", "Medium", check_ssh_public_keys, "chmod 644 /etc/ssh/*.pub"),
        
        # 5.3 PAM
        ("5.3.1.3", "PAM PWQuality", "Ensure latest version of libpam-pwquality is installed", "Medium", check_pam_pwquality, "apt install libpam-pwquality"),
        ("5.3.2.1", "PAM Unix Module", "Ensure pam_unix module is enabled", "Medium", check_pam_unix, "Enable pam_unix in PAM configuration"),
        ("5.3.2.2", "PAM Faillock Module", "Ensure pam_faillock module is enabled", "Medium", check_pam_faillock, "Enable pam_faillock in PAM configuration"),
        ("5.3.2.3", "PAM PWQuality Module", "Ensure pam_pwquality module is enabled", "Medium", check_pam_pwquality_enabled, "Enable pam_pwquality in /etc/pam.d/common-password"),
        ("5.3.2.4", "PAM PWHistory Module", "Ensure pam_pwhistory module is enabled", "Medium", check_pam_pwhistory_enabled, "Enable pam_pwhistory in /etc/pam.d/common-password"),
        ("5.3.3.1.1", "Password Lockout", "Ensure password failed attempts lockout is configured", "High", check_password_lockout_configured, "Configure deny=1-5 in /etc/security/faillock.conf"),
        ("5.3.3.1.2", "Password Unlock Time", "Ensure password unlock time is configured", "Medium", check_password_unlock_time, "Configure unlock_time=0 or >=900 in /etc/security/faillock.conf"),
        ("5.3.3.1.3", "Password Lockout Root", "Ensure password lockout includes root account", "High", check_password_history, "Add 'even_deny_root' to /etc/security/faillock.conf"),
        ("5.3.3.2.2", "Password Length", "Ensure minimum password length is configured", "Medium", check_password_length, "Set 'minlen = 14' in /etc/security/pwquality.conf"),
        ("5.3.3.3.1", "Password History", "Ensure password history remember is configured", "Medium", check_password_history_remember, "Set remember=24 in pam_pwhistory configuration"),
        ("5.3.3.4.1", "PAM Unix Nullok", "Ensure pam_unix does not include nullok", "High", check_pam_unix_nullok, "Remove nullok parameter from pam_unix.so lines"),
        
        # 5.4 User Accounts
        ("5.4.1.1", "Password Expiration", "Ensure password expiration is configured", "Medium", check_password_expiration, "Set PASS_MAX_DAYS in /etc/login.defs"),
        ("5.4.1.2", "Minimum Password Days", "Ensure minimum password days is configured", "Medium", check_minimum_password_days, "Set PASS_MIN_DAYS >=1 in /etc/login.defs"),
        ("5.4.1.3", "Password Warning Days", "Ensure password expiration warning days is configured", "Low", check_password_warning_days, "Set PASS_WARN_AGE >=7 in /etc/login.defs"),
        ("5.4.1.4", "Password Hashing", "Ensure strong password hashing algorithm is configured", "High", check_password_hashing_algorithm, "Set ENCRYPT_METHOD to SHA512 or YESCRYPT in /etc/login.defs"),
        ("5.4.1.5", "Inactive Password Lock", "Ensure inactive password lock is configured", "Medium", check_inactive_password_lock, "Set INACTIVE <=45 days in useradd defaults"),
        ("5.4.1.6", "Last Password Change", "Ensure all users last password change date is in the past", "Low", check_last_password_change, "Check and correct password change dates with 'chage -d' command"),
        
        ("5.4.2.1", "UID 0 Accounts", "Ensure root is the only UID 0 account", "Critical", check_only_root_uid0, "Remove or modify non-root accounts with UID 0"),
        ("5.4.2.2", "GID 0 Accounts", "Ensure root is the only GID 0 account", "High", check_only_root_gid0, "Change GID of non-root accounts with GID 0"),
        ("5.4.2.3", "GID 0 Groups", "Ensure group root is the only GID 0 group", "High", check_only_root_group_gid0, "Remove or modify non-root groups with GID 0"),
        ("5.4.2.4", "Root Account Access", "Ensure root account access is controlled", "Critical", check_root_password, "Set or lock root password: passwd root or usermod -L root"),
        ("5.4.2.7", "System Account Shells", "Ensure system accounts do not have valid login shell", "Medium", check_system_accounts_shell, "Set shell to /usr/sbin/nologin for system accounts"),
        ("5.4.2.8", "Accounts Without Shell Locked", "Ensure accounts without a valid login shell are locked", "Medium", check_accounts_without_shell_locked, "Lock accounts without valid shells: usermod -L <user>"),
        
        # 6.1 Logging
        ("6.1.1.2", "Journald Log Access", "Ensure journald log file access is configured", "Medium", check_journald_logs, "Set journal directory permissions to 750"),
        ("6.1.2.4", "Rsyslog Permissions", "Ensure rsyslog log file creation mode is configured", "Medium", check_rsyslog_perms, "Set $FileCreateMode 0640 in rsyslog.conf"),
        ("6.1.3.1", "Log File Permissions", "Ensure access to all logfiles has been configured", "Medium", check_log_files_perms, "Set log file permissions to 640 and owner to syslog:adm"),
        
        # 6.2 Audit
        ("6.2.4.1", "Audit Log Permissions", "Ensure audit log files mode is configured", "Medium", check_audit_log_perms, "Set audit log directory permissions to 750"),
        ("6.2.4.2", "Audit Log Owner", "Ensure audit log files owner is configured", "Medium", check_audit_log_owner, "chown root /var/log/audit/*"),
        ("6.2.4.3", "Audit Log Group", "Ensure audit log files group owner is configured", "Medium", check_audit_log_group, "chgrp adm /var/log/audit/* and set log_group=adm in auditd.conf"),
        ("6.2.4.4", "Audit Log Directory Mode", "Ensure the audit log file directory mode is configured", "Medium", check_audit_log_dir_mode, "chmod 750 /var/log/audit/"),
        ("6.2.4.5", "Audit Config Files Mode", "Ensure audit configuration files mode is configured", "Medium", check_audit_config_mode, "chmod 640 /etc/audit/*.conf /etc/audit/*.rules"),
        ("6.2.4.6", "Audit Config Files Owner", "Ensure audit configuration files owner is configured", "Medium", check_audit_config_owner, "chown root /etc/audit/*.conf /etc/audit/*.rules"),
        ("6.2.4.7", "Audit Config Files Group", "Ensure audit configuration files group owner is configured", "Medium", check_audit_config_group, "chgrp root /etc/audit/*.conf /etc/audit/*.rules"),
        ("6.2.4.8", "Audit Tools Mode", "Ensure audit tools mode is configured", "Medium", check_audit_tools_mode, "chmod 755 /sbin/audit*"),
        ("6.2.4.9", "Audit Tools Owner", "Ensure audit tools owner is configured", "Medium", check_audit_tools_owner, "chown root /sbin/audit*"),
        ("6.2.4.10", "Audit Tools Group", "Ensure audit tools group owner is configured", "Medium", check_audit_tools_group, "chgrp root /sbin/audit*"),
        
        # 7.1 File Permissions
        ("7.1.1", "/etc/passwd Permissions", "Ensure access to /etc/passwd is configured", "Medium", check_passwd_perms, "chmod 644 /etc/passwd"),
        ("7.1.2", "/etc/passwd- Permissions", "Ensure access to /etc/passwd- is configured", "Medium", check_passwd_backup_perms, "chmod 644 /etc/passwd-"),
        ("7.1.3", "/etc/group Permissions", "Ensure access to /etc/group is configured", "Medium", check_group_perms, "chmod 644 /etc/group"),
        ("7.1.4", "/etc/group- Permissions", "Ensure access to /etc/group- is configured", "Medium", check_group_backup_perms, "chmod 644 /etc/group-"),
        ("7.1.5", "/etc/shadow Permissions", "Ensure access to /etc/shadow is configured", "High", check_shadow_perms, "chmod 640 /etc/shadow && chown root:shadow /etc/shadow"),
        ("7.1.6", "/etc/shadow- Permissions", "Ensure access to /etc/shadow- is configured", "High", check_shadow_backup_perms, "chmod 640 /etc/shadow- && chown root:shadow /etc/shadow-"),
        ("7.1.7", "/etc/gshadow Permissions", "Ensure access to /etc/gshadow is configured", "High", check_gshadow_perms, "chmod 640 /etc/gshadow && chown root:shadow /etc/gshadow"),
        ("7.1.8", "/etc/gshadow- Permissions", "Ensure access to /etc/gshadow- is configured", "High", check_gshadow_backup_perms, "chmod 640 /etc/gshadow- && chown root:shadow /etc/gshadow-"),
        ("7.1.9", "/etc/shells Permissions", "Ensure access to /etc/shells is configured", "Low", check_shells_perms, "chmod 644 /etc/shells"),
        ("7.1.10", "/etc/security/opasswd", "Ensure access to /etc/security/opasswd is configured", "Medium", check_opasswd_perms, "chmod 600 /etc/security/opasswd*"),
        ("7.1.11", "World Writable Files", "Ensure world writable files and directories are secured", "Medium", check_world_writable, "Remove world-writable permissions or set sticky bit"),
        ("7.1.12", "Unowned Files", "Ensure no files or directories without owner/group exist", "Low", check_unowned_files, "Find and fix unowned files"),
        ("7.1.13", "SUID/SGID Files", "Ensure SUID and SGID files are reviewed", "Medium", check_suid_sgid, "Review SUID/SGID files for legitimacy"),
        ("7.2.9", "Home Directories", "Ensure local interactive user home directories are configured", "Medium", check_home_dirs, "Create and secure user home directories"),
        ("7.2.10", "User Dot Files", "Ensure local interactive user dot files access is configured", "Medium", lambda: ("MANUAL", "Check .bash_history, .netrc, .forward, .rhosts files"), "Secure dot files in user home directories"),
        
        # 4.1 Firewall Configuration
        ("4.1.1", "UFW Firewall", "Ensure Uncomplicated Firewall (UFW) is installed and enabled", "High", check_ufw_status, "apt install ufw && ufw enable"),
    ]
    
    for cis_id, title, description, severity, check_func, fix_cmd in checks:
        audit_check(cis_id, title, description, severity, check_func, fix_cmd)
    
    print("\n" + "=" * 60)
    print("[+] Generating Report...")
    
    try:
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('template.html')
        
        total_checks = len(results)
        passed_checks = len([x for x in results if x['status'] == 'PASS'])
        failed_checks = len([x for x in results if x['status'] == 'FAIL'])
        manual_checks = len([x for x in results if x['status'] == 'MANUAL'])
        skip_checks = len([x for x in results if x['status'] == 'SKIP'])
        error_checks = len([x for x in results if x['status'] == 'ERROR'])
        other_checks = total_checks - passed_checks - failed_checks - manual_checks - skip_checks - error_checks
        
        valid_checks = total_checks - manual_checks - skip_checks - error_checks - other_checks
        score = round((passed_checks / valid_checks) * 100, 1) if valid_checks > 0 else 0
        
        cnt_critical = len([x for x in results if x['severity'] == "Critical" and x['status'] == "FAIL"])
        cnt_high = len([x for x in results if x['severity'] == "High" and x['status'] == "FAIL"])
        cnt_medium = len([x for x in results if x['severity'] == "Medium" and x['status'] == "FAIL"])
        cnt_low = len([x for x in results if x['severity'] == "Low" and x['status'] == "FAIL"])
        
        non_pass_results = [x for x in results if x['status'] != 'PASS']
        
        html_out = template.render(
            results=non_pass_results,
            all_results=results,
            hostname=run_cmd("hostname"),
            ip_address=run_cmd("hostname -I | awk '{print $1}'"),
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_checks=total_checks, 
            passed_checks=passed_checks, 
            failed_checks=failed_checks,
            manual_checks=manual_checks,
            skip_checks=skip_checks,
            error_checks=error_checks,
            other_checks=other_checks,
            score=score,
            count_critical=cnt_critical, 
            count_high=cnt_high, 
            count_medium=cnt_medium,
            count_low=cnt_low
        )
        
        pdf_file = f"Ubuntu_CIS_Audit_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        options = { 
            'page-size': 'A4', 
            'margin-top': '0.3in', 
            'margin-right': '0.3in', 
            'margin-bottom': '0.3in', 
            'margin-left': '0.3in', 
            'encoding': "UTF-8", 
            'enable-local-file-access': None,
            'quiet': '',
            'print-media-type': '',
            'no-outline': None,
            'disable-smart-shrinking': ''
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            f.write(html_out)
            html_temp = f.name
        
        try:
            pdfkit.from_file(html_temp, pdf_file, options=options)
            print(f"[SUCCESS] Report saved: {pdf_file}")
        except Exception as e:
            print(f"[WARNING] PDF generation failed: {e}")
            print("[INFO] Saving HTML report instead...")
            html_file = pdf_file.replace('.pdf', '.html')
            with open(html_file, 'w') as f:
                f.write(html_out)
            print(f"[SUCCESS] HTML report saved: {html_file}")
        finally:
            os.unlink(html_temp)
            
    except Exception as e:
        print(f"[ERROR] Report generation failed: {e}")
        print("\n[INFO] Raw results:")
        for r in results:
            print(f"{r['id']}: {r['status']} - {r['title']}")
    
    print("\n[+] Audit Summary:")
    print(f"   Total Checks: {total_checks}")
    print(f"   Passed: {passed_checks}")
    print(f"   Failed: {failed_checks}")
    print(f"   Manual Review Needed: {manual_checks}")
    if skip_checks > 0:
        print(f"   Skipped: {skip_checks}")
    if error_checks > 0:
        print(f"   Errors: {error_checks}")
    
    print(f"   Compliance Score: {score}%")
    print("=" * 60)
