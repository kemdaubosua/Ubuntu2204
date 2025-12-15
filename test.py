import os
import subprocess
import re
import pdfkit
import tempfile
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import sys

results = []

# ==================== DICTIONARY CHỨA RATIONALE ====================
RATIONALE_DICT = {
    # 1.2 Package Management
    "1.2.1.1": "It is important to ensure that updates are obtained from a valid source to protect against spoofing that could lead to the inadvertent installation of malware on the system.",
    "1.2.1.2": "If a system's package repositories are misconfigured important patches may not be identified or a rogue repository could introduce compromised software.",
    "1.2.2.1": "Newer patches may contain security enhancements that would not be available through the latest full update. As a result, it is recommended that the latest software patches be used to take advantage of the latest functionality.",
    
    # 1.3 AppArmor
    "1.3.1.1": "Without a Mandatory Access Control system installed only the default Discretionary Access Control system will be available.",
    "1.3.1.2": "AppArmor is a security mechanism and disabling it is not recommended.",
    "1.3.1.3": "Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that any policies that exist on the system are activated.",
    "1.3.1.4": "Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that any policies that exist on the system are activated.",
    
    # 1.6 Message of the Day
    "1.6.4": "If the /etc/motd file does not have the correct access configured, it could be modified by unauthorized users with incorrect or misleading information.",
    "1.6.5": "If the /etc/issue file does not have the correct access configured, it could be modified by unauthorized users with incorrect or misleading information.",
    "1.6.6": "If the /etc/issue.net file does not have the correct access configured, it could be modified by unauthorized users with incorrect or misleading information.",
    
    # 2.4 Cron
    "2.4.1.2": "This file contains information on what system jobs are run by cron. Write access to these files could provide unprivileged users with the ability to elevate their privileges. Read access could provide insight on system jobs.",
    "2.4.1.3": "Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access could give an unprivileged user insight in how to gain elevated privileges.",
    "2.4.1.4": "Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access could give an unprivileged user insight in how to gain elevated privileges.",
    "2.4.1.5": "Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access could give an unprivileged user insight in how to gain elevated privileges.",
    "2.4.1.6": "Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access could give an unprivileged user insight in how to gain elevated privileges.",
    "2.4.1.7": "Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access could give an unprivileged user insight in how to gain elevated privileges.",
    "2.4.1.8": "Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access could give an unprivileged user insight in how to gain elevated privileges.",
    "2.4.1.9": "On many systems, only the system administrator is authorized to schedule cron jobs. Using the cron.allow file to control who can run cron jobs enforces this policy.",
    "2.4.2.1": "On many systems, only the system administrator is authorized to schedule at jobs. Using the at.allow file to control who can run at jobs enforces this policy.",
    
    # 5.1 SSH
    "5.1.1": "Configuration specifications for sshd need to be protected from unauthorized changes by non-privileged users.",
    "5.1.2": "If an unauthorized user obtains the private SSH host key file, the host could be impersonated.",
    "5.1.3": "If a public host key file is modified by an unauthorized user, the SSH service may be compromised.",
    "5.2.10": "Even though the primary function of root is to have privileges to modify any aspect of a Unix type system, if root is permitted to log in via SSH, an attacker could attempt a brute force attack against the root password.",
    
    # 5.3 PAM
    "5.3.1.3": "Strong passwords reduce the risk of systems being hacked through brute force methods. Older versions of the libpam-pwquality package may not include the latest security patches.",
    "5.3.2.1": "The system should only provide access after performing authentication of a user.",
    "5.3.2.2": "Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.",
    
    # 5.3.2.3 PAM pwquality (mới bổ sung)
    "5.3.2.3": "Use of a unique, complex passwords helps to increase the time and resources required to compromise the password.",
    
    # 5.3.2.4 PAM pwhistory (mới bổ sung)  
    "5.3.2.4": "Use of a unique, complex passwords helps to increase the time and resources required to compromise the password.",
    
    # 5.3.3.1.1 Password failed attempts lockout (mới bổ sung)
    "5.3.3.1.1": "Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.",
    
    # 5.3.3.1.2 Password unlock time (mới bổ sung)
    "5.3.3.1.2": "Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.",
    
    "5.3.3.1.3": "Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.",
    "5.3.3.2.2": "Strong passwords help protect systems from password attacks. Types of password attacks include dictionary attacks and brute force attacks.",
    
    # 5.3.3.3.1 Password history remember (mới bổ sung)
    "5.3.3.3.1": "Requiring users not to reuse their passwords make it less likely that an attacker will be able to guess the password or use a compromised password.",
    
    # 5.3.3.4.1 PAM unix nullok (mới bổ sung)
    "5.3.3.4.1": "Using a strong password is essential to helping protect personal and sensitive information from unauthorized access",
    
    # 5.4 User Accounts
    "5.4.1.1": "The window of opportunity for an attacker to leverage compromised credentials or successfully compromise credentials via an online brute force attack is limited by the age of the password.",
    
    # 5.4.1.2 Minimum password days (mới bổ sung)
    "5.4.1.2": "Users may have favorite passwords that they like to use because they are easy to remember. By restricting the frequency of password changes, an administrator can prevent users from repeatedly changing their password in an attempt to circumvent password reuse controls.",
    
    # 5.4.1.3 Password expiration warning days (mới bổ sung)
    "5.4.1.3": "Providing an advance warning that a password will be expiring gives users time to think of a secure password. Users caught unaware may choose a simple password or write it down where it may be discovered.",
    
    "5.4.1.4": "The SHA-512 and yescrypt algorithms provide a stronger hash than other algorithms used by Linux for password hash generation.",
    "5.4.1.5": "Inactive accounts pose a threat to system security since the users are not logging in to notice failed login attempts or other anomalies.",
    "5.4.2.1": "Any account with UID 0 has superuser privileges on the system. This access must be limited to only the default root account.",
    
    # 5.4.2.2 Root GID 0 (mới bổ sung)
    "5.4.2.2": "Using GID 0 for the root account helps prevent root-owned files from accidentally becoming accessible to non-privileged users.",
    
    # 5.4.2.3 Group root GID 0 (mới bổ sung)
    "5.4.2.3": "Using GID 0 for the root group helps prevent root group owned files from accidentally becoming accessible to non-privileged users.",
    
    "5.4.2.4": "Access to root should be secured at all times.",
    "5.4.2.7": "It is important to make sure that accounts that are not being used by regular users are prevented from being used to provide an interactive shell.",
    
    # 5.4.2.8 Accounts without valid shell locked (mới bổ sung)
    "5.4.2.8": "It is important to make sure that accounts that are not being used by regular users are prevented from being used to provide an interactive shell.",
    
    # 6.1 Logging
    "6.1.1.2": "It is important to ensure that log files have the correct permissions to ensure that sensitive data is archived and protected.",
    "6.1.2.4": "It is important to ensure that log files have the correct permissions to ensure that sensitive data is archived and protected.",
    "6.1.3.1": "It is important that log files have the correct permissions to ensure that sensitive data is protected and that only the appropriate users/groups have access to them.",
    
    # 6.2 Audit
    "6.2.4.1": "It is important that log files have the correct permissions to ensure that sensitive data is protected and that only the appropriate users/groups have access to them.",
    
    # 6.2.4.2 Audit log files owner (mới bổ sung)
    "6.2.4.2": "Access to audit records can reveal system and configuration data to attackers, potentially compromising its confidentiality.",
    
    # 6.2.4.3 Audit log files group owner (mới bổ sung)
    "6.2.4.3": "Access to audit records can reveal system and configuration data to attackers, potentially compromising its confidentiality.",
    
    # 6.2.4.4 Audit log directory mode (mới bổ sung)
    "6.2.4.4": "Audit information includes all information including: audit records, audit settings and audit reports. This information is needed to successfully audit system activity.",
    
    # 6.2.4.5 Audit configuration files mode (mới bổ sung)
    "6.2.4.5": "Access to the audit configuration files could allow unauthorized personnel to prevent the auditing of critical events.",
    
    # 6.2.4.6 Audit configuration files owner (mới bổ sung)
    "6.2.4.6": "Access to the audit configuration files could allow unauthorized personnel to prevent the auditing of critical events.",
    
    # 6.2.4.7 Audit configuration files group owner (mới bổ sung)
    "6.2.4.7": "Access to the audit configuration files could allow unauthorized personnel to prevent the auditing of critical events.",
    
    # 6.2.4.8 Audit tools mode (mới bổ sung)
    "6.2.4.8": "Protecting audit information includes identifying and protecting the tools used to view and manipulate log data.",
    
    # 6.2.4.9 Audit tools owner (mới bổ sung)
    "6.2.4.9": "Protecting audit information includes identifying and protecting the tools used to view and manipulate log data.",
    
    # 6.2.4.10 Audit tools group owner (mới bổ sung)
    "6.2.4.10": "Protecting audit information includes identifying and protecting the tools used to view and manipulate log data.",
    
    # 7.1 File Permissions
    "7.1.1": "It is critical to ensure that the /etc/passwd file is protected from unauthorized write access.",
    "7.1.2": "It is critical to ensure that the /etc/passwd- file is protected from unauthorized access.",
    "7.1.3": "The /etc/group file needs to be protected from unauthorized changes by non-privileged users.",
    "7.1.4": "It is critical to ensure that the /etc/group- file is protected from unauthorized access.",
    "7.1.5": "If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program against the hashed password to break it.",
    "7.1.6": "If attackers can gain read access to the /etc/shadow- file, they can easily run a password cracking program against the hashed password to break it.",
    "7.1.7": "If attackers can gain read access to the /etc/gshadow file, they can easily run a password cracking program against the hashed password to break it.",
    "7.1.8": "If attackers can gain read access to the /etc/gshadow- file, they can easily run a password cracking program against the hashed password to break it.",
    "7.1.9": "It is critical to ensure that the /etc/shells file is protected from unauthorized access.",
    
    # 7.1.10 /etc/security/opasswd (mới bổ sung)
    "7.1.10": "It is critical to ensure that /etc/security/opasswd is protected from unauthorized access.",
    
    "7.1.11": "Data in world-writable files can be modified and compromised by any user on the system. World writable files may also indicate an incorrectly written script or program.",
    "7.1.12": "A new user or group who is assigned a deleted user's user ID or group ID may then end up 'owning' a deleted user or group's files, and thus have more access on the system than was intended.",
    "7.1.13": "There are valid reasons for SUID and SGID programs, but it is important to identify and review such programs to ensure they are legitimate.",
    "7.2.9": "Since the user is accountable for files stored in the user home directory, the user must be the owner of the directory. Group or world-writable user home directories may enable malicious users to steal or modify other users' data.",
    
    # Additional checks
    "4.5.1": "A firewall is essential for controlling the incoming and outgoing network traffic based on predetermined security rules.",
    "3.1.1": "IP forwarding permits the kernel to forward packets from one network interface to another. This should only be enabled if the system is intended to function as a router.",
}

# ==================== CÁC HÀM TIỆN ÍCH ====================
def run_cmd(command):
    """Chạy lệnh shell và trả về kết quả"""
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        return e.output.decode('utf-8').strip()
    except Exception as e:
        return f"Error: {str(e)}"

def get_file_content(filepath):
    """Đọc toàn bộ nội dung của một file văn bản."""
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
    """
    Hàm trung tâm để thực hiện một bài kiểm tra (Audit Check).
    """
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
    """
    Hàm phụ trợ quan trọng: Kiểm tra quyền (permissions) của một file.
    """
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
    """Hàm phụ: Kiểm tra quyền các thư mục cron."""
    if not os.path.exists(directory):
        return "PASS", f"Directory {directory} does not exist (cron may not be installed)"
    return check_file_permission(directory, expected_mode)

# ==================== CÁC HÀM KIỂM TRA CƠ BẢN ====================

def check_gpg_keys():
    """1.2.1.1: Kiểm tra xem GPG keys cho apt có được cấu hình đúng không."""
    apt_key_out = run_cmd("apt-key list 2>/dev/null | head -20")
    gpg_files = run_cmd("ls -la /etc/apt/trusted.gpg.d/ 2>/dev/null | wc -l")
    
    if "deprecated" in apt_key_out.lower() or int(gpg_files or 0) <= 1:
        return "FAIL", f"GPG keys may not be properly configured\napt-key output (truncated): {apt_key_out[:200]}\nGPG files in trusted.gpg.d: {gpg_files}"
    return "PASS", "GPG keys appear to be configured"

def check_package_repos():
    """1.2.1.2: Kiểm tra cấu hình kho (repo) cài phần mềm."""
    out = run_cmd("apt-cache policy")
    if "http" in out or "https" in out:
        return "PASS", "Package repositories configured"
    return "FAIL", "No valid repositories found in apt-cache policy"

def check_updates_installed():
    """1.2.2.1: Kiểm tra xem hệ thống đã cài hết bản vá lỗi chưa."""
    run_cmd("apt update > /dev/null 2>&1")
    out = run_cmd("apt -s upgrade 2>/dev/null | grep -E 'upgraded|installed'")
    
    if "0 upgraded" in out and "0 newly installed" in out:
        return "PASS", "All updates are installed"
    return "FAIL", f"Updates available:\n{out}"

def check_apparmor_installed():
    """1.3.1.1: Kiểm tra gói AppArmor đã cài chưa."""
    apparmor = run_cmd("dpkg-query -s apparmor 2>/dev/null | grep Status")
    apparmor_utils = run_cmd("dpkg-query -s apparmor-utils 2>/dev/null | grep Status")
    
    if "install ok installed" in apparmor and "install ok installed" in apparmor_utils:
        return "PASS", "AppArmor packages are installed"
    return "FAIL", f"AppArmor status: {apparmor}\nAppArmor-utils status: {apparmor_utils}"

def check_apparmor_enabled():
    """1.3.1.2: Kiểm tra AppArmor có được bật trong Bootloader (GRUB) không."""
    out = run_cmd("grep '^\s*linux' /boot/grub/grub.cfg 2>/dev/null | grep -v 'apparmor=0' | wc -l")
    if int(out or 0) > 0:
        return "PASS", "AppArmor is enabled in GRUB"
    return "FAIL", "AppArmor may be disabled in GRUB configuration"

def check_apparmor_profiles():
    """1.3.1.3: Kiểm tra các profile bảo mật đã load chưa."""
    out = run_cmd("apparmor_status 2>/dev/null")
    if out and "profiles are loaded" in out and "0 profiles are in complain mode" not in out:
        return "PASS", "AppArmor profiles are loaded"
    return "MANUAL", "Check AppArmor profiles manually:\n" + (out[:500] if out else "No output from apparmor_status")

def check_apparmor_enforcing():
    """1.3.1.4: Kiểm tra xem AppArmor có đang ở chế độ 'enforce' (bắt buộc) không."""
    out = run_cmd("apparmor_status 2>/dev/null")
    if out and "profiles are in enforce mode" in out:
        profiles = re.search(r'(\d+) profiles are in enforce mode', out)
        if profiles and int(profiles.group(1)) > 0:
            return "PASS", "AppArmor profiles are in enforce mode"
    return "MANUAL", "Check AppArmor enforcing mode:\n" + (out[:500] if out else "No output")

def check_motd():
    """1.6.4: Kiểm tra quyền file /etc/motd (thông báo chào mừng)."""
    return check_file_permission("/etc/motd", "644")

def check_issue():
    """1.6.5: Kiểm tra quyền file /etc/issue (thông tin hệ điều hành)."""
    return check_file_permission("/etc/issue", "644")

def check_issue_net():
    """1.6.6: Kiểm tra quyền file /etc/issue.net (thông tin cho remote login)."""
    return check_file_permission("/etc/issue.net", "644")

def check_crontab_perms():
    """2.4.1.2: Kiểm tra quyền file cấu hình crontab chính."""
    return check_file_permission("/etc/crontab", "600")

def check_cron_hourly():
    """2.4.1.3: Kiểm tra quyền thư mục cron.hourly."""
    return check_cron_dir_perms("/etc/cron.hourly")

def check_cron_daily():
    """2.4.1.4: Kiểm tra quyền thư mục cron.daily."""
    return check_cron_dir_perms("/etc/cron.daily")

def check_cron_weekly():
    """2.4.1.5: Kiểm tra quyền thư mục cron.weekly."""
    return check_cron_dir_perms("/etc/cron.weekly")

def check_cron_monthly():
    """2.4.1.6: Kiểm tra quyền thư mục cron.monthly."""
    return check_cron_dir_perms("/etc/cron.monthly")

def check_cron_yearly():
    """2.4.1.7: Kiểm tra quyền thư mục cron.yearly."""
    return check_cron_dir_perms("/etc/cron.yearly")

def check_cron_d():
    """2.4.1.8: Kiểm tra quyền thư mục cron.d."""
    return check_cron_dir_perms("/etc/cron.d")

def check_cron_allow():
    """2.4.1.9: Kiểm tra file cho phép/cấm dùng cron."""
    allow_check = check_file_permission("/etc/cron.allow", "640")
    deny_check = check_file_permission("/etc/cron.deny", "640")
    
    if "FAIL" in allow_check[0] or "FAIL" in deny_check[0]:
        return "FAIL", f"cron.allow: {allow_check[1]}\ncron.deny: {deny_check[1]}"
    return "PASS", "cron.allow and cron.deny permissions are correct"

def check_at_cron_restricted():
    """2.4.2.1: Kiểm tra quyền truy cập lệnh 'at'."""
    allow_check = check_file_permission("/etc/at.allow", "640", "root", "daemon")
    deny_check = check_file_permission("/etc/at.deny", "640", "root", "daemon")
    
    if "FAIL" in allow_check[0] or "FAIL" in deny_check[0]:
        return "FAIL", f"at.allow: {allow_check[1]}\nat.deny: {deny_check[1]}"
    return "PASS", "at.allow and at.deny permissions are correct"

def check_sshd_config():
    """5.1.1: Kiểm tra quyền file cấu hình SSH Server."""
    return check_file_permission("/etc/ssh/sshd_config", "600")

def check_ssh_private_keys():
    """5.1.2: Kiểm tra các khóa bí mật (Private keys) của SSH."""
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
    """5.1.3: Kiểm tra các khóa công khai (Public keys) của SSH."""
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

def check_ssh_root_login():
    """5.2.10: Kiểm tra xem Root có được phép login qua SSH không."""
    content = get_file_content("/etc/ssh/sshd_config")
    if not content:
        return "FAIL", "File /etc/ssh/sshd_config not found"
    
    match = re.search(r"^PermitRootLogin\s+(yes|prohibit-password|without-password)", content, re.MULTILINE | re.IGNORECASE)
    if match:
        return "FAIL", f"Insecure config: {match.group(0).strip()}"
    
    if re.search(r"^PermitRootLogin\s+no", content, re.MULTILINE | re.IGNORECASE):
        return "PASS", "PermitRootLogin is set to 'no'"
    
    return "MANUAL", "PermitRootLogin not explicitly set (check default)"

def check_pam_pwquality():
    """5.3.1.3: Kiểm tra thư viện kiểm soát chất lượng mật khẩu."""
    out = run_cmd("dpkg-query -s libpam-pwquality 2>/dev/null | grep Status")
    if "install ok installed" in out:
        return "PASS", "libpam-pwquality is installed"
    return "FAIL", "libpam-pwquality is not installed"

def check_pam_unix():
    """5.3.2.1: Kiểm tra module xác thực unix chuẩn."""
    out = run_cmd("grep -l 'pam_unix.so' /etc/pam.d/* 2>/dev/null | wc -l")
    if int(out or 0) > 0:
        return "PASS", "pam_unix module is enabled"
    return "FAIL", "pam_unix module not found in PAM configuration"

def check_pam_faillock():
    """5.3.2.2: Kiểm tra module khóa tài khoản khi nhập sai pass (faillock)."""
    out = run_cmd("grep -l 'pam_faillock.so' /etc/pam.d/* 2>/dev/null | wc -l")
    if int(out or 0) > 0:
        return "PASS", "pam_faillock module is enabled"
    return "FAIL", "pam_faillock module not found in PAM configuration"

def check_password_history():
    """5.3.3.1.3: Kiểm tra xem việc khóa tài khoản có áp dụng cho cả root không."""
    out = run_cmd("grep -i 'even_deny_root' /etc/security/faillock.conf 2>/dev/null")
    if "even_deny_root" in out:
        return "PASS", "Root account is included in password lockout"
    return "MANUAL", "Check /etc/security/faillock.conf for even_deny_root setting"

def check_password_length():
    """5.3.3.2.2: Kiểm tra độ dài mật khẩu tối thiểu (minlen)."""
    out = run_cmd("grep -i 'minlen' /etc/security/pwquality.conf 2>/dev/null")
    if "minlen" in out:
        match = re.search(r'minlen\s*=\s*(\d+)', out)
        if match and int(match.group(1)) >= 14:
            return "PASS", f"Minimum password length: {match.group(1)}"
    return "MANUAL", "Check /etc/security/pwquality.conf for minlen setting"

def check_password_expiration():
    """5.4.1.1: Kiểm tra thời hạn hiệu lực tối đa của mật khẩu."""
    out = run_cmd("grep -i 'PASS_MAX_DAYS' /etc/login.defs 2>/dev/null")
    if "PASS_MAX_DAYS" in out:
        match = re.search(r'PASS_MAX_DAYS\s+(\d+)', out)
        if match and int(match.group(1)) <= 365:
            return "PASS", f"Password max days: {match.group(1)}"
    return "MANUAL", "Check /etc/login.defs for PASS_MAX_DAYS setting"

def check_password_hashing_algorithm():
    """5.4.1.4: Kiểm tra thuật toán băm mật khẩu có đủ mạnh không."""
    out = run_cmd("grep -i 'ENCRYPT_METHOD' /etc/login.defs 2>/dev/null")
    if "ENCRYPT_METHOD SHA512" in out or "ENCRYPT_METHOD YESCRYPT" in out:
        return "PASS", "Strong password hashing algorithm is configured"
    return "MANUAL", "Check /etc/login.defs for ENCRYPT_METHOD setting"

def check_inactive_password_lock():
    """5.4.1.5: Kiểm tra cấu hình khóa tài khoản không hoạt động."""
    out = run_cmd("useradd -D | grep INACTIVE")
    if "INACTIVE=30" in out or "INACTIVE=45" in out:
        return "PASS", "Inactive password lock is configured"
    return "MANUAL", "Check useradd defaults for INACTIVE setting"

def check_only_root_uid0():
    """5.4.2.1: Quan trọng - Kiểm tra xem có ai khác ngoài root có UID 0 không."""
    out = run_cmd("awk -F: '($3 == 0) { print $1 }' /etc/passwd")
    users = [u.strip() for u in out.split('\n') if u.strip()]
    
    if len(users) == 1 and users[0] == 'root':
        return "PASS", "Only root has UID 0"
    return "FAIL", f"Accounts with UID 0: {', '.join(users)}"

def check_root_password():
    """5.4.2.4: Kiểm tra trạng thái mật khẩu của root."""
    out = run_cmd("passwd -S root 2>/dev/null")
    if "Password set" in out or "Password locked" in out:
        return "PASS", "Root password is set or locked"
    return "FAIL", "Root password may not be properly secured"

def check_system_accounts_shell():
    """5.4.2.7: Đảm bảo các user hệ thống (bin, daemon...) không có shell đăng nhập."""
    out = run_cmd("awk -F: '$1 !~ /^(root|halt|sync|shutdown)$/ && $3 < 1000 && $7 !~ /nologin/ {print $1}' /etc/passwd")
    accounts = [a.strip() for a in out.split('\n') if a.strip()]
    
    if not accounts:
        return "PASS", "System accounts have nologin shell"
    return "FAIL", f"System accounts with login shell: {', '.join(accounts)}"

def check_journald_logs():
    """6.1.1.2: Kiểm tra quyền truy cập thư mục log của journald."""
    out = run_cmd("stat -c '%a' /var/log/journal 2>/dev/null || echo '750'")
    if out and int(out) <= 750:
        return "PASS", f"Journal directory permissions: {out}"
    return "MANUAL", f"Check /var/log/journal permissions (current: {out})"

def check_rsyslog_perms():
    """6.1.2.4: Kiểm tra cấu hình quyền file log mới tạo của rsyslog."""
    out = run_cmd("grep -i '\\$FileCreateMode' /etc/rsyslog.conf 2>/dev/null")
    if "0640" in out or "0600" in out:
        return "PASS", "rsyslog FileCreateMode is configured"
    return "MANUAL", "Check /etc/rsyslog.conf for $FileCreateMode setting"

def check_log_files_perms():
    """6.1.3.1: Kiểm tra quyền của các file log cụ thể (syslog, auth.log...)."""
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

def check_audit_log_perms():
    """6.2.4.1: Kiểm tra quyền thư mục chứa log audit."""
    audit_status = run_cmd("systemctl is-active auditd 2>/dev/null || echo 'inactive'")
    if "inactive" in audit_status:
        return "SKIP", "auditd is not active"
    
    out = run_cmd("stat -c '%a' /var/log/audit/ 2>/dev/null")
    if out and int(out) <= 750:
        return "PASS", f"Audit log directory permissions: {out}"
    return "MANUAL", f"Check /var/log/audit/ permissions (current: {out})"

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

def check_world_writable():
    """7.1.11: Tìm các file/thư mục mà ai cũng ghi được (nguy hiểm)."""
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
    """7.1.12: Tìm các file không có người sở hữu (do user bị xóa nhưng file còn)."""
    files = run_cmd("find / -xdev -nouser -o -nogroup 2>/dev/null | head -5")
    if files:
        file_list = files.split('\n')
        file_count = len([f for f in file_list if f.strip()])
        if file_count > 0:
            return "MANUAL", f"Found {file_count} unowned files/groups:\n{files[:500]}"
    return "PASS", "No unowned files or directories"

def check_suid_sgid():
    """7.1.13: Kiểm đếm số lượng file SUID/SGID. Nếu quá nhiều là bất thường."""
    suid = run_cmd("find / -xdev -type f -perm -4000 2>/dev/null | wc -l")
    sgid = run_cmd("find / -xdev -type f -perm -2000 2>/dev/null | wc -l")
    
    suid_count = int(suid or 0)
    sgid_count = int(sgid or 0)
    
    if suid_count > 50 or sgid_count > 50:
        return "MANUAL", f"SUID files: {suid_count}, SGID files: {sgid_count}. Review manually."
    return "PASS", f"SUID files: {suid_count}, SGID files: {sgid_count}"

def check_home_dirs():
    """7.2.9: Kiểm tra thư mục Home của user có tồn tại và đúng quyền không."""
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

def check_ufw_status():
    """4.5.1: Kiểm tra Firewall UFW đã bật chưa."""
    out = run_cmd("ufw status 2>/dev/null")
    if "Status: active" in out:
        return "PASS", "UFW is active"
    return "MANUAL", "UFW is not active or not installed"

def check_ip_forwarding():
    """3.1.1: Kiểm tra IP Forwarding (chuyển tiếp gói tin) có tắt không."""
    out = run_cmd("sysctl net.ipv4.ip_forward")
    if "net.ipv4.ip_forward = 0" in out:
        return "PASS", "IP forwarding is disabled"
    return "FAIL", f"IP forwarding may be enabled:\n{out}"

# ==================== BỔ SUNG CÁC HÀM KIỂM TRA MỚI ====================

# --- 5.3.2.3 PAM pwquality module enabled ---
def check_pam_pwquality_enabled():
    """5.3.2.3: Kiểm tra module pam_pwquality.so có được bật không."""
    out = run_cmd("grep -P -- '\\bpam_pwquality\\.so\\b' /etc/pam.d/common-password")
    if out and "pam_pwquality.so" in out:
        return "PASS", "pam_pwquality module is enabled"
    return "FAIL", "pam_pwquality module is not enabled in /etc/pam.d/common-password"

# --- 5.3.2.4 PAM pwhistory module enabled ---
def check_pam_pwhistory_enabled():
    """5.3.2.4: Kiểm tra module pam_pwhistory.so có được bật không."""
    out = run_cmd("grep -P -- '\\bpam_pwhistory\\.so\\b' /etc/pam.d/common-password")
    if out and "pam_pwhistory.so" in out:
        return "PASS", "pam_pwhistory module is enabled"
    return "FAIL", "pam_pwhistory module is not enabled in /etc/pam.d/common-password"

# --- 5.3.3.1.1 Password failed attempts lockout ---
def check_password_lockout_configured():
    """5.3.3.1.1: Kiểm tra cấu hình khóa tài khoản sau số lần nhập sai."""
    out = run_cmd("grep -Pi -- '^\\h*deny\\h*=\\h*[0-5]\\b' /etc/security/faillock.conf")
    if out and "deny = 5" in out or "deny = 3" in out:
        return "PASS", f"Password lockout configured: {out.strip()}"
    
    pam_out = run_cmd("grep -Pi -- 'pam_faillock\\.so.*deny=' /etc/pam.d/common-auth")
    if pam_out:
        return "MANUAL", f"Password lockout configured in PAM: {pam_out[:100]}"
    
    return "FAIL", "Password failed attempts lockout not properly configured"

# --- 5.3.3.1.2 Password unlock time ---
def check_password_unlock_time():
    """5.3.3.1.2: Kiểm tra thời gian mở khóa tài khoản."""
    out = run_cmd("grep -Pi -- '^\\h*unlock_time\\h*=' /etc/security/faillock.conf")
    if out:
        match = re.search(r'unlock_time\s*=\s*(\d+)', out)
        if match:
            time = int(match.group(1))
            if time == 0 or time >= 900:
                return "PASS", f"Password unlock time configured: {out.strip()}"
    
    return "MANUAL", "Check /etc/security/faillock.conf for unlock_time setting"

# --- 5.3.3.3.1 Password history remember ---
def check_password_history_remember():
    """5.3.3.3.1: Kiểm tra cấu hình lịch sử mật khẩu (remember)."""
    out = run_cmd("grep -P -- 'pam_pwhistory\\.so.*remember=' /etc/pam.d/common-password")
    if out:
        match = re.search(r'remember\s*=\s*(\d+)', out)
        if match and int(match.group(1)) >= 24:
            return "PASS", f"Password history remember configured: {out.strip()[:100]}"
        elif match:
            return "FAIL", f"Password history remember too low: {match.group(1)} (should be >=24)"
    
    return "MANUAL", "Password history remember not configured or check manually"

# --- 5.3.3.4.1 PAM unix nullok ---
def check_pam_unix_nullok():
    """5.3.3.4.1: Kiểm tra pam_unix.so không có tham số nullok."""
    out = run_cmd("grep -P -- 'pam_unix\\.so.*nullok' /etc/pam.d/common-password")
    if out:
        return "FAIL", f"nullok parameter found: {out.strip()[:100]}"
    
    auth_out = run_cmd("grep -P -- 'pam_unix\\.so.*nullok' /etc/pam.d/common-auth")
    if auth_out:
        return "FAIL", f"nullok parameter found in common-auth: {auth_out.strip()[:100]}"
    
    return "PASS", "pam_unix.so does not include nullok parameter"

# --- 5.4.1.2 Minimum password days ---
def check_minimum_password_days():
    """5.4.1.2: Kiểm tra số ngày tối thiểu giữa các lần đổi mật khẩu."""
    out = run_cmd("grep -Pi -- '^\\h*PASS_MIN_DAYS\\h+' /etc/login.defs")
    if out:
        match = re.search(r'PASS_MIN_DAYS\s+(\d+)', out)
        if match and int(match.group(1)) >= 1:
            return "PASS", f"Minimum password days configured: {out.strip()}"
        elif match:
            return "FAIL", f"PASS_MIN_DAYS is {match.group(1)} (should be >=1)"
    
    return "MANUAL", "PASS_MIN_DAYS not configured in /etc/login.defs"

# --- 5.4.1.3 Password expiration warning days ---
def check_password_warning_days():
    """5.4.1.3: Kiểm tra số ngày cảnh báo trước khi mật khẩu hết hạn."""
    out = run_cmd("grep -Pi -- '^\\h*PASS_WARN_AGE\\h+' /etc/login.defs")
    if out:
        match = re.search(r'PASS_WARN_AGE\s+(\d+)', out)
        if match and int(match.group(1)) >= 7:
            return "PASS", f"Password warning days configured: {out.strip()}"
        elif match:
            return "FAIL", f"PASS_WARN_AGE is {match.group(1)} (should be >=7)"
    
    return "MANUAL", "PASS_WARN_AGE not configured in /etc/login.defs"

# --- 5.4.2.2 Root is the only GID 0 account ---
def check_only_root_gid0():
    """5.4.2.2: Kiểm tra chỉ có root có primary GID 0."""
    out = run_cmd("awk -F: '($4 == \"0\") { print $1\":\"$4 }' /etc/passwd")
    users = [line.strip() for line in out.split('\n') if line.strip()]
    
    allowed_users = ['root:0', 'sync:0', 'shutdown:0', 'halt:0', 'operator:0']
    for user in users:
        if user not in allowed_users:
            return "FAIL", f"Non-root account with GID 0: {user}"
    
    return "PASS", "Only root (and allowed system accounts) have GID 0 as primary GID"

# --- 5.4.2.3 Group root is the only GID 0 group ---
def check_only_root_group_gid0():
    """5.4.2.3: Kiểm tra chỉ có group root có GID 0."""
    out = run_cmd("awk -F: '($3 == \"0\") { print $1\":\"$3 }' /etc/group")
    groups = [line.strip() for line in out.split('\n') if line.strip()]
    
    if len(groups) == 1 and groups[0] == 'root:0':
        return "PASS", "Only root group has GID 0"
    elif len(groups) > 1:
        return "FAIL", f"Multiple groups with GID 0: {', '.join(groups)}"
    
    return "FAIL", "No group with GID 0 found (root group missing?)"

# --- 5.4.2.8 Accounts without valid shell are locked ---
def check_accounts_without_shell_locked():
    """5.4.2.8: Kiểm tra các tài khoản không có shell hợp lệ đã bị khóa."""
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

# --- 6.2.4.2 Audit log files owner ---
def check_audit_log_owner():
    """6.2.4.2: Kiểm tra chủ sở hữu file log audit là root."""
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

# --- 6.2.4.3 Audit log files group owner ---
def check_audit_log_group():
    """6.2.4.3: Kiểm tra group của file log audit là adm hoặc root."""
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

# --- 6.2.4.4 Audit log directory mode ---
def check_audit_log_dir_mode():
    """6.2.4.4: Kiểm tra quyền thư mục log audit."""
    if not os.path.exists("/etc/audit/auditd.conf"):
        return "SKIP", "auditd not installed or configured"
    
    log_dir = run_cmd("awk -F= '/^\\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs dirname 2>/dev/null")
    if not log_dir or not os.path.exists(log_dir):
        return "MANUAL", "Cannot determine audit log directory"
    
    mode = run_cmd(f"stat -c '%a' {log_dir} 2>/dev/null")
    if mode and int(mode) <= 750:
        return "PASS", f"Audit log directory mode: {mode}"
    
    return "FAIL", f"Audit log directory mode too permissive: {mode} (should be 750 or less)"

# --- 6.2.4.5 Audit configuration files mode ---
def check_audit_config_mode():
    """6.2.4.5: Kiểm tra quyền file cấu hình audit."""
    if not os.path.exists("/etc/audit"):
        return "SKIP", "auditd not installed"
    
    out = run_cmd("find /etc/audit -type f \\( -name '*.conf' -o -name '*.rules' \\) -perm /0137 2>/dev/null | wc -l")
    if out and int(out) > 0:
        files = run_cmd("find /etc/audit -type f \\( -name '*.conf' -o -name '*.rules' \\) -perm /0137 2>/dev/null | head -5")
        return "FAIL", f"Audit config files with permissive permissions:\n{files}"
    
    return "PASS", "Audit configuration files have proper permissions (0640 or more restrictive)"

# --- 6.2.4.6 Audit configuration files owner ---
def check_audit_config_owner():
    """6.2.4.6: Kiểm tra chủ sở hữu file cấu hình audit."""
    if not os.path.exists("/etc/audit"):
        return "SKIP", "auditd not installed"
    
    out = run_cmd("find /etc/audit -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -user root 2>/dev/null | wc -l")
    if out and int(out) > 0:
        files = run_cmd("find /etc/audit -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -user root 2>/dev/null | head -5")
        return "FAIL", f"Audit config files not owned by root:\n{files}"
    
    return "PASS", "All audit configuration files are owned by root"

# --- 6.2.4.7 Audit configuration files group owner ---
def check_audit_config_group():
    """6.2.4.7: Kiểm tra group của file cấu hình audit."""
    if not os.path.exists("/etc/audit"):
        return "SKIP", "auditd not installed"
    
    out = run_cmd("find /etc/audit -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -group root 2>/dev/null | wc -l")
    if out and int(out) > 0:
        files = run_cmd("find /etc/audit -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -group root 2>/dev/null | head -5")
        return "FAIL", f"Audit config files not owned by root group:\n{files}"
    
    return "PASS", "All audit configuration files are owned by root group"

# --- 6.2.4.8 Audit tools mode ---
def check_audit_tools_mode():
    """6.2.4.8: Kiểm tra quyền công cụ audit."""
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

# --- 6.2.4.9 Audit tools owner ---
def check_audit_tools_owner():
    """6.2.4.9: Kiểm tra chủ sở hữu công cụ audit."""
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

# --- 6.2.4.10 Audit tools group owner ---
def check_audit_tools_group():
    """6.2.4.10: Kiểm tra group của công cụ audit."""
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

# --- 7.1.10 /etc/security/opasswd permissions ---
def check_opasswd_perms():
    """7.1.10: Kiểm tra quyền file /etc/security/opasswd."""
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

# ==================== CHƯƠNG TRÌNH CHÍNH ====================

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: Run as root (sudo python3 ubuntu_cis_audit.py)")
        exit(1)
    
    print("=" * 60)
    print("CIS Ubuntu 22.04 Security Audit - COMPLETE CHECKLIST")
    print("=" * 60)
    
    # Định nghĩa danh sách kiểm tra với mức độ nghiêm trọng theo CVSS
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
        ("5.2.10", "SSH Root Login", "Ensure SSH Root Login is disabled", "Critical", check_ssh_root_login, "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"),
        
        # 5.3 PAM - Bổ sung các tiêu chí mới
        ("5.3.1.3", "PAM PWQuality", "Ensure latest version of libpam-pwquality is installed", "Medium", check_pam_pwquality, "apt install libpam-pwquality"),
        ("5.3.2.1", "PAM Unix Module", "Ensure pam_unix module is enabled", "Medium", check_pam_unix, "Enable pam_unix in PAM configuration"),
        ("5.3.2.2", "PAM Faillock Module", "Ensure pam_faillock module is enabled", "Medium", check_pam_faillock, "Enable pam_faillock in PAM configuration"),
        ("5.3.2.3", "PAM PWQuality Module", "Ensure pam_pwquality module is enabled", "Medium", check_pam_pwquality_enabled, "Enable pam_pwquality in /etc/pam.d/common-password"),
        ("5.3.2.4", "PAM PWHistory Module", "Ensure pam_pwhistory module is enabled", "Medium", check_pam_pwhistory_enabled, "Enable pam_pwhistory in /etc/pam.d/common-password"),
        ("5.3.3.1.1", "Password Lockout", "Ensure password failed attempts lockout is configured", "High", check_password_lockout_configured, "Configure deny= in /etc/security/faillock.conf"),
        ("5.3.3.1.2", "Password Unlock Time", "Ensure password unlock time is configured", "Medium", check_password_unlock_time, "Configure unlock_time= in /etc/security/faillock.conf"),
        ("5.3.3.1.3", "Password Lockout Root", "Ensure password lockout includes root account", "High", check_password_history, "Add 'even_deny_root' to /etc/security/faillock.conf"),
        ("5.3.3.2.2", "Password Length", "Ensure minimum password length is configured", "Medium", check_password_length, "Set 'minlen = 14' in /etc/security/pwquality.conf"),
        ("5.3.3.3.1", "Password History", "Ensure password history remember is configured", "Medium", check_password_history_remember, "Set remember=24 in pam_pwhistory configuration"),
        ("5.3.3.4.1", "PAM Unix Nullok", "Ensure pam_unix does not include nullok", "High", check_pam_unix_nullok, "Remove nullok parameter from pam_unix.so lines"),
        
        # 5.4 User Accounts - Bổ sung các tiêu chí mới
        ("5.4.1.1", "Password Expiration", "Ensure password expiration is configured", "Medium", check_password_expiration, "Set PASS_MAX_DAYS in /etc/login.defs"),
        ("5.4.1.2", "Minimum Password Days", "Ensure minimum password days is configured", "Medium", check_minimum_password_days, "Set PASS_MIN_DAYS >=1 in /etc/login.defs"),
        ("5.4.1.3", "Password Warning Days", "Ensure password expiration warning days is configured", "Low", check_password_warning_days, "Set PASS_WARN_AGE >=7 in /etc/login.defs"),
        ("5.4.1.4", "Password Hashing", "Ensure strong password hashing algorithm is configured", "High", check_password_hashing_algorithm, "Set ENCRYPT_METHOD to SHA512 or YESCRYPT in /etc/login.defs"),
        ("5.4.1.5", "Inactive Password Lock", "Ensure inactive password lock is configured", "Medium", check_inactive_password_lock, "Set INACTIVE in useradd defaults"),
        ("5.4.1.6", "Last Password Change", "Ensure all users last password change date is in the past", "Low", lambda: ("MANUAL", "Check manually with 'chage -l <user>'"), "Check and correct password change dates"),
        
        ("5.4.2.1", "UID 0 Accounts", "Ensure root is the only UID 0 account", "Critical", check_only_root_uid0, "Remove or modify non-root accounts with UID 0"),
        ("5.4.2.2", "GID 0 Accounts", "Ensure root is the only GID 0 account", "High", check_only_root_gid0, "Change GID of non-root accounts with GID 0"),
        ("5.4.2.3", "GID 0 Groups", "Ensure group root is the only GID 0 group", "High", check_only_root_group_gid0, "Remove or modify non-root groups with GID 0"),
        ("5.4.2.4", "Root Account Access", "Ensure root account access is controlled", "Critical", check_root_password, "Set or lock root password: passwd root or usermod -L root"),
        ("5.4.2.7", "System Account Shells", "Ensure system accounts do not have valid login shell", "Medium", check_system_accounts_shell, "Set shell to /usr/sbin/nologin for system accounts"),
        ("5.4.2.8", "Accounts Without Shell Locked", "Ensure accounts without a valid login shell are locked", "Medium", check_accounts_without_shell_locked, "Lock accounts without valid shells: usermod -L <user>"),
        
        # 6.1 Logging
        ("6.1.1.2", "Journald Log Access", "Ensure journald log file access is configured", "Low", check_journald_logs, "Set journal directory permissions to 750"),
        ("6.1.2.4", "Rsyslog Permissions", "Ensure rsyslog log file creation mode is configured", "Low", check_rsyslog_perms, "Set $FileCreateMode 0640 in rsyslog.conf"),
        ("6.1.3.1", "Log File Permissions", "Ensure access to all logfiles has been configured", "Low", check_log_files_perms, "Set log file permissions to 640 and owner to syslog:adm"),
        
        # 6.2 Audit - Bổ sung các tiêu chí mới
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
        
        # Additional checks
        ("4.5.1", "UFW Firewall", "Ensure Uncomplicated Firewall (UFW) is enabled", "High", check_ufw_status, "ufw enable"),
        ("3.1.1", "IP Forwarding", "Ensure IP forwarding is disabled", "Medium", check_ip_forwarding, "sysctl -w net.ipv4.ip_forward=0"),
    ]
    
    # Thực thi tất cả các bài kiểm tra
    for cis_id, title, description, severity, check_func, fix_cmd in checks:
        audit_check(cis_id, title, description, severity, check_func, fix_cmd)
    
    # Tạo báo cáo
    print("\n" + "=" * 60)
    print("[+] Generating Report...")
    
    try:
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('template.html')
        
        # Tính toán thống kê
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
