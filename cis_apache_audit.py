#!/usr/bin/env python3
"""
CIS Apache HTTP Server 2.4 Benchmark Compliance Auditor
Version: 2.4.0 - 10-02-2025
Enhanced with recursive config parsing
"""

import os
import re
import sys
import json
import stat
import pwd
import grp
import socket
import logging
import tempfile
import subprocess
import fnmatch
from datetime import datetime
from pathlib import Path, PurePath
from typing import List, Dict, Tuple, Optional, Callable, Set

# Import for report generation
import pdfkit
from jinja2 import Environment, FileSystemLoader

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global results storage
results = []

# Cache for parsed configuration to avoid redundant parsing
config_cache = {}

# ============================================
# ENHANCED CONFIG PARSING FUNCTIONS
# ============================================

def run_cmd(cmd: str) -> str:
    """Run shell command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return f"Error: {result.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return "Error: Command timeout"
    except Exception as e:
        return f"Error: {str(e)}"

def get_apache_binary() -> str:
    """Find Apache binary location"""
    possible_paths = [
        "/usr/sbin/apache2",
        "/usr/sbin/httpd",
        "/usr/local/apache2/bin/httpd",
        "/usr/local/bin/httpd",
        "/usr/bin/httpd"
    ]
    
    for path in possible_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    
    # Try which command
    result = run_cmd("which apache2")
    if not result.startswith("Error"):
        return result
    
    result = run_cmd("which httpd")
    if not result.startswith("Error"):
        return result
    
    return ""

def get_apache_config_dir() -> str:
    """Find Apache configuration directory"""
    possible_paths = [
        "/etc/apache2",
        "/etc/httpd",
        "/usr/local/apache2/conf",
        "/usr/local/etc/apache2"
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    return ""

def get_apache_root() -> str:
    """Get Apache ServerRoot"""
    apache_bin = get_apache_binary()
    if not apache_bin:
        return ""
    
    result = run_cmd(f"{apache_bin} -V | grep HTTPD_ROOT")
    if not result.startswith("Error"):
        # Extract value: -D HTTPD_ROOT="/etc/apache2"
        match = re.search(r'HTTPD_ROOT="([^"]+)"', result)
        if match:
            return match.group(1)
    
    # Default values based on OS
    config_dir = get_apache_config_dir()
    if config_dir:
        return os.path.dirname(config_dir) if config_dir != "/etc" else "/etc"
    
    return "/etc"

def get_enabled_modules() -> List[str]:
    """Get list of enabled Apache modules"""
    apache_bin = get_apache_binary()
    if not apache_bin:
        return []
    
    result = run_cmd(f"{apache_bin} -M")
    if result.startswith("Error"):
        return []
    
    modules = []
    for line in result.split('\n'):
        if "_module" in line:
            modules.append(line.strip())
    return modules

def expand_apache_path(pattern: str, base_dir: str, server_root: str) -> List[str]:
    """Expand Apache include patterns to actual file paths"""
    expanded_paths = []
    
    # Handle absolute paths
    if os.path.isabs(pattern):
        # If pattern is already absolute
        search_pattern = pattern
    else:
        # If pattern is relative, try both relative to current file and ServerRoot
        search_pattern = os.path.join(base_dir, pattern)
    
    # Check if pattern exists
    if os.path.exists(search_pattern):
        if os.path.isfile(search_pattern):
            expanded_paths.append(search_pattern)
        elif os.path.isdir(search_pattern):
            # Directory - include all files in directory (non-recursive)
            try:
                for file in os.listdir(search_pattern):
                    full_path = os.path.join(search_pattern, file)
                    if os.path.isfile(full_path) and not file.startswith('.'):
                        expanded_paths.append(full_path)
            except:
                pass
    else:
        # Try glob pattern matching
        import glob
        for path in glob.glob(search_pattern, recursive=False):
            if os.path.isfile(path):
                expanded_paths.append(path)
    
    return expanded_paths

def parse_config_file_recursive(config_path: str, visited: Set[str] = None, 
                               base_dir: str = None, server_root: str = None) -> List[str]:
    """
    Parse Apache configuration file recursively following Include directives
    Returns list of configuration lines without comments
    """
    if visited is None:
        visited = set()
    
    if config_path in visited:
        return []
    
    if base_dir is None:
        base_dir = os.path.dirname(config_path)
    
    if server_root is None:
        server_root = get_apache_root()
    
    # Use cache to avoid redundant parsing
    if config_path in config_cache:
        return config_cache[config_path]
    
    visited.add(config_path)
    all_lines = []
    
    try:
        if not os.path.exists(config_path):
            logger.warning(f"Config file not found: {config_path}")
            return []
        
        with open(config_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                # Remove leading/trailing whitespace
                original_line = line.rstrip('\n')
                line = original_line.strip()
                
                # Skip empty lines and full comment lines
                if not line or line.startswith('#'):
                    continue
                
                # Remove inline comments
                if '#' in line:
                    line = line.split('#')[0].strip()
                    if not line:
                        continue
                
                # Check for Include or IncludeOptional directive
                if line.lower().startswith('include') or line.lower().startswith('includeoptional'):
                    # Parse the include directive
                    parts = line.split(None, 1)
                    if len(parts) > 1:
                        include_pattern = parts[1].strip()
                        
                        # Handle quotes
                        if (include_pattern.startswith('"') and include_pattern.endswith('"')) or \
                           (include_pattern.startswith("'") and include_pattern.endswith("'")):
                            include_pattern = include_pattern[1:-1]
                        
                        # Expand the pattern
                        included_files = expand_apache_path(include_pattern, base_dir, server_root)
                        
                        # Recursively parse included files
                        for included_file in included_files:
                            included_dir = os.path.dirname(included_file)
                            included_lines = parse_config_file_recursive(
                                included_file, visited, included_dir, server_root
                            )
                            all_lines.extend(included_lines)
                else:
                    # Regular configuration line
                    all_lines.append(line)
    
    except Exception as e:
        logger.error(f"Error parsing config file {config_path}: {str(e)}")
    
    # Cache the result
    config_cache[config_path] = all_lines
    
    return all_lines

def parse_config_file(config_path: str) -> List[str]:
    """Wrapper for backward compatibility"""
    return parse_config_file_recursive(config_path)

def get_directive_value(directive: str, config_lines: List[str]) -> List[str]:
    """Get values for a directive from config lines"""
    values = []
    directive_lower = directive.lower()
    
    for line in config_lines:
        # Split line into words
        parts = line.split(None, 1)
        if parts and parts[0].lower() == directive_lower:
            if len(parts) > 1:
                values.append(parts[1].strip())
            else:
                values.append("")  # Directive with no value
    
    return values

def get_directive_from_all_files(directive: str, config_files: List[str]) -> List[str]:
    """Get directive values from multiple config files"""
    all_values = []
    
    for config_file in config_files:
        if os.path.exists(config_file):
            lines = parse_config_file(config_file)
            values = get_directive_value(directive, lines)
            all_values.extend(values)
    
    return all_values

def check_module_enabled(module_name: str) -> bool:
    """Check if a module is enabled"""
    modules = get_enabled_modules()
    for module in modules:
        if module_name in module:
            return True
    return False

def get_apache_user() -> str:
    """Get Apache user from configuration"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return ""
    
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        user_values = get_directive_value('User', lines)
        if user_values:
            return user_values[0]
    return ""

# ============================================
# CIS CHECK FUNCTIONS - PILLAR 1
# ============================================

def check_2_1() -> Tuple[str, str]:
    """2.1 Ensure Only Necessary Authentication and Authorization Modules Are Enabled"""
    modules = get_enabled_modules()
    auth_modules = []
    for module in modules:
        if 'auth' in module.lower():
            auth_modules.append(module)
    
    if auth_modules:
        return "MANUAL", f"Found auth modules: {', '.join(auth_modules[:3])}..."
    else:
        return "PASS", "No auth modules found (or not enabled)"

def check_2_2() -> Tuple[str, str]:
    """2.2 Ensure the Log Config Module Is Enabled"""
    if check_module_enabled('log_config'):
        return "PASS", "log_config module is enabled"
    else:
        return "FAIL", "log_config module is not enabled"

def check_2_3() -> Tuple[str, str]:
    """2.3 Ensure the WebDAV Modules Are Disabled"""
    dav_modules = ['dav', 'dav_fs', 'dav_lock']
    enabled_dav = []
    
    for module in dav_modules:
        if check_module_enabled(module):
            enabled_dav.append(module)
    
    if enabled_dav:
        return "FAIL", f"WebDAV modules enabled: {', '.join(enabled_dav)}"
    else:
        return "PASS", "WebDAV modules are disabled"

def check_2_4() -> Tuple[str, str]:
    """2.4 Ensure the Status Module Is Disabled"""
    if check_module_enabled('status'):
        return "FAIL", "status_module is enabled"
    else:
        return "PASS", "status_module is disabled"

def check_2_5() -> Tuple[str, str]:
    """2.5 Ensure the Autoindex Module Is Disabled"""
    if check_module_enabled('autoindex'):
        return "FAIL", "autoindex_module is enabled"
    else:
        return "PASS", "autoindex_module is disabled"

def check_2_6() -> Tuple[str, str]:
    """2.6 Ensure the Proxy Modules Are Disabled if not in use"""
    proxy_modules = ['proxy', 'proxy_http', 'proxy_connect', 'proxy_ftp']
    enabled_proxy = []
    
    for module in proxy_modules:
        if check_module_enabled(module):
            enabled_proxy.append(module)
    
    if enabled_proxy:
        return "MANUAL", f"Proxy modules enabled: {', '.join(enabled_proxy)} - Verify if needed"
    else:
        return "PASS", "Proxy modules are disabled"

def check_2_7() -> Tuple[str, str]:
    """2.7 Ensure the User Directories Module Is Disabled"""
    if check_module_enabled('userdir'):
        return "FAIL", "userdir_module is enabled"
    else:
        return "PASS", "userdir_module is disabled"

def check_2_8() -> Tuple[str, str]:
    """2.8 Ensure the Info Module Is Disabled"""
    if check_module_enabled('info'):
        return "FAIL", "info_module is enabled"
    else:
        return "PASS", "info_module is disabled"

def check_2_9() -> Tuple[str, str]:
    """2.9 Ensure the Basic and Digest Authentication Modules are Disabled"""
    auth_modules = ['auth_basic', 'auth_digest']
    enabled_auth = []
    
    for module in auth_modules:
        if check_module_enabled(module):
            enabled_auth.append(module)
    
    if enabled_auth:
        return "MANUAL", f"Basic/Digest auth modules enabled: {', '.join(enabled_auth)}"
    else:
        return "PASS", "Basic/Digest auth modules are disabled"

def check_5_4() -> Tuple[str, str]:
    """5.4 Ensure Default HTML Content Is Removed (Manual)"""
    # Check for default content
    default_paths = [
        "/var/www/html/index.html",
        "/usr/share/apache2/default-site/index.html",
        "/var/www/index.html"
    ]
    
    found_default = []
    for path in default_paths:
        if os.path.exists(path):
            found_default.append(path)
    
    if found_default:
        return "MANUAL", f"Default HTML content found: {', '.join(found_default)}"
    else:
        return "PASS", "No default HTML content found"

def check_5_5() -> Tuple[str, str]:
    """5.5 Ensure the Default CGI Content printenv Script Is Removed"""
    cgi_paths = [
        "/usr/lib/cgi-bin/printenv",
        "/var/www/cgi-bin/printenv",
        "/usr/local/apache2/cgi-bin/printenv"
    ]
    
    for path in cgi_paths:
        if os.path.exists(path):
            return "MANUAL", f"printenv CGI script found: {path}"
    
    return "PASS", "printenv CGI script not found"

def check_5_6() -> Tuple[str, str]:
    """5.6 Ensure the Default CGI Content test-cgi Script Is Removed"""
    cgi_paths = [
        "/usr/lib/cgi-bin/test-cgi",
        "/var/www/cgi-bin/test-cgi",
        "/usr/local/apache2/cgi-bin/test-cgi"
    ]
    
    for path in cgi_paths:
        if os.path.exists(path):
            return "MANUAL", f"test-cgi script found: {path}"
    
    return "PASS", "test-cgi script not found"

def check_8_1() -> Tuple[str, str]:
    """8.1 Ensure ServerTokens is Set to 'Prod' or 'ProductOnly'"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    # Look for ServerTokens in all config files
    config_files = [
        f"{config_dir}/apache2.conf",
        f"{config_dir}/httpd.conf",
        f"{config_dir}/conf-enabled/security.conf",
        f"{config_dir}/conf-available/security.conf"
    ]
    
    for config_file in config_files:
        if os.path.exists(config_file):
            lines = parse_config_file(config_file)
            values = get_directive_value('ServerTokens', lines)
            if values:
                value = values[0].lower()
                if value in ['prod', 'productonly']:
                    return "PASS", f"ServerTokens is set to '{value}' in {config_file}"
                else:
                    return "FAIL", f"ServerTokens is set to '{value}' in {config_file} (should be Prod or ProductOnly)"
    
    return "FAIL", "ServerTokens directive not found or not properly configured"

def check_8_2() -> Tuple[str, str]:
    """8.2 Ensure ServerSignature Is Not Enabled"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    config_files = [
        f"{config_dir}/apache2.conf",
        f"{config_dir}/httpd.conf",
        f"{config_dir}/conf-enabled/security.conf",
        f"{config_dir}/conf-available/security.conf"
    ]
    
    for config_file in config_files:
        if os.path.exists(config_file):
            lines = parse_config_file(config_file)
            values = get_directive_value('ServerSignature', lines)
            if values:
                value = values[0].lower()
                if value == 'off':
                    return "PASS", f"ServerSignature is set to '{value}' in {config_file}"
                else:
                    return "FAIL", f"ServerSignature is set to '{value}' in {config_file} (should be Off)"
    
    return "PASS", "ServerSignature directive not found (default is Off)"

def check_8_3() -> Tuple[str, str]:
    """8.3 Ensure All Default Apache Content Is Removed (Manual)"""
    # Check for Apache icons and manuals
    default_content = [
        "/usr/share/apache2/icons",
        "/usr/share/doc/apache2",
        "/var/www/manual"
    ]
    
    found_content = []
    for path in default_content:
        if os.path.exists(path):
            found_content.append(path)
    
    if found_content:
        return "MANUAL", f"Default Apache content found: {', '.join(found_content)}"
    else:
        return "PASS", "No default Apache content found"

def check_8_4() -> Tuple[str, str]:
    """8.4 Ensure ETag Response Header Fields Do Not Include Inodes"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    config_files = [
        f"{config_dir}/apache2.conf",
        f"{config_dir}/httpd.conf",
        f"{config_dir}/conf-enabled/security.conf",
        f"{config_dir}/conf-available/security.conf"
    ]
    
    for config_file in config_files:
        if os.path.exists(config_file):
            lines = parse_config_file(config_file)
            values = get_directive_value('FileETag', lines)
            if values:
                value = values[0].lower()
                if 'inode' in value or value == 'all':
                    return "FAIL", f"FileETag includes inode: '{value}' in {config_file}"
                else:
                    return "PASS", f"FileETag properly configured: '{value}' in {config_file}"
    
    return "PASS", "FileETag directive not found (default is MTime Size)"

# ============================================
# CIS CHECK FUNCTIONS - PILLAR 2
# ============================================

def check_3_1() -> Tuple[str, str]:
    """3.1 Ensure the Apache Web Server Runs As a Non-Root User"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        user_values = get_directive_value('User', lines)
        group_values = get_directive_value('Group', lines)
        
        if not user_values or not group_values:
            return "FAIL", "User or Group directive not found"
        
        user = user_values[0]
        group = group_values[0]
        
        if user in ['root', 'daemon']:
            return "FAIL", f"Apache runs as user '{user}' (should be a dedicated non-root user)"
        else:
            return "PASS", f"Apache runs as user '{user}' and group '{group}'"
    
    return "ERROR", "Could not find main Apache config file"

def check_3_2() -> Tuple[str, str]:
    """3.2 Ensure the Apache User Account Has an Invalid Shell"""
    apache_user = get_apache_user()
    if not apache_user:
        return "SKIP", "Apache user not found in config"
    
    try:
        user_info = pwd.getpwnam(apache_user)
        shell = user_info.pw_shell
        
        invalid_shells = ['/sbin/nologin', '/usr/sbin/nologin', '/bin/false', '/dev/null']
        
        if shell in invalid_shells:
            return "PASS", f"Apache user '{apache_user}' has invalid shell: {shell}"
        else:
            return "FAIL", f"Apache user '{apache_user}' has valid shell: {shell}"
    except KeyError:
        return "ERROR", f"User '{apache_user}' not found in system"

def check_3_3() -> Tuple[str, str]:
    """3.3 Ensure the Apache User Account Is Locked"""
    apache_user = get_apache_user()
    if not apache_user:
        return "SKIP", "Apache user not found in config"
    
    try:
        # Check if account is locked
        result = run_cmd(f"passwd -S {apache_user}")
        if "LK" in result or "L" in result:
            return "PASS", f"Apache user '{apache_user}' is locked"
        else:
            return "FAIL", f"Apache user '{apache_user}' is not locked"
    except:
        return "ERROR", f"Could not check lock status for user '{apache_user}'"

def check_3_4() -> Tuple[str, str]:
    """3.4 Ensure Apache Directories and Files Are Owned By Root"""
    # Check common Apache directories
    apache_dirs = [
        "/etc/apache2",
        "/etc/httpd",
        "/usr/lib/apache2",
        "/var/log/apache2"
    ]
    
    non_root_dirs = []
    for apache_dir in apache_dirs:
        if os.path.exists(apache_dir):
            try:
                # Check directory itself
                stat_info = os.stat(apache_dir)
                if stat_info.st_uid != 0:
                    non_root_dirs.append(apache_dir)
            except:
                pass
    
    if non_root_dirs:
        return "FAIL", f"Found directories not owned by root: {', '.join(non_root_dirs[:3])}"
    else:
        return "PASS", "All Apache directories are owned by root"

def check_3_5() -> Tuple[str, str]:
    """3.5 Ensure the Group Is Set Correctly on Apache Directories and Files"""
    apache_dirs = [
        "/etc/apache2",
        "/etc/httpd",
        "/usr/lib/apache2"
    ]
    
    non_root_group = []
    for apache_dir in apache_dirs:
        if os.path.exists(apache_dir):
            try:
                stat_info = os.stat(apache_dir)
                if stat_info.st_gid != 0:
                    # Get group name
                    try:
                        group_name = grp.getgrgid(stat_info.st_gid).gr_name
                        non_root_group.append(f"{apache_dir}:{group_name}")
                    except:
                        non_root_group.append(apache_dir)
            except:
                pass
    
    if non_root_group:
        return "FAIL", f"Found items with non-root group: {', '.join(non_root_group[:3])}"
    else:
        return "PASS", "All Apache directories have root group"

def check_3_6() -> Tuple[str, str]:
    """3.6 Ensure Other Write Access on Apache Directories and Files Is Restricted"""
    apache_dirs = [
        "/etc/apache2",
        "/usr/lib/apache2"
    ]
    
    other_write = []
    for apache_dir in apache_dirs:
        if os.path.exists(apache_dir):
            try:
                for root, dirs, files in os.walk(apache_dir):
                    for name in files[:10]:  # Check first 10 files
                        full_path = os.path.join(root, name)
                        try:
                            stat_info = os.stat(full_path)
                            if stat_info.st_mode & stat.S_IWOTH:  # Other write permission
                                other_write.append(full_path)
                        except:
                            pass
                    break  # Only check top level
            except:
                pass
    
    if other_write:
        return "FAIL", f"Found {len(other_write)} files with other write access"
    else:
        return "PASS", "No files with other write access found"

def check_3_11() -> Tuple[str, str]:
    """3.11 Ensure Group Write Access for the Apache Directories and Files Is Properly Restricted"""
    apache_dirs = [
        "/etc/apache2",
        "/usr/lib/apache2",
        "/var/log/apache2"
    ]
    
    group_write = []
    for apache_dir in apache_dirs:
        if os.path.exists(apache_dir):
            try:
                stat_info = os.stat(apache_dir)
                if stat_info.st_mode & stat.S_IWGRP:  # Group write permission
                    group_write.append(apache_dir)
            except:
                pass
    
    if group_write:
        return "MANUAL", f"Found directories with group write: {', '.join(group_write)}"
    else:
        return "PASS", "No directories with group write access found"

def check_3_12() -> Tuple[str, str]:
    """3.12 Ensure Group Write Access for the Document Root Directories and Files Is Properly Restricted"""
    # Check common document roots
    doc_roots = [
        "/var/www/html",
        "/var/www",
        "/usr/local/apache2/htdocs"
    ]
    
    group_write = []
    for doc_root in doc_roots:
        if os.path.exists(doc_root):
            try:
                stat_info = os.stat(doc_root)
                if stat_info.st_mode & stat.S_IWGRP:
                    group_write.append(doc_root)
            except:
                pass
    
    if group_write:
        return "MANUAL", f"Document roots with group write: {', '.join(group_write)}"
    else:
        return "PASS", "Document roots properly restricted"

def check_4_1() -> Tuple[str, str]:
    """4.1 Ensure Access to OS Root Directory Is Denied By Default"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        
        # Look for <Directory /> or <Directory "/"> sections
        in_root_dir = False
        root_dir_denied = False
        
        for line in lines:
            if line.lower().startswith('<directory') and ('/>' in line.lower() or '"/">' in line.lower()):
                in_root_dir = True
                continue
            elif line.lower().startswith('</directory>') and in_root_dir:
                in_root_dir = False
                continue
            
            if in_root_dir:
                if 'require all denied' in line.lower() or 'deny from all' in line.lower():
                    root_dir_denied = True
        
        if root_dir_denied:
            return "PASS", "Root directory access properly denied"
        else:
            return "FAIL", "Root directory not properly denied"
    
    return "FAIL", "Root directory configuration not found"

def check_4_4() -> Tuple[str, str]:
    """4.4 Ensure OverRide Is Disabled for All Directories"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        
        in_directory = False
        directory_stack = []
        
        for line in lines:
            # Check for Directory sections
            if line.lower().startswith('<directory'):
                in_directory = True
                directory_stack.append(line)
                continue
            elif line.lower().startswith('</directory>'):
                if directory_stack:
                    directory_stack.pop()
                if not directory_stack:
                    in_directory = False
                continue
            
            # Check AllowOverride directive
            if in_directory and line.lower().startswith('allowoverride'):
                if 'none' not in line.lower():
                    return "FAIL", f"AllowOverride not set to None: {line}"
        
        return "PASS", "AllowOverride is set to None for all directories (or not found)"
    
    return "PASS", "AllowOverride directive not found (default may be None)"

def check_5_1() -> Tuple[str, str]:
    """5.1 Ensure Options for the OS Root Directory Are Restricted"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        
        in_root_dir = False
        root_dir_options = False
        
        for line in lines:
            if line.lower().startswith('<directory') and ('/>' in line.lower() or '"/">' in line.lower()):
                in_root_dir = True
                continue
            elif line.lower().startswith('</directory>') and in_root_dir:
                in_root_dir = False
                continue
            
            if in_root_dir and line.lower().startswith('options'):
                root_dir_options = True
                if 'none' in line.lower() or '-all' in line.lower():
                    return "PASS", "Root directory Options properly restricted"
                else:
                    return "FAIL", f"Root directory Options not restricted: {line}"
        
        if not root_dir_options:
            return "MANUAL", "Root directory Options directive not found"
    
    return "MANUAL", "Root directory configuration not found"

def check_5_10() -> Tuple[str, str]:
    """5.10 Ensure Access to .ht* Files Is Restricted"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    config_files = [
        f"{config_dir}/apache2.conf",
        f"{config_dir}/httpd.conf",
        f"{config_dir}/conf-enabled/security.conf",
        f"{config_dir}/conf-available/security.conf"
    ]
    
    for config_file in config_files:
        if os.path.exists(config_file):
            lines = parse_config_file(config_file)
            
            in_filesmatch = False
            ht_restricted = False
            
            for line in lines:
                if '<filesmatch' in line.lower() and '\.ht' in line.lower():
                    in_filesmatch = True
                    continue
                elif '</filesmatch>' in line.lower() and in_filesmatch:
                    in_filesmatch = False
                    continue
                
                if in_filesmatch:
                    if 'require all denied' in line.lower() or 'deny from all' in line.lower():
                        ht_restricted = True
            
            if ht_restricted:
                return "PASS", f".ht* files restricted in {config_file}"
    
    return "FAIL", ".ht* files access is not restricted"

def check_5_11() -> Tuple[str, str]:
    """5.11 Ensure Access to .git Files Is Restricted"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    config_files = [
        f"{config_dir}/apache2.conf",
        f"{config_dir}/httpd.conf"
    ]
    
    for config_file in config_files:
        if os.path.exists(config_file):
            lines = parse_config_file(config_file)
            
            # Look for FilesMatch or DirectoryMatch with .git
            for i, line in enumerate(lines):
                if (('filesmatch' in line.lower() or 'directorymatch' in line.lower()) and 
                    '\.git' in line.lower()):
                    
                    # Check if access is denied in the section
                    for j in range(i, min(i+10, len(lines))):
                        if '</filesmatch>' in lines[j].lower() or '</directorymatch>' in lines[j].lower():
                            break
                        if 'require all denied' in lines[j].lower() or 'deny from all' in lines[j].lower():
                            return "PASS", f".git files restricted in {config_file}"
    
    return "MANUAL", ".git files access restriction not found"

def check_5_12() -> Tuple[str, str]:
    """5.12 Ensure Access to .svn Files Is Restricted"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    config_files = [
        f"{config_dir}/apache2.conf",
        f"{config_dir}/httpd.conf"
    ]
    
    for config_file in config_files:
        if os.path.exists(config_file):
            lines = parse_config_file(config_file)
            
            # Look for FilesMatch or DirectoryMatch with .svn
            for i, line in enumerate(lines):
                if (('filesmatch' in line.lower() or 'directorymatch' in line.lower()) and 
                    '\.svn' in line.lower()):
                    
                    # Check if access is denied in the section
                    for j in range(i, min(i+10, len(lines))):
                        if '</filesmatch>' in lines[j].lower() or '</directorymatch>' in lines[j].lower():
                            break
                        if 'require all denied' in lines[j].lower() or 'deny from all' in lines[j].lower():
                            return "PASS", f".svn files restricted in {config_file}"
    
    return "MANUAL", ".svn files access restriction not found"

def check_5_13() -> Tuple[str, str]:
    """5.13 Ensure Access to Inappropriate File Extensions Is Restricted"""
    # This is complex to check automatically
    return "MANUAL", "Manual review required for file extension restrictions"

def check_5_2() -> Tuple[str, str]:
    """5.2 Ensure Options for the Web Root Directory Are Restricted"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    # Get web root from configuration
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        
        # Find DocumentRoot
        docroot_values = get_directive_value('DocumentRoot', lines)
        if docroot_values:
            docroot = docroot_values[0]
            
            # Find Directory section for DocumentRoot
            in_docroot_dir = False
            docroot_found = False
            
            for line in lines:
                if line.lower().startswith('<directory') and docroot in line.lower():
                    in_docroot_dir = True
                    docroot_found = True
                    continue
                elif line.lower().startswith('</directory>') and in_docroot_dir:
                    in_docroot_dir = False
                    continue
                
                if in_docroot_dir and line.lower().startswith('options'):
                    if 'none' in line.lower() or '-all' in line.lower() or '-indexes' in line.lower():
                        return "PASS", f"DocumentRoot Options properly restricted: {line}"
                    else:
                        return "MANUAL", f"DocumentRoot Options not minimal: {line}"
            
            if docroot_found:
                return "MANUAL", f"DocumentRoot found but Options not specified"
    
    return "MANUAL", "Manual review required for web root Options"

def check_5_3() -> Tuple[str, str]:
    """5.3 Ensure Options for Other Directories Are Minimized"""
    return "MANUAL", "Manual review required for directory Options"

# ============================================
# CIS CHECK FUNCTIONS - PILLAR 3
# ============================================

def check_7_1() -> Tuple[str, str]:
    """7.1 Ensure mod_ssl and/or mod_nss Is Installed"""
    ssl_enabled = check_module_enabled('ssl')
    nss_enabled = check_module_enabled('nss')
    
    if ssl_enabled or nss_enabled:
        return "PASS", "SSL/TLS module is enabled"
    else:
        return "MANUAL", "SSL/TLS module is not enabled (enable if HTTPS is required)"

def check_7_3() -> Tuple[str, str]:
    """7.3 Ensure the Server's Private Key Is Protected (Manual)"""
    # Check for private key files
    key_paths = [
        "/etc/ssl/private",
        "/etc/apache2/ssl",
        "/etc/httpd/conf/ssl.key"
    ]
    
    for path in key_paths:
        if os.path.exists(path):
            return "MANUAL", f"SSL private key directory found: {path}"
    
    return "MANUAL", "SSL private key protection requires manual verification"

def check_7_4() -> Tuple[str, str]:
    """7.4 Ensure the TLSv1.0 and TLSv1.1 Protocols are Disabled"""
    if not check_module_enabled('ssl'):
        return "SKIP", "SSL module not enabled"
    
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    # Look for SSL configuration in all possible locations
    ssl_configs = [
        f"{config_dir}/mods-enabled/ssl.conf",
        f"{config_dir}/conf-enabled/ssl.conf",
        f"{config_dir}/extra/httpd-ssl.conf",
        f"{config_dir}/sites-enabled/default-ssl.conf",
        f"{config_dir}/sites-available/default-ssl.conf"
    ]
    
    # Also check main config for SSL directives
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        ssl_configs.append(main_config)
    
    for config_file in ssl_configs:
        if os.path.exists(config_file):
            lines = parse_config_file(config_file)
            values = get_directive_value('SSLProtocol', lines)
            if values:
                value = values[0]
                # Check if TLSv1.0 or TLSv1.1 are allowed
                if 'TLSv1' in value and not ('-TLSv1' in value or '!TLSv1' in value):
                    return "FAIL", f"SSLProtocol allows old TLS versions: {value} in {config_file}"
                else:
                    return "PASS", f"SSLProtocol properly configured: {value} in {config_file}"
    
    return "MANUAL", "SSLProtocol directive not found (check SSL configuration)"

def check_7_5() -> Tuple[str, str]:
    """7.5 Ensure Weak SSL/TLS Ciphers Are Disabled"""
    if not check_module_enabled('ssl'):
        return "SKIP", "SSL module not enabled"
    
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    ssl_configs = [
        f"{config_dir}/mods-enabled/ssl.conf",
        f"{config_dir}/conf-enabled/ssl.conf",
        f"{config_dir}/sites-enabled/default-ssl.conf"
    ]
    
    weak_ciphers = ['RC4', 'MD5', 'DES', 'EXP', 'NULL', 'ADH', 'AECDH']
    
    for config_file in ssl_configs:
        if os.path.exists(config_file):
            lines = parse_config_file(config_file)
            values = get_directive_value('SSLCipherSuite', lines)
            if values:
                value = values[0].upper()
                found_weak = []
                for cipher in weak_ciphers:
                    if cipher in value:
                        found_weak.append(cipher)
                
                if found_weak:
                    return "FAIL", f"SSLCipherSuite contains weak ciphers: {', '.join(found_weak)}"
                else:
                    return "PASS", f"SSLCipherSuite seems properly configured"
    
    return "MANUAL", "SSLCipherSuite directive not found"

def check_7_6() -> Tuple[str, str]:
    """7.6 Ensure Insecure SSL Renegotiation Is Not Enabled"""
    if not check_module_enabled('ssl'):
        return "SKIP", "SSL module not enabled"
    
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    ssl_configs = [
        f"{config_dir}/mods-enabled/ssl.conf",
        f"{config_dir}/conf-enabled/ssl.conf"
    ]
    
    for config_file in ssl_configs:
        if os.path.exists(config_file):
            lines = parse_config_file(config_file)
            values = get_directive_value('SSLInsecureRenegotiation', lines)
            if values:
                value = values[0].lower()
                if value == 'off':
                    return "PASS", f"SSLInsecureRenegotiation is off"
                else:
                    return "FAIL", f"SSLInsecureRenegotiation is {value} (should be off)"
    
    return "PASS", "SSLInsecureRenegotiation directive not found (default is off)"

def check_7_7() -> Tuple[str, str]:
    """7.7 Ensure SSL Compression is not Enabled"""
    if not check_module_enabled('ssl'):
        return "SKIP", "SSL module not enabled"
    
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    ssl_configs = [
        f"{config_dir}/mods-enabled/ssl.conf",
        f"{config_dir}/conf-enabled/ssl.conf"
    ]
    
    for config_file in ssl_configs:
        if os.path.exists(config_file):
            lines = parse_config_file(config_file)
            values = get_directive_value('SSLCompression', lines)
            if values:
                value = values[0].lower()
                if value == 'off':
                    return "PASS", f"SSLCompression is off"
                else:
                    return "FAIL", f"SSLCompression is {value} (should be off)"
    
    return "PASS", "SSLCompression directive not found (implicitly disabled in newer versions)"

def check_7_8() -> Tuple[str, str]:
    """7.8 Ensure Medium Strength SSL/TLS Ciphers Are Disabled"""
    if not check_module_enabled('ssl'):
        return "SKIP", "SSL module not enabled"
    
    return "MANUAL", "Manual verification required for medium strength ciphers"

def check_7_9() -> Tuple[str, str]:
    """7.9 Ensure All Web Content is Accessed via HTTPS"""
    # Check if SSL is enabled
    if not check_module_enabled('ssl'):
        return "MANUAL", "SSL not enabled - HTTPS not available"
    
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    # Check VirtualHost configurations
    vhost_configs = [
        f"{config_dir}/sites-enabled",
        f"{config_dir}/vhosts.d",
        f"{config_dir}/extra/httpd-vhosts.conf"
    ]
    
    http_only_vhosts = []
    
    for vhost_path in vhost_configs:
        if os.path.exists(vhost_path):
            if os.path.isdir(vhost_path):
                # Directory - check all .conf files
                for file in os.listdir(vhost_path):
                    if file.endswith('.conf'):
                        config_file = os.path.join(vhost_path, file)
                        lines = parse_config_file(config_file)
                        
                        # Check for VirtualHost sections
                        in_virtualhost = False
                        vhost_has_ssl = False
                        
                        for line in lines:
                            if '<virtualhost' in line.lower():
                                in_virtualhost = True
                                if ':443' in line.lower() or 'ssl' in line.lower():
                                    vhost_has_ssl = True
                                continue
                            elif '</virtualhost>' in line.lower():
                                if in_virtualhost and not vhost_has_ssl:
                                    http_only_vhosts.append(config_file)
                                in_virtualhost = False
                                vhost_has_ssl = False
                                continue
            
            elif os.path.isfile(vhost_path):
                # Single file
                lines = parse_config_file(vhost_path)
                
                # Similar logic for single file
                in_virtualhost = False
                vhost_has_ssl = False
                
                for line in lines:
                    if '<virtualhost' in line.lower():
                        in_virtualhost = True
                        if ':443' in line.lower() or 'ssl' in line.lower():
                            vhost_has_ssl = True
                        continue
                    elif '</virtualhost>' in line.lower():
                        if in_virtualhost and not vhost_has_ssl:
                            http_only_vhosts.append(vhost_path)
                        in_virtualhost = False
                        vhost_has_ssl = False
                        continue
    
    if http_only_vhosts:
        return "MANUAL", f"HTTP-only VirtualHosts found: {', '.join(http_only_vhosts[:3])}"
    else:
        return "PASS", "All VirtualHosts appear to use HTTPS"

def check_7_11() -> Tuple[str, str]:
    """7.11 Ensure HTTP Strict Transport Security Is Enabled"""
    if not check_module_enabled('ssl'):
        return "SKIP", "SSL module not enabled"
    
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    # Check various config files for HSTS header
    config_files = [
        f"{config_dir}/apache2.conf",
        f"{config_dir}/httpd.conf",
        f"{config_dir}/conf-enabled/security.conf",
        f"{config_dir}/sites-enabled/default-ssl.conf",
        f"{config_dir}/mods-enabled/ssl.conf"
    ]
    
    for config_file in config_files:
        if os.path.exists(config_file):
            lines = parse_config_file(config_file)
            
            for line in lines:
                if 'strict-transport-security' in line.lower() or 'hsts' in line.lower():
                    return "PASS", f"HSTS header found in {config_file}"
    
    return "MANUAL", "HSTS header not found (manual configuration required)"

def check_7_12() -> Tuple[str, str]:
    """7.12 Ensure Only Cipher Suites That Provide Forward Secrecy Are Enabled"""
    if not check_module_enabled('ssl'):
        return "SKIP", "SSL module not enabled"
    
    return "MANUAL", "Manual verification required for forward secrecy ciphers"

# ============================================
# CIS CHECK FUNCTIONS - PILLAR 4
# ============================================

def check_5_7() -> Tuple[str, str]:
    """5.7 Ensure HTTP Request Methods Are Restricted"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    # Look for LimitExcept or Limit directives
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        
        for line in lines:
            if '<limit' in line.lower() or '<limitexcept' in line.lower():
                return "PASS", "HTTP method restrictions found"
    
    return "MANUAL", "HTTP method restrictions not found (manual configuration required)"

def check_5_8() -> Tuple[str, str]:
    """5.8 Ensure the HTTP TRACE Method Is Disabled"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    config_files = [
        f"{config_dir}/apache2.conf",
        f"{config_dir}/httpd.conf",
        f"{config_dir}/conf-enabled/security.conf",
        f"{config_dir}/conf-available/security.conf"
    ]
    
    for config_file in config_files:
        if os.path.exists(config_file):
            lines = parse_config_file(config_file)
            values = get_directive_value('TraceEnable', lines)
            if values:
                value = values[0].lower()
                if value == 'off':
                    return "PASS", f"TraceEnable is set to '{value}' in {config_file}"
                else:
                    return "FAIL", f"TraceEnable is set to '{value}' in {config_file} (should be Off)"
    
    return "FAIL", "TraceEnable directive not found (default is On)"

def check_5_9() -> Tuple[str, str]:
    """5.9 Ensure Old HTTP Protocol Versions Are Disallowed"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    # Check for mod_rewrite rules in all configs
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        
        for line in lines:
            if 'rewriteengine' in line.lower() and 'on' in line.lower():
                # Look for HTTP version restrictions
                for i, l in enumerate(lines):
                    if 'rewritecond' in l.lower() and 'http/1\\.1' in l.lower():
                        return "PASS", "HTTP protocol restrictions found"
    
    return "MANUAL", "HTTP protocol restrictions not found"

def check_5_16() -> Tuple[str, str]:
    """5.16 Ensure Browser Framing Is Restricted (Clickjacking)"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    config_files = [
        f"{config_dir}/apache2.conf",
        f"{config_dir}/httpd.conf",
        f"{config_dir}/conf-enabled/security.conf",
        f"{config_dir}/conf-available/security.conf"
    ]
    
    for config_file in config_files:
        if os.path.exists(config_file):
            lines = parse_config_file(config_file)
            
            for line in lines:
                if 'x-frame-options' in line.lower() or 'content-security-policy' in line.lower():
                    return "PASS", "Clickjacking protection headers found"
    
    return "MANUAL", "Clickjacking protection headers not found"

def check_6_1() -> Tuple[str, str]:
    """6.1 Ensure the Error Log Filename and Severity Level Are Configured Correctly"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        loglevel = get_directive_value('LogLevel', lines)
        errorlog = get_directive_value('ErrorLog', lines)
        
        if not loglevel:
            return "MANUAL", "LogLevel directive not found"
        if not errorlog:
            return "MANUAL", "ErrorLog directive not found"
        
        return "PASS", f"LogLevel: {loglevel[0] if loglevel else 'N/A'}, ErrorLog configured"
    
    return "ERROR", "Could not find main Apache config file"

def check_6_3() -> Tuple[str, str]:
    """6.3 Ensure the Server Access Log Is Configured Correctly"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        customlog = get_directive_value('CustomLog', lines)
        
        if customlog:
            return "PASS", "CustomLog directive found"
        else:
            return "MANUAL", "CustomLog directive not found"
    
    return "ERROR", "Could not find main Apache config file"

def check_9_1() -> Tuple[str, str]:
    """9.1 Ensure the TimeOut Is Set to 10 or Less"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        values = get_directive_value('Timeout', lines)
        if values:
            try:
                timeout = int(values[0])
                if timeout <= 10:
                    return "PASS", f"Timeout is set to {timeout}"
                else:
                    return "FAIL", f"Timeout is set to {timeout} (should be ≤ 10)"
            except ValueError:
                return "ERROR", f"Invalid Timeout value: {values[0]}"
    
    return "FAIL", "Timeout directive not found (default is 60)"

def check_9_2() -> Tuple[str, str]:
    """9.2 Ensure KeepAlive Is Enabled"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        values = get_directive_value('KeepAlive', lines)
        if values:
            value = values[0].lower()
            if value == 'on':
                return "PASS", f"KeepAlive is {value}"
            else:
                return "FAIL", f"KeepAlive is {value} (should be On)"
    
    return "PASS", "KeepAlive directive not found (default is On)"

def check_9_3() -> Tuple[str, str]:
    """9.3 Ensure MaxKeepAliveRequests is Set to 100 or Greater"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        values = get_directive_value('MaxKeepAliveRequests', lines)
        if values:
            try:
                max_req = int(values[0])
                if max_req >= 100:
                    return "PASS", f"MaxKeepAliveRequests is set to {max_req}"
                else:
                    return "FAIL", f"MaxKeepAliveRequests is set to {max_req} (should be ≥ 100)"
            except ValueError:
                return "ERROR", f"Invalid MaxKeepAliveRequests value: {values[0]}"
    
    return "PASS", "MaxKeepAliveRequests directive not found (default is 100)"

def check_9_4() -> Tuple[str, str]:
    """9.4 Ensure KeepAliveTimeout is Set to 15 or Less"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        values = get_directive_value('KeepAliveTimeout', lines)
        if values:
            try:
                timeout = int(values[0])
                if timeout <= 15:
                    return "PASS", f"KeepAliveTimeout is set to {timeout}"
                else:
                    return "FAIL", f"KeepAliveTimeout is set to {timeout} (should be ≤ 15)"
            except ValueError:
                return "ERROR", f"Invalid KeepAliveTimeout value: {values[0]}"
    
    return "PASS", "KeepAliveTimeout directive not found (default is 5)"

def check_10_1() -> Tuple[str, str]:
    """10.1 Ensure the LimitRequestLine directive is Set to 8190 or less"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        values = get_directive_value('LimitRequestLine', lines)
        if values:
            try:
                limit = int(values[0])
                if limit <= 8190 and limit > 0:
                    return "PASS", f"LimitRequestLine is set to {limit}"
                else:
                    return "FAIL", f"LimitRequestLine is set to {limit} (should be ≤ 8190 and > 0)"
            except ValueError:
                return "ERROR", f"Invalid LimitRequestLine value: {values[0]}"
    
    return "PASS", "LimitRequestLine directive not found (default is 8190)"

def check_10_2() -> Tuple[str, str]:
    """10.2 Ensure the LimitRequestFields Directive is Set to 100 or Less"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        values = get_directive_value('LimitRequestFields', lines)
        if values:
            try:
                limit = int(values[0])
                if limit <= 100 and limit > 0:
                    return "PASS", f"LimitRequestFields is set to {limit}"
                else:
                    return "FAIL", f"LimitRequestFields is set to {limit} (should be ≤ 100 and > 0)"
            except ValueError:
                return "ERROR", f"Invalid LimitRequestFields value: {values[0]}"
    
    return "PASS", "LimitRequestFields directive not found (default is 100)"

def check_10_3() -> Tuple[str, str]:
    """10.3 Ensure the LimitRequestFieldsize Directive is Set to 8190 or Less"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        values = get_directive_value('LimitRequestFieldsize', lines)
        if values:
            try:
                limit = int(values[0])
                if limit <= 8190:
                    return "PASS", f"LimitRequestFieldsize is set to {limit}"
                else:
                    return "FAIL", f"LimitRequestFieldsize is set to {limit} (should be ≤ 8190)"
            except ValueError:
                return "ERROR", f"Invalid LimitRequestFieldsize value: {values[0]}"
    
    return "PASS", "LimitRequestFieldsize directive not found (default is 8190)"

def check_10_4() -> Tuple[str, str]:
    """10.4 Ensure the LimitRequestBody Directive is Set to 102400 or Less"""
    config_dir = get_apache_config_dir()
    if not config_dir:
        return "ERROR", "Could not find Apache config directory"
    
    main_config = f"{config_dir}/apache2.conf"
    if not os.path.exists(main_config):
        main_config = f"{config_dir}/httpd.conf"
    
    if os.path.exists(main_config):
        lines = parse_config_file(main_config)
        values = get_directive_value('LimitRequestBody', lines)
        if values:
            try:
                limit = int(values[0])
                if limit <= 102400 and limit > 0:
                    return "PASS", f"LimitRequestBody is set to {limit}"
                else:
                    return "FAIL", f"LimitRequestBody is set to {limit} (should be ≤ 102400 and > 0)"
            except ValueError:
                return "ERROR", f"Invalid LimitRequestBody value: {values[0]}"
    
    return "PASS", "LimitRequestBody directive not found (default is 0 - unlimited)"

# ============================================
# MAIN AUDIT FUNCTION
# ============================================

def audit_check(cis_id: str, title: str, description: str, severity: str, 
                check_func: Callable, fix_cmd: str = "") -> None:
    """Execute a single CIS check and store the result"""
    print(f"Checking {cis_id}... ", end='', flush=True)
    
    try:
        status, actual = check_func()
    except Exception as e:
        status = "ERROR"
        actual = f"Check failed with exception: {str(e)}"
    
    result = {
        'id': cis_id,
        'title': title,
        'description': description,
        'severity': severity,
        'status': status,
        'actual': actual,
        'fix': fix_cmd if status == 'FAIL' else ""
    }
    
    results.append(result)
    
    status_colors = {
        'PASS': '\033[92m',  # Green
        'FAIL': '\033[91m',  # Red
        'MANUAL': '\033[93m', # Yellow
        'SKIP': '\033[94m',   # Blue
        'ERROR': '\033[95m'   # Magenta
    }
    
    color = status_colors.get(status, '\033[0m')
    print(f"[{color}{status}\033[0m]")

# ============================================
# MAIN EXECUTION
# ============================================

def main():
    """Main function"""
    print("\n" + "="*60)
    print("CIS Apache HTTP Server 2.4 Benchmark Compliance Auditor")
    print("Version: 2.4.0 - 10-02-2025")
    print("Enhanced with recursive config parsing")
    print("="*60)
    
    # Get system information
    hostname = run_cmd("hostname")
    ip_address = run_cmd("hostname -I | awk '{print $1}'")
    
    print(f"Hostname: {hostname}")
    print(f"IP Address: {ip_address}")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Get Apache information
    apache_bin = get_apache_binary()
    if apache_bin:
        print(f"Apache Binary: {apache_bin}")
        
        # Get Apache version
        version_result = run_cmd(f"{apache_bin} -v | head -1")
        if not version_result.startswith("Error"):
            print(f"Apache Version: {version_result}")
    
    config_dir = get_apache_config_dir()
    if config_dir:
        print(f"Config Directory: {config_dir}")
    
    print("-"*60)
    
    # Define all CIS checks
    checks = [
        # 🏛️ TRỤ CỘT 1: SERVER HARDENING & ATTACK SURFACE REDUCTION
        ("2.1", "Ensure Only Necessary Authentication and Authorization Modules Are Enabled",
         "The Apache 2.4 modules for authentication and authorization should be minimized.", "Medium",
         check_2_1, "Review and disable unnecessary auth modules with: a2dismod module_name"),
        
        ("2.2", "Ensure the Log Config Module Is Enabled",
         "The log_config module provides for flexible logging of client requests.", "Medium",
         check_2_2, "Enable log_config module: a2enmod log_config"),
        
        ("2.3", "Ensure the WebDAV Modules Are Disabled",
         "The Apache mod_dav and mod_dev_fs modules support WebDAV functionality.", "High",
         check_2_3, "Disable WebDAV modules: a2dismod dav_fs; a2dismod dav"),
        
        ("2.4", "Ensure the Status Module Is Disabled",
         "The Apache mod_status module provides current server performance statistics.", "High",
         check_2_4, "Disable status module: a2dismod status"),
        
        ("2.5", "Ensure the Autoindex Module Is Disabled",
         "The Apache autoindex module automatically generates web page listing the contents of directories.", "Medium",
         check_2_5, "Disable autoindex module: a2dismod autoindex"),
        
        ("2.6", "Ensure the Proxy Modules Are Disabled if not in use",
         "The Apache proxy modules allow the server to act as a proxy.", "High",
         check_2_6, "Disable proxy modules if not needed: a2dismod proxy; a2dismod proxy_http"),
        
        ("2.7", "Ensure the User Directories Module Is Disabled",
         "The UserDir directive must be disabled so that user home directories are not accessed via the web site.", "Medium",
         check_2_7, "Disable userdir module: a2dismod userdir"),
        
        ("2.8", "Ensure the Info Module Is Disabled",
         "The Apache mod_info module provides information on the server configuration.", "High",
         check_2_8, "Disable info module: a2dismod info"),
        
        ("2.9", "Ensure the Basic and Digest Authentication Modules are Disabled",
         "The Apache mod_auth_basic and mod_auth_digest modules support HTTP Basic and Digest Authentication.", "Medium",
         check_2_9, "Disable basic/digest auth: a2dismod auth_basic; a2dismod auth_digest"),
        
        ("5.4", "Ensure Default HTML Content Is Removed (Manual)",
         "Apache installations have default content that is not needed for production use.", "Low",
         check_5_4, "Remove default HTML content from web root directory"),
        
        ("5.5", "Ensure the Default CGI Content printenv Script Is Removed (Manual)",
         "The printenv CGI script discloses inappropriate information about the web server.", "Medium",
         check_5_5, "Remove printenv script: rm /usr/lib/cgi-bin/printenv"),
        
        ("5.6", "Ensure the Default CGI Content test-cgi Script Is Removed (Manual)",
         "The test-cgi script will print back CGI environment variables which includes server configuration details.", "Medium",
         check_5_6, "Remove test-cgi script: rm /usr/lib/cgi-bin/test-cgi"),
        
        ("8.1", "Ensure ServerTokens is Set to 'Prod' or 'ProductOnly'",
         "Configure the Apache ServerTokens directive to provide minimal information.", "Low",
         check_8_1, "Set ServerTokens to Prod in Apache configuration"),
        
        ("8.2", "Ensure ServerSignature Is Not Enabled",
         "Disable the server signatures which generates a signature line.", "Low",
         check_8_2, "Set ServerSignature Off in Apache configuration"),
        
        ("8.3", "Ensure All Default Apache Content Is Removed (Manual)",
         "Default content such as icons can identify the type and version of web server.", "Low",
         check_8_3, "Remove default Apache icons and manuals"),
        
        ("8.4", "Ensure ETag Response Header Fields Do Not Include Inodes",
         "When FileETag is configured to include file inode number, remote attackers may discern the inode.", "Medium",
         check_8_4, "Set FileETag to 'MTime Size' or remove the directive"),
        
        # 🔐 TRỤ CỘT 2: ACCESS CONTROL & PERMISSIONS
        ("3.1", "Ensure the Apache Web Server Runs As a Non-Root User",
         "The Apache User and Group directives are used to designate the user and group.", "High",
         check_3_1, "Create dedicated user and set in Apache config: User apache; Group apache"),
        
        ("3.2", "Ensure the Apache User Account Has an Invalid Shell",
         "The apache account must not be used as a regular login account.", "Medium",
         check_3_2, "Change shell for Apache user: usermod -s /sbin/nologin apache"),
        
        ("3.3", "Ensure the Apache User Account Is Locked",
         "The user account under which Apache runs should not have a valid password.", "Medium",
         check_3_3, "Lock Apache user account: passwd -l apache"),
        
        ("3.4", "Ensure Apache Directories and Files Are Owned By Root",
         "The Apache directories and files should be owned by root.", "Medium",
         check_3_4, "Change ownership: chown -R root:root /etc/apache2 /usr/lib/apache2"),
        
        ("3.5", "Ensure the Group Is Set Correctly on Apache Directories and Files",
         "The Apache directories and files should be set to have a group Id of root.", "Medium",
         check_3_5, "Change group: chgrp -R root /etc/apache2 /usr/lib/apache2"),
        
        ("3.6", "Ensure Other Write Access on Apache Directories and Files Is Restricted",
         "Permissions on Apache directories should generally be rwxr-xr-x (755).", "Medium",
         check_3_6, "Remove other write access: chmod -R o-w /etc/apache2 /usr/lib/apache2"),
        
        ("3.11", "Ensure Group Write Access for the Apache Directories and Files Is Properly Restricted",
         "Group permissions on Apache directories should generally be r-x.", "Medium",
         check_3_11, "Remove group write access on Apache directories"),
        
        ("3.12", "Ensure Group Write Access for the Document Root Directories and Files Is Properly Restricted",
         "Group permissions on Apache Document Root directories may need to be writable by authorized group.", "Medium",
         check_3_12, "Ensure Apache group does not have write access to document root"),
        
        ("4.1", "Ensure Access to OS Root Directory Is Denied By Default",
         "Create a default deny policy that does not allow access to operating system directories.", "High",
         check_4_1, "Add to Apache config: <Directory />\n  Require all denied\n</Directory>"),
        
        ("4.4", "Ensure OverRide Is Disabled for All Directories",
         "The Apache AllowOverride directive allows .htaccess files to override configuration.", "Medium",
         check_4_4, "Set AllowOverride None in all Directory sections"),
        
        ("5.1", "Ensure Options for the OS Root Directory Are Restricted",
         "The Apache Options directive allows for specific configuration of options.", "Medium",
         check_5_1, "Set Options None for root directory"),
        
        ("5.2", "Ensure Options for the Web Root Directory Are Restricted",
         "The Options directive at the web root needs to be restricted to minimal options.", "Medium",
         check_5_2, "Set Options None or Multiviews for web root"),
        
        ("5.3", "Ensure Options for Other Directories Are Minimized",
         "The options for other directories needs to be restricted to minimal options required.", "Medium",
         check_5_3, "Set appropriate Options for each directory"),
        
        ("5.10", "Ensure Access to .ht* Files Is Restricted",
         "Restrict access to any files beginning with .ht using the FileMatch directive.", "Medium",
         check_5_10, "Add to config: <FilesMatch \"^\\.ht\">\n  Require all denied\n</FilesMatch>"),
        
        ("5.11", "Ensure Access to .git Files Is Restricted",
         "Restrict access to any files beginning with .git using the FilesMatch directive.", "Low",
         check_5_11, "Add to config: <FilesMatch \"/\\.git\">\n  Require all denied\n</FilesMatch>"),
        
        ("5.12", "Ensure Access to .svn Files Is Restricted",
         "Restrict access to any files beginning with .svn using the FilesMatch directive.", "Low",
         check_5_12, "Add to config: <DirectoryMatch \"/\\.svn\">\n  Require all denied\n</DirectoryMatch>"),
        
        ("5.13", "Ensure Access to Inappropriate File Extensions Is Restricted",
         "Restrict access to inappropriate file extensions using the FilesMatch directive.", "Medium",
         check_5_13, "Create whitelist of allowed file extensions using FilesMatch"),
        
        # 📡 TRỤ CỘT 3: ENCRYPTION & KEY MANAGEMENT
        ("7.1", "Ensure mod_ssl and/or mod_nss Is Installed",
         "The mod_ssl module is the standard, most used module that implements SSL/TLS for Apache.", "Medium",
         check_7_1, "Enable SSL module: a2enmod ssl; apt install libapache2-mod-ssl"),
        
        ("7.3", "Ensure the Server's Private Key Is Protected (Manual)",
         "It is critical to protect the server's private key.", "High",
         check_7_3, "Ensure private key is stored separately and has permissions 0400"),
        
        ("7.4", "Ensure the TLSv1.0 and TLSv1.1 Protocols are Disabled",
         "The TLSv1.0 and TLSv1.1 protocols should be disabled via the SSLProtocol directive.", "High",
         check_7_4, "Set SSLProtocol to TLSv1.2 or higher in SSL configuration"),
        
        ("7.5", "Ensure Weak SSL/TLS Ciphers Are Disabled",
         "Disable weak SSL ciphers using the SSLCipherSuite directive.", "High",
         check_7_5, "Configure strong ciphers in SSLCipherSuite directive"),
        
        ("7.6", "Ensure Insecure SSL Renegotiation Is Not Enabled",
         "Enabling SSLInsecureRenegotiation leaves the server vulnerable to man-in-the-middle attack.", "High",
         check_7_6, "Ensure SSLInsecureRenegotiation is off"),
        
        ("7.7", "Ensure SSL Compression is not Enabled",
         "The SSLCompression directive controls whether SSL compression is used.", "High",
         check_7_7, "Set SSLCompression off"),
        
        ("7.8", "Ensure Medium Strength SSL/TLS Ciphers Are Disabled",
         "Disable medium strength ciphers such as Triple DES (3DES) and IDEA.", "High",
         check_7_8, "Add !3DES and !IDEA to SSLCipherSuite"),
        
        ("7.9", "Ensure All Web Content is Accessed via HTTPS",
         "All of the website content should be served via HTTPS rather than HTTP.", "High",
         check_7_9, "Redirect HTTP to HTTPS and disable HTTP listeners"),
        
        ("7.11", "Ensure HTTP Strict Transport Security Is Enabled",
         "HTTP Strict Transport Security (HSTS) helps protect from HTTP downgrade attacks.", "Medium",
         check_7_11, "Add Header always set Strict-Transport-Security header"),
        
        ("7.12", "Ensure Only Cipher Suites That Provide Forward Secrecy Are Enabled",
         "Forward secrecy gives assurance that session keys will not be compromised.", "Medium",
         check_7_12, "Configure SSLCipherSuite to require ECDHE or DHE"),
        
        # 🚦 TRỤ CỘT 4: TRAFFIC CONTROL & LOGGING
        ("5.7", "Ensure HTTP Request Methods Are Restricted",
         "Use the Apache <LimitExcept> directive to restrict unnecessary HTTP request methods.", "Medium",
         check_5_7, "Add <LimitExcept GET POST OPTIONS> Require all denied </LimitExcept>"),
        
        ("5.8", "Ensure the HTTP TRACE Method Is Disabled",
         "Use the Apache TraceEnable directive to disable the HTTP TRACE request method.", "Medium",
         check_5_8, "Add to Apache config: TraceEnable Off"),
        
        ("5.9", "Ensure Old HTTP Protocol Versions Are Disallowed",
         "Disallow old and invalid HTTP protocols versions using mod_rewrite or mod_security.", "Medium",
         check_5_9, "Add rewrite condition to disallow non-HTTP/1.1 requests"),
        
        ("5.16", "Ensure Browser Framing Is Restricted (Clickjacking)",
         "Include HTTP header which instructs browsers to restrict the content from being framed.", "Medium",
         check_5_16, "Add X-Frame-Options or Content-Security-Policy header"),
        
        ("6.1", "Ensure the Error Log Filename and Severity Level Are Configured Correctly",
         "The LogLevel directive configures the severity level for the error logs.", "Medium",
         check_6_1, "Configure LogLevel and ErrorLog directives appropriately"),
        
        ("6.3", "Ensure the Server Access Log Is Configured Correctly",
         "The LogFormat directive defines a nickname for a log format and information.", "Medium",
         check_6_3, "Configure CustomLog with appropriate log format"),
        
        ("9.1", "Ensure the TimeOut Is Set to 10 or Less",
         "Denial of Service (DoS) is an attack technique with the intent of preventing a web site.", "Medium",
         check_9_1, "Set Timeout 10 in Apache configuration"),
        
        ("9.2", "Ensure KeepAlive Is Enabled",
         "The KeepAlive directive controls whether Apache will reuse the same TCP connection.", "Medium",
         check_9_2, "Set KeepAlive On in Apache configuration"),
        
        ("9.3", "Ensure MaxKeepAliveRequests is Set to 100 or Greater",
         "The MaxKeepAliveRequests directive limits the number of requests allowed per connection.", "Medium",
         check_9_3, "Set MaxKeepAliveRequests 100 or more"),
        
        ("9.4", "Ensure KeepAliveTimeout is Set to 15 or Less",
         "The KeepAliveTimeout directive specifies the number of seconds Apache will wait.", "Medium",
         check_9_4, "Set KeepAliveTimeout 15 or less"),
        
        ("10.1", "Ensure the LimitRequestLine directive is Set to 8190 or less",
         "The LimitRequestLine directive limits the allowed size of a client's HTTP request-line.", "Medium",
         check_10_1, "Set LimitRequestLine 8190 in Apache configuration"),
        
        ("10.2", "Ensure the LimitRequestFields Directive is Set to 100 or Less",
         "The LimitRequestFields directive limits the number of fields allowed in an HTTP request.", "Medium",
         check_10_2, "Set LimitRequestFields 100 in Apache configuration"),
        
        ("10.3", "Ensure the LimitRequestFieldsize Directive is Set to 8190 or Less",
         "The LimitRequestFieldSize limits the number of bytes that will be allowed in an HTTP request header.", "Medium",
         check_10_3, "Set LimitRequestFieldsize 8190 in Apache configuration"),
        
        ("10.4", "Ensure the LimitRequestBody Directive is Set to 102400 or Less",
         "The LimitRequestBody directive limits the number of bytes that are allowed in a request body.", "Medium",
         check_10_4, "Set LimitRequestBody 102400 in Apache configuration"),
    ]
    
    # Run all checks
    for cis_id, title, description, severity, check_func, fix_cmd in checks:
        audit_check(cis_id, title, description, severity, check_func, fix_cmd)
    
    # Calculate statistics BEFORE report generation
    total_checks = len(results)
    passed_checks = len([x for x in results if x['status'] == 'PASS'])
    failed_checks = len([x for x in results if x['status'] == 'FAIL'])
    manual_checks = len([x for x in results if x['status'] == 'MANUAL'])
    skip_checks = len([x for x in results if x['status'] == 'SKIP'])
    error_checks = len([x for x in results if x['status'] == 'ERROR'])
    
    # Calculate score (excluding MANUAL, SKIP, ERROR)
    valid_checks = total_checks - manual_checks - skip_checks - error_checks
    score = round((passed_checks / valid_checks) * 100, 1) if valid_checks > 0 else 0
    
    print("\n" + "=" * 60)
    print("[+] Generating Report...")
    
    try:
        # Create Jinja2 environment
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('template_apache.html')
        
        # Count failed items by severity
        cnt_critical = len([x for x in results if x['severity'] == "Critical" and x['status'] == "FAIL"])
        cnt_high = len([x for x in results if x['severity'] == "High" and x['status'] == "FAIL"])
        cnt_medium = len([x for x in results if x['severity'] == "Medium" and x['status'] == "FAIL"])
        cnt_low = len([x for x in results if x['severity'] == "Low" and x['status'] == "FAIL"])
        
        # Non-pass results for detailed findings
        non_pass_results = [x for x in results if x['status'] != 'PASS']
        
        # Render HTML
        html_out = template.render(
            results=non_pass_results,
            all_results=results,
            hostname=hostname,
            ip_address=ip_address,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_checks=total_checks, 
            passed_checks=passed_checks, 
            failed_checks=failed_checks,
            manual_checks=manual_checks,
            skip_checks=skip_checks,
            error_checks=error_checks,
            score=score,
            count_critical=cnt_critical, 
            count_high=cnt_high, 
            count_medium=cnt_medium,
            count_low=cnt_low
        )
        
        # Generate PDF
        pdf_file = f"Apache_CIS_Audit_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
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
        
        # Write HTML to temp file and convert to PDF
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f:
            f.write(html_out)
            html_temp = f.name
        
        try:
            pdfkit.from_file(html_temp, pdf_file, options=options)
            print(f"[SUCCESS] Report saved: {pdf_file}")
        except Exception as e:
            print(f"[WARNING] PDF generation failed: {e}")
            print("[INFO] Saving HTML report instead...")
            html_file = pdf_file.replace('.pdf', '.html')
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_out)
            print(f"[SUCCESS] HTML report saved: {html_file}")
        finally:
            os.unlink(html_temp)
            
    except Exception as e:
        print(f"[ERROR] Report generation failed: {e}")
        print("\n[INFO] Raw results:")
        for r in results:
            print(f"{r['id']}: {r['status']} - {r['title']}")
    
    # Print summary
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

if __name__ == "__main__":
    main()
