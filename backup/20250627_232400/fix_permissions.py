#!/usr/bin/env python3
"""
SCAPA Permission Diagnostics and Fix Tool
"""
import os
import sys
import pwd
import grp
import stat
import tempfile
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def check_and_fix_permissions():
    """Check and fix SCAPA file permissions comprehensively"""
    print("🔍 SCAPA Permission Diagnostics and Fix Tool")
    print("=" * 50)
    
    issues_found = []
    fixes_applied = []
    
    # Check current user context
    current_uid = os.getuid()
    current_gid = os.getgid()
    is_root = current_uid == 0
    sudo_user = os.environ.get('SUDO_USER')
    
    print(f"Current user: UID={current_uid}, GID={current_gid}")
    print(f"Running as root: {is_root}")
    if sudo_user:
        print(f"Original user (SUDO_USER): {sudo_user}")
    
    # Directories to check/create
    directories = ['temp', 'logs', 'savedpcap']
    
    # Files to check
    files_to_check = [
        'main.py', 'config.ini', 'rules.txt', 
        'model.pkl', 'fmap.pkl', 'pmap.pkl'
    ]
    
    print("\n📁 Checking directories...")
    for directory in directories:
        try:
            # Create directory if it doesn't exist
            if not os.path.exists(directory):
                os.makedirs(directory, mode=0o755)
                print(f"   Created: {directory}")
                fixes_applied.append(f"Created directory {directory}")
            
            # Check permissions
            dir_stat = os.stat(directory)
            dir_mode = stat.filemode(dir_stat.st_mode)
            dir_owner = pwd.getpwuid(dir_stat.st_uid).pw_name
            dir_group = grp.getgrgid(dir_stat.st_gid).gr_name
            
            print(f"   {directory}: {dir_mode} {dir_owner}:{dir_group}")
            
            # Check if directory is writable
            if not os.access(directory, os.W_OK):
                issues_found.append(f"Directory {directory} is not writable")
                
                # Try to fix
                try:
                    os.chmod(directory, 0o755)
                    if is_root and sudo_user:
                        user_info = pwd.getpwnam(sudo_user)
                        os.chown(directory, user_info.pw_uid, user_info.pw_gid)
                    fixes_applied.append(f"Fixed permissions for {directory}")
                    print(f"   ✅ Fixed permissions for {directory}")
                except Exception as e:
                    print(f"   ❌ Could not fix {directory}: {e}")
            else:
                print(f"   ✅ {directory} is writable")
        
        except Exception as e:
            issues_found.append(f"Error with directory {directory}: {e}")
            print(f"   ❌ Error with {directory}: {e}")
    
    print("\n📄 Checking critical files...")
    for filename in files_to_check:
        try:
            if os.path.exists(filename):
                file_stat = os.stat(filename)
                file_mode = stat.filemode(file_stat.st_mode)
                file_owner = pwd.getpwuid(file_stat.st_uid).pw_name
                file_group = grp.getgrgid(file_stat.st_gid).gr_name
                
                print(f"   {filename}: {file_mode} {file_owner}:{file_group}")
                
                # Check if file is readable
                if not os.access(filename, os.R_OK):
                    issues_found.append(f"File {filename} is not readable")
                    
                    # Try to fix
                    try:
                        os.chmod(filename, 0o644)
                        if is_root and sudo_user:
                            user_info = pwd.getpwnam(sudo_user)
                            os.chown(filename, user_info.pw_uid, user_info.pw_gid)
                        fixes_applied.append(f"Fixed permissions for {filename}")
                        print(f"   ✅ Fixed permissions for {filename}")
                    except Exception as e:
                        print(f"   ❌ Could not fix {filename}: {e}")
                else:
                    print(f"   ✅ {filename} is readable")
            else:
                print(f"   ⚠️  {filename} not found")
        
        except Exception as e:
            issues_found.append(f"Error with file {filename}: {e}")
            print(f"   ❌ Error with {filename}: {e}")
    
    print("\n🧪 Testing pcap file creation...")
    test_pcap = os.path.join('temp', 'permission_test.pcap')
    try:
        # Test creating a file
        with open(test_pcap, 'w') as f:
            f.write("test")
        
        # Set proper permissions
        os.chmod(test_pcap, 0o644)
        
        # Test tshark access
        if os.access(test_pcap, os.R_OK):
            print("   ✅ Pcap file creation and permissions: OK")
            fixes_applied.append("Verified pcap file creation works")
        else:
            issues_found.append("Created pcap file is not readable")
        
        # Clean up
        os.unlink(test_pcap)
        
    except Exception as e:
        issues_found.append(f"Pcap file creation test failed: {e}")
        print(f"   ❌ Pcap file creation test failed: {e}")
    
    print("\n📊 Summary:")
    print(f"   Issues found: {len(issues_found)}")
    print(f"   Fixes applied: {len(fixes_applied)}")
    
    if issues_found:
        print("\n❌ Issues found:")
        for issue in issues_found:
            print(f"   - {issue}")
    
    if fixes_applied:
        print("\n✅ Fixes applied:")
        for fix in fixes_applied:
            print(f"   - {fix}")
    
    if not issues_found:
        print("\n🎉 All permission checks passed!")
        print("   SCAPA should work correctly with current permissions.")
        return True
    else:
        print("\n⚠️  Some issues remain. Consider:")
        print("   1. Running this script with sudo")
        print("   2. Manually fixing file/directory ownership")
        print("   3. Checking filesystem permissions")
        return False

def main():
    """Main function"""
    try:
        success = check_and_fix_permissions()
        
        if success:
            print("\n🎯 Permission check: PASSED")
            print("✅ SCAPA is ready to run")
        else:
            print("\n❌ Permission check: ISSUES FOUND")
            print("🔧 Some manual intervention may be required")
        
        return success
    
    except KeyboardInterrupt:
        print("\n\n👋 Permission check cancelled by user")
        return False
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
