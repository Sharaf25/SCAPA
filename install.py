#!/usr/bin/env python3
"""
Fixed cross-platform installation script for SCAPA with proper PySimpleGUI handling
"""
import sys
import platform
import subprocess
import os
import logging

def setup_logging():
    """Setup logging for the installer"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        logging.error("SCAPA requires Python 3.8 or higher")
        logging.error(f"Current version: {sys.version}")
        return False
    logging.info(f"Python version check passed: {sys.version}")
    return True

def install_requirements():
    """Install Python requirements with proper PySimpleGUI handling"""
    try:
        # Check if we're in a virtual environment
        in_venv = hasattr(sys, 'real_prefix') or (
            hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
        )
        
        if not in_venv:
            logging.info("Not in virtual environment. Creating one...")
            try:
                # Try to create virtual environment
                subprocess.check_call([sys.executable, "-m", "venv", "venv"])
                logging.info("Virtual environment created successfully")
                
                # Determine the correct path to the virtual environment python
                if platform.system() == "Windows":
                    venv_python = os.path.join("venv", "Scripts", "python.exe")
                    venv_pip = os.path.join("venv", "Scripts", "pip.exe")
                else:
                    venv_python = os.path.join("venv", "bin", "python")
                    venv_pip = os.path.join("venv", "bin", "pip")
                
                # Upgrade pip first
                logging.info("Upgrading pip...")
                subprocess.check_call([venv_pip, "install", "--upgrade", "pip", "setuptools", "wheel"])
                
                # Install core dependencies
                logging.info("Installing core dependencies...")
                core_deps = [
                    "scapy>=2.4.5",
                    "pyshark>=0.4.5", 
                    "scikit-learn>=1.2.0",
                    "numpy>=1.24.0",
                    "psutil>=5.9.0",
                    "plyer>=2.1.0"
                ]
                
                for dep in core_deps:
                    try:
                        subprocess.check_call([venv_pip, "install", dep])
                        logging.info(f"Successfully installed {dep}")
                    except subprocess.CalledProcessError as e:
                        logging.error(f"Failed to install {dep}: {e}")
                
                # Special handling for PySimpleGUI
                logging.info("Installing PySimpleGUI from official source...")
                subprocess.check_call([
                    venv_pip, "install", "--upgrade", 
                    "--extra-index-url", "https://PySimpleGUI.net/install", "PySimpleGUI"
                ])
                
                logging.info("Virtual environment setup complete!")
                logging.info("To activate the virtual environment:")
                if platform.system() == "Windows":
                    logging.info("venv\\Scripts\\activate")
                else:
                    logging.info("source venv/bin/activate")
                
                return True
                
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to create virtual environment: {e}")
                logging.info("Trying system-wide installation...")
                
        # Try system-wide installation
        logging.info("Installing Python requirements system-wide...")
        
        # Install core dependencies
        core_deps = [
            "scapy>=2.4.5",
            "pyshark>=0.4.5", 
            "scikit-learn>=1.2.0",
            "numpy>=1.24.0",
            "psutil>=5.9.0",
            "plyer>=2.1.0"
        ]
        
        for dep in core_deps:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", dep])
                logging.info(f"Successfully installed {dep}")
            except subprocess.CalledProcessError:
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "--break-system-packages", dep])
                    logging.info(f"Successfully installed {dep} with --break-system-packages")
                except subprocess.CalledProcessError as e:
                    logging.error(f"Failed to install {dep}: {e}")
        
        # Special handling for PySimpleGUI
        logging.info("Installing PySimpleGUI from official source...")
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "--user", "--upgrade", 
                "--extra-index-url", "https://PySimpleGUI.net/install", "PySimpleGUI"
            ])
        except subprocess.CalledProcessError:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "--break-system-packages", "--upgrade", 
                "--extra-index-url", "https://PySimpleGUI.net/install", "PySimpleGUI"
            ])
        
        logging.info("Python requirements installed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to install requirements: {e}")
        return False

def check_system_dependencies():
    """Check and install system dependencies"""
    system = platform.system().lower()
    logging.info(f"Detected operating system: {system}")
    
    if system == "linux":
        return check_linux_dependencies()
    elif system == "darwin":  # macOS
        return check_macos_dependencies()
    elif system == "windows":
        return check_windows_dependencies()
    else:
        logging.warning(f"Unsupported operating system: {system}")
        return False

def check_linux_dependencies():
    """Check Linux-specific dependencies"""
    logging.info("Checking Linux dependencies...")
    
    # Check for required packages
    required_packages = [
        ("tshark", "wireshark-common"),
        ("paplay", "pulseaudio-utils")
    ]
    
    missing_packages = []
    for cmd, package in required_packages:
        if not check_command_exists(cmd):
            missing_packages.append(package)
    
    if missing_packages:
        logging.warning(f"Missing packages: {', '.join(missing_packages)}")
        logging.info("Install missing packages with:")
        logging.info(f"sudo apt-get install {' '.join(missing_packages)}")
        return False
    
    logging.info("All Linux dependencies are satisfied")
    return True

def check_macos_dependencies():
    """Check macOS-specific dependencies"""
    logging.info("Checking macOS dependencies...")
    
    # Check for Wireshark/tshark
    if not check_command_exists("tshark"):
        logging.warning("tshark not found. Install Wireshark from https://www.wireshark.org/")
        return False
    
    logging.info("All macOS dependencies are satisfied")
    return True

def check_windows_dependencies():
    """Check Windows-specific dependencies"""
    logging.info("Checking Windows dependencies...")
    
    # Check for Wireshark/tshark
    if not check_command_exists("tshark"):
        logging.warning("tshark not found. Install Wireshark from https://www.wireshark.org/")
        logging.info("Make sure to add Wireshark to your PATH during installation")
        return False
    
    logging.info("All Windows dependencies are satisfied")
    return True

def check_command_exists(command):
    """Check if a command exists in PATH"""
    try:
        subprocess.run([command, "--version"], 
                      capture_output=True, check=True, timeout=5)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False

def create_directories():
    """Create necessary directories"""
    directories = ["temp", "savedpcap", "logs"]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            logging.info(f"Created directory: {directory}")
        except Exception as e:
            logging.error(f"Failed to create directory {directory}: {e}")
            return False
    
    return True

def check_network_permissions():
    """Check if the user has network capture permissions"""
    system = platform.system().lower()
    
    if system == "linux":
        # Check if user is in wireshark group
        try:
            import grp
            user_groups = [g.gr_name for g in grp.getgrall() if os.getlogin() in g.gr_mem]
            if "wireshark" in user_groups:
                logging.info("User has wireshark group permissions")
                return True
        except:
            pass
        
        logging.warning("Network capture permissions may be required")
        logging.info("Run: sudo usermod -a -G wireshark $USER")
        logging.info("Then logout and login again")
        return False
    
    elif system == "darwin":
        logging.info("macOS: You may need to run with elevated privileges for packet capture")
        return True
    
    elif system == "windows":
        logging.info("Windows: Administrator privileges may be required for packet capture")
        return True
    
    return True

def main():
    """Main installation function"""
    setup_logging()
    logging.info("Starting SCAPA installation (Fixed version)...")
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Create directories
    if not create_directories():
        logging.error("Failed to create required directories")
        sys.exit(1)
    
    # Install Python requirements
    if not install_requirements():
        logging.error("Failed to install Python requirements")
        sys.exit(1)
    
    # Check system dependencies
    if not check_system_dependencies():
        logging.warning("Some system dependencies are missing")
        logging.warning("SCAPA may not work correctly without them")
    
    # Check network permissions
    check_network_permissions()
    
    logging.info("SCAPA installation completed successfully!")
    logging.info("Run 'python main.py' to start SCAPA")
    logging.info("Or use the launcher scripts: ./run_scapa.sh (Linux/Mac) or run_scapa.bat (Windows)")

if __name__ == "__main__":
    main()
