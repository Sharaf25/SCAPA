"""
PyShark and tshark configuration handler for SCAPA
Ensures proper setup and fallback for packet capture functionality
"""
import os
import configparser
import subprocess
import logging
from pathlib import Path
from typing import Optional

class PySharkConfig:
    """Manages PyShark configuration for SCAPA"""
    
    def __init__(self):
        self.config_file = Path.home() / ".config" / "pyshark" / "config"
        self.setup_pyshark_config()
    
    def setup_pyshark_config(self):
        """Setup PyShark configuration file for compatibility"""
        try:
            # Find tshark path
            tshark_path = self.find_tshark_path()
            if not tshark_path:
                logging.warning("tshark not found - packet analysis may not work")
                return False
            
            # PyShark looks for config.ini in current directory or package directory
            config_locations = [
                Path("config.ini"),  # Current directory (highest priority)
                Path(__file__).parent / "config.ini",  # SCAPA directory
            ]
            
            # Also update the PyShark package config.ini
            try:
                import pyshark
                package_config = Path(pyshark.__file__).parent / "config.ini"
                if package_config.exists():
                    config_locations.append(package_config)
            except ImportError:
                pass
            
            success_count = 0
            
            for config_path in config_locations:
                try:
                    # Read existing config or create new one
                    config = configparser.ConfigParser()
                    
                    if config_path.exists():
                        config.read(config_path)
                    
                    # Ensure tshark section exists
                    if not config.has_section('tshark'):
                        config.add_section('tshark')
                    config.set('tshark', 'tshark_path', tshark_path)
                    
                    # Ensure dumpcap section exists
                    if not config.has_section('dumpcap'):
                        config.add_section('dumpcap')
                    dumpcap_path = tshark_path.replace('tshark', 'dumpcap')
                    config.set('dumpcap', 'dumpcap_path', dumpcap_path)
                    
                    # Write config file
                    with open(config_path, 'w') as f:
                        config.write(f)
                    
                    success_count += 1
                    logging.info(f"PyShark configuration updated: {config_path}")
                    
                except (PermissionError, OSError) as e:
                    logging.debug(f"Could not write to {config_path}: {e}")
                    continue
            
            if success_count > 0:
                return True
            else:
                logging.error("Could not create PyShark config in any location")
                return False
            
        except Exception as e:
            logging.error(f"Error setting up PyShark config: {e}")
            return False
    
    def find_tshark_path(self) -> Optional[str]:
        """Find tshark executable path"""
        possible_paths = [
            '/usr/bin/tshark',
            '/usr/local/bin/tshark',
            '/opt/wireshark/bin/tshark'
        ]
        
        # Try common paths first
        for path in possible_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path
        
        # Try which command
        try:
            result = subprocess.run(['which', 'tshark'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        
        return None
    
    def verify_tshark(self) -> bool:
        """Verify tshark is working"""
        try:
            result = subprocess.run(['tshark', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False
    
    def get_network_interfaces(self) -> list:
        """Get available network interfaces using tshark"""
        try:
            result = subprocess.run(['tshark', '-D'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                interfaces = []
                for line in result.stdout.strip().split('\n'):
                    if line and '.' in line:
                        # Format: "1. eth0"
                        parts = line.split('.', 1)
                        if len(parts) > 1:
                            interface = parts[1].strip()
                            interfaces.append(interface)
                return interfaces
        except Exception as e:
            logging.error(f"Error getting interfaces with tshark: {e}")
        
        return []

def configure_pyshark():
    """Configure PyShark for SCAPA"""
    import os
    
    # Set environment variables as an alternative
    os.environ['TSHARK_PATH'] = '/usr/bin/tshark'
    os.environ['WIRESHARK_PATH'] = '/usr/bin/wireshark'
    
    config = PySharkConfig()
    
    if not config.verify_tshark():
        logging.error("tshark verification failed")
        return False
    
    interfaces = config.get_network_interfaces()
    logging.info(f"Available interfaces: {interfaces}")
    
    return True

if __name__ == "__main__":
    # Test configuration
    logging.basicConfig(level=logging.INFO)
    success = configure_pyshark()
    print(f"PyShark configuration: {'Success' if success else 'Failed'}")
