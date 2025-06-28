"""
Cross-platform network interface utilities for SCAPA
"""
import platform
import subprocess
import logging
from typing import List, Dict

def get_network_interfaces() -> List[Dict[str, str]]:
    """
    Get available network interfaces across different platforms
    
    Returns:
        List of dictionaries with interface information
    """
    interfaces = []
    
    try:
        system = platform.system().lower()
        
        if system == "windows":
            interfaces = _get_windows_interfaces()
        elif system in ["linux", "darwin"]:  # Linux or macOS
            interfaces = _get_unix_interfaces()
        else:
            logging.warning(f"Unsupported platform: {system}")
            
    except Exception as e:
        logging.error(f"Error getting network interfaces: {e}")
        
    return interfaces

def _get_windows_interfaces() -> List[Dict[str, str]]:
    """Get Windows network interfaces using scapy"""
    try:
        import scapy.arch.windows as scpwinarch
        win_interfaces = scpwinarch.get_windows_if_list()
        return [{"name": iface["name"], "description": iface.get("description", "")} 
                for iface in win_interfaces]
    except ImportError:
        logging.error("scapy.arch.windows not available")
        return []

def _get_unix_interfaces() -> List[Dict[str, str]]:
    """Get Unix-like system interfaces using scapy"""
    try:
        from scapy.all import get_if_list
        interface_names = get_if_list()
        return [{"name": name, "description": name} for name in interface_names]
    except ImportError:
        logging.error("scapy not available")
        return _get_interfaces_fallback()

def _get_interfaces_fallback() -> List[Dict[str, str]]:
    """Fallback method using system commands"""
    interfaces = []
    system = platform.system().lower()
    
    try:
        if system == "linux":
            # Use ip command
            result = subprocess.run(["ip", "link", "show"], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if ': ' in line and 'state' in line:
                    parts = line.split(': ')
                    if len(parts) >= 2:
                        name = parts[1].split('@')[0]
                        interfaces.append({"name": name, "description": name})
                        
        elif system == "darwin":  # macOS
            # Use ifconfig
            result = subprocess.run(["ifconfig", "-l"], 
                                  capture_output=True, text=True)
            for name in result.stdout.strip().split():
                interfaces.append({"name": name, "description": name})
                
    except Exception as e:
        logging.error(f"Fallback interface detection failed: {e}")
        
    return interfaces

def validate_interface(interface_name: str) -> bool:
    """
    Validate if an interface exists and is available
    
    Args:
        interface_name: Name of the interface to validate
        
    Returns:
        True if interface is valid and available
    """
    available_interfaces = get_network_interfaces()
    return any(iface["name"] == interface_name for iface in available_interfaces)
