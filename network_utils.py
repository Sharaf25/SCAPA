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

def get_available_interfaces() -> List[str]:
    """
    Get list of available network interface names (simplified version for SCAPA)
    
    Returns:
        List of interface names ready for use with scapy
    """
    interfaces = get_network_interfaces()
    
    # Filter out common problematic interfaces
    filtered_names = []
    for iface in interfaces:
        name = iface["name"]
        
        # Skip loopback and virtual interfaces
        if name in ["lo", "lo0"]:
            continue
        if name.startswith(("docker", "veth", "br-")):
            continue
        if "Virtual" in iface.get("description", ""):
            continue
            
        filtered_names.append(name)
    
    # Limit to reasonable number of interfaces
    return filtered_names[:5] if len(filtered_names) > 5 else filtered_names

def get_interface_statistics(interface_name: str) -> Dict[str, int]:
    """
    Get basic statistics for a network interface
    
    Args:
        interface_name: Name of the interface
        
    Returns:
        Dictionary with interface statistics
    """
    try:
        import psutil
        stats = psutil.net_io_counters(pernic=True)
        
        if interface_name in stats:
            iface_stats = stats[interface_name]
            return {
                "bytes_sent": iface_stats.bytes_sent,
                "bytes_recv": iface_stats.bytes_recv,
                "packets_sent": iface_stats.packets_sent,
                "packets_recv": iface_stats.packets_recv,
                "errin": iface_stats.errin,
                "errout": iface_stats.errout,
                "dropin": iface_stats.dropin,
                "dropout": iface_stats.dropout
            }
    except Exception as e:
        logging.error(f"Error getting interface statistics: {e}")
    
    return {}

def is_interface_active(interface_name: str) -> bool:
    """
    Check if a network interface is active
    
    Args:
        interface_name: Name of the interface to check
        
    Returns:
        True if interface is active
    """
    try:
        stats = get_interface_statistics(interface_name)
        # Consider interface active if it has sent or received packets
        return stats.get("packets_sent", 0) > 0 or stats.get("packets_recv", 0) > 0
    except Exception:
        return False
