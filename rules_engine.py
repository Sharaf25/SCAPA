"""
Enhanced rules engine for SCAPA with better parsing and validation
"""
import re
import ipaddress
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

class RuleAction(Enum):
    ALERT = "alert"
    LOG = "log"
    DROP = "drop"
    PASS = "pass"

@dataclass
class Rule:
    """Represents a single detection rule"""
    action: RuleAction
    protocol: str
    src_ip: str
    src_port: str
    direction: str
    dst_ip: str
    dst_port: str
    message: str
    enabled: bool = True
    rule_id: Optional[int] = None

class RulesEngine:
    """Enhanced rules engine with validation and error handling"""
    
    def __init__(self, rules_file: str = "rules.txt"):
        self.rules_file = rules_file
        self.rules: List[Rule] = []
        self.load_rules()
    
    def load_rules(self) -> None:
        """Load and parse rules from file"""
        try:
            with open(self.rules_file, 'r') as file:
                lines = file.readlines()
            
            self.rules = []
            for line_num, line in enumerate(lines, 1):
                rule = self._parse_rule(line.strip(), line_num)
                if rule:
                    self.rules.append(rule)
            
            logging.info(f"Loaded {len(self.rules)} rules from {self.rules_file}")
            
        except FileNotFoundError:
            logging.error(f"Rules file not found: {self.rules_file}")
        except Exception as e:
            logging.error(f"Error loading rules: {e}")
    
    def _parse_rule(self, line: str, line_num: int) -> Optional[Rule]:
        """Parse a single rule line"""
        # Skip empty lines and comments
        if not line or line.startswith('#') or line.startswith('!'):
            return None
        
        try:
            # Rule format: action protocol src_ip src_port -> dst_ip dst_port message
            parts = line.split()
            if len(parts) < 7:
                logging.warning(f"Invalid rule format at line {line_num}: {line}")
                return None
            
            action = RuleAction(parts[0].lower())
            protocol = parts[1].lower()
            src_ip = parts[2]
            src_port = parts[3]
            direction = parts[4]
            dst_ip = parts[5]
            dst_port = parts[6]
            message = " ".join(parts[7:]) if len(parts) > 7 else ""
            
            # Validate rule components
            if not self._validate_rule_components(protocol, src_ip, src_port, 
                                                dst_ip, dst_port, direction):
                logging.warning(f"Invalid rule components at line {line_num}: {line}")
                return None
            
            return Rule(
                action=action,
                protocol=protocol,
                src_ip=src_ip,
                src_port=src_port,
                direction=direction,
                dst_ip=dst_ip,
                dst_port=dst_port,
                message=message,
                rule_id=line_num
            )
            
        except ValueError as e:
            logging.warning(f"Error parsing rule at line {line_num}: {e}")
            return None
    
    def _validate_rule_components(self, protocol: str, src_ip: str, src_port: str,
                                 dst_ip: str, dst_port: str, direction: str) -> bool:
        """Validate individual rule components"""
        # Validate protocol
        valid_protocols = ["tcp", "udp", "icmp", "ip", "any"]
        if protocol not in valid_protocols:
            return False
        
        # Validate direction
        if direction != "->":
            return False
        
        # Validate IP addresses
        if not self._validate_ip(src_ip) or not self._validate_ip(dst_ip):
            return False
        
        # Validate ports
        if not self._validate_port(src_port) or not self._validate_port(dst_port):
            return False
        
        return True
    
    def _validate_ip(self, ip_str: str) -> bool:
        """Validate IP address or network"""
        if ip_str == "any":
            return True
        
        try:
            if "/" in ip_str:
                ipaddress.ip_network(ip_str, strict=False)
            else:
                ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def _validate_port(self, port_str: str) -> bool:
        """Validate port number or range"""
        if port_str == "any":
            return True
        
        try:
            if ":" in port_str:
                # Port range
                start, end = port_str.split(":")
                return 0 <= int(start) <= 65535 and 0 <= int(end) <= 65535
            else:
                # Single port
                port = int(port_str)
                return 0 <= port <= 65535
        except ValueError:
            return False
    
    def check_packet(self, packet_info: Dict) -> Tuple[bool, str]:
        """
        Check if packet matches any rules
        
        Args:
            packet_info: Dictionary with packet information
            
        Returns:
            Tuple of (matches, message)
        """
        for rule in self.rules:
            if not rule.enabled:
                continue
                
            if self._match_rule(rule, packet_info):
                return True, rule.message
        
        return False, ""
    
    def _match_rule(self, rule: Rule, packet_info: Dict) -> bool:
        """Check if packet matches a specific rule"""
        # Check protocol
        if rule.protocol != "any" and rule.protocol != packet_info.get("protocol", "").lower():
            return False
        
        # Check source IP
        if not self._match_ip(rule.src_ip, packet_info.get("src_ip", "")):
            return False
        
        # Check destination IP
        if not self._match_ip(rule.dst_ip, packet_info.get("dst_ip", "")):
            return False
        
        # Check source port
        if not self._match_port(rule.src_port, packet_info.get("src_port", 0)):
            return False
        
        # Check destination port
        if not self._match_port(rule.dst_port, packet_info.get("dst_port", 0)):
            return False
        
        return True
    
    def _match_ip(self, rule_ip: str, packet_ip: str) -> bool:
        """Check if packet IP matches rule IP"""
        if rule_ip == "any":
            return True
        
        try:
            if "/" in rule_ip:
                # Network match
                network = ipaddress.ip_network(rule_ip, strict=False)
                return ipaddress.ip_address(packet_ip) in network
            else:
                # Exact match
                return rule_ip == packet_ip
        except ValueError:
            return False
    
    def _match_port(self, rule_port: str, packet_port: int) -> bool:
        """Check if packet port matches rule port"""
        if rule_port == "any":
            return True
        
        try:
            if ":" in rule_port:
                # Port range
                start, end = map(int, rule_port.split(":"))
                return start <= packet_port <= end
            else:
                # Exact match
                return int(rule_port) == packet_port
        except ValueError:
            return False
    
    def add_rule(self, rule: Rule) -> bool:
        """Add a new rule"""
        try:
            self.rules.append(rule)
            self._save_rules()
            return True
        except Exception as e:
            logging.error(f"Error adding rule: {e}")
            return False
    
    def remove_rule(self, rule_id: int) -> bool:
        """Remove a rule by ID"""
        try:
            self.rules = [r for r in self.rules if r.rule_id != rule_id]
            self._save_rules()
            return True
        except Exception as e:
            logging.error(f"Error removing rule: {e}")
            return False
    
    def _save_rules(self) -> None:
        """Save rules back to file"""
        try:
            with open(self.rules_file, 'w') as file:
                for rule in self.rules:
                    rule_line = f"{rule.action.value} {rule.protocol} {rule.src_ip} {rule.src_port} {rule.direction} {rule.dst_ip} {rule.dst_port} {rule.message}\n"
                    file.write(rule_line)
        except Exception as e:
            logging.error(f"Error saving rules: {e}")
    
    def get_rule_stats(self) -> Dict:
        """Get statistics about loaded rules"""
        stats = {
            "total_rules": len(self.rules),
            "enabled_rules": len([r for r in self.rules if r.enabled]),
            "disabled_rules": len([r for r in self.rules if not r.enabled]),
            "by_protocol": {},
            "by_action": {}
        }
        
        for rule in self.rules:
            # Count by protocol
            protocol = rule.protocol
            stats["by_protocol"][protocol] = stats["by_protocol"].get(protocol, 0) + 1
            
            # Count by action
            action = rule.action.value
            stats["by_action"][action] = stats["by_action"].get(action, 0) + 1
        
        return stats
