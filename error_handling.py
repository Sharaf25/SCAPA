"""
Enhanced logging and error handling for SCAPA
"""
import logging
import sys
import traceback
from functools import wraps
from typing import Callable, Any

class SCAPALogger:
    """Centralized logging for SCAPA"""
    
    def __init__(self, log_file: str = "scapa.log", level: str = "INFO"):
        self.setup_logging(log_file, level)
    
    def setup_logging(self, log_file: str, level: str):
        """Setup logging configuration"""
        log_level = getattr(logging, level.upper(), logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        
        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        
        # Configure root logger
        logger = logging.getLogger()
        logger.setLevel(log_level)
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

def safe_execute(func: Callable) -> Callable:
    """Decorator for safe function execution with error logging"""
    @wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error(f"Error in {func.__name__}: {str(e)}")
            logging.debug(f"Traceback: {traceback.format_exc()}")
            return None
    return wrapper

def handle_packet_error(packet_summary: str = "Unknown"):
    """Context manager for packet processing errors"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logging.warning(f"Error processing packet {packet_summary}: {str(e)}")
                return None
        return wrapper
    return decorator

class ConfigError(Exception):
    """Custom exception for configuration errors"""
    pass

class NetworkError(Exception):
    """Custom exception for network-related errors"""
    pass

class MLModelError(Exception):
    """Custom exception for ML model errors"""
    pass

class PermissionError(Exception):
    """Custom exception for permission-related errors"""
    pass

class FileCreationError(Exception):
    """Custom exception for file creation errors"""
    pass

def validate_file_exists(filepath: str, file_type: str = "file") -> bool:
    """Validate that a required file exists"""
    import os
    if not os.path.exists(filepath):
        logging.error(f"Required {file_type} not found: {filepath}")
        return False
    return True

def safe_pickle_load(filepath: str) -> Any:
    """Safely load pickle files with validation"""
    import pickle
    import os
    
    if not validate_file_exists(filepath, "pickle file"):
        raise FileNotFoundError(f"Pickle file not found: {filepath}")
    
    try:
        # Check file size to prevent loading huge files
        file_size = os.path.getsize(filepath)
        if file_size > 100 * 1024 * 1024:  # 100MB limit
            raise MLModelError(f"Pickle file too large: {file_size} bytes")
        
        with open(filepath, 'rb') as file:
            return pickle.load(file)
    except Exception as e:
        raise MLModelError(f"Error loading pickle file {filepath}: {str(e)}")

def fix_file_permissions(filepath: str, mode: int = 0o644) -> bool:
    """Fix file permissions with proper ownership handling"""
    import os
    import pwd
    
    try:
        # Set basic permissions
        os.chmod(filepath, mode)
        
        # If running as root, fix ownership to original user
        if os.geteuid() == 0:
            original_user = os.environ.get('SUDO_USER')
            if original_user:
                try:
                    user_info = pwd.getpwnam(original_user)
                    os.chown(filepath, user_info.pw_uid, user_info.pw_gid)
                    logging.debug(f"Fixed ownership of {filepath} to {original_user}")
                except (KeyError, OSError) as e:
                    logging.warning(f"Could not fix ownership of {filepath}: {e}")
        
        # Verify the file is accessible
        if not os.access(filepath, os.R_OK):
            raise PermissionError(f"File {filepath} is not readable after permission fix")
        
        logging.debug(f"Successfully fixed permissions for {filepath}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to fix permissions for {filepath}: {e}")
        return False

def create_secure_file(filepath: str, content: bytes = b"", mode: int = 0o644) -> bool:
    """Create a file with secure permissions and proper ownership"""
    import os
    import tempfile
    
    try:
        # Ensure directory exists
        dir_path = os.path.dirname(filepath)
        if dir_path:
            os.makedirs(dir_path, mode=0o755, exist_ok=True)
            # Fix directory permissions too
            fix_file_permissions(dir_path, mode=0o755)
        
        # Create file with secure permissions
        with open(filepath, 'wb') as f:
            f.write(content)
        
        # Fix permissions and ownership
        if not fix_file_permissions(filepath, mode):
            raise FileCreationError(f"Failed to set proper permissions for {filepath}")
        
        logging.info(f"Created secure file: {filepath}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to create secure file {filepath}: {e}")
        return False

def create_tshark_compatible_pcap(original_path: str) -> str:
    """
    Create a tshark-compatible copy of pcap file in /tmp
    This works around permission issues with tshark in certain directories
    """
    import os
    import shutil
    import tempfile
    import hashlib
    
    try:
        # Generate a unique filename in /tmp
        basename = os.path.basename(original_path)
        name, ext = os.path.splitext(basename)
        
        # Create hash of original path for uniqueness
        path_hash = hashlib.md5(original_path.encode()).hexdigest()[:8]
        temp_filename = f"{name}_{path_hash}{ext}"
        temp_path = os.path.join("/tmp", temp_filename)
        
        # Copy the file to /tmp
        shutil.copy2(original_path, temp_path)
        
        # Ensure proper permissions
        os.chmod(temp_path, 0o644)
        
        logging.debug(f"Created tshark-compatible copy: {temp_path}")
        return temp_path
        
    except Exception as e:
        logging.error(f"Failed to create tshark-compatible copy of {original_path}: {e}")
        return original_path  # Fallback to original

def cleanup_temp_pcap(temp_path: str) -> bool:
    """Clean up temporary pcap file"""
    import os
    
    try:
        if temp_path.startswith("/tmp/") and os.path.exists(temp_path):
            os.remove(temp_path)
            logging.debug(f"Cleaned up temporary pcap: {temp_path}")
            return True
    except Exception as e:
        logging.warning(f"Failed to cleanup temporary pcap {temp_path}: {e}")
    return False

def setup_error_handling():
    """Setup global error handling"""
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        logging.critical("Uncaught exception", 
                        exc_info=(exc_type, exc_value, exc_traceback))
    
    sys.excepthook = handle_exception

def setup_logging(log_file: str = "logs/scapa.log", level: str = "INFO"):
    """Setup logging for SCAPA application"""
    import os
    
    # Ensure logs directory exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    logger = SCAPALogger(log_file, level)
    setup_error_handling()
    
    logging.info("SCAPA logging and error handling initialized")

def handle_error(error: Exception, context: str = "Unknown") -> bool:
    """
    Generic error handler function
    Returns True if error was handled successfully, False otherwise
    """
    try:
        error_msg = f"Error in {context}: {str(error)}"
        logging.error(error_msg)
        logging.debug(f"Traceback: {traceback.format_exc()}")
        return True
    except Exception as logging_error:
        # Fallback if logging fails
        print(f"Critical error in error handler: {logging_error}")
        return False

def handle_permission_error(error: Exception, filepath: str, suggested_action: str = "") -> bool:
    """Handle permission-related errors with helpful suggestions"""
    error_msg = f"Permission error for {filepath}: {str(error)}"
    logging.error(error_msg)
    
    suggestions = [
        "Try running with elevated privileges (sudo)",
        "Check file/directory ownership and permissions",
        "Ensure the user has read/write access to the target location"
    ]
    
    if suggested_action:
        suggestions.insert(0, suggested_action)
    
    for i, suggestion in enumerate(suggestions, 1):
        logging.info(f"  {i}. {suggestion}")
    
    return True

# Export commonly used exceptions
SCAPAError = Exception  # Generic SCAPA exception
