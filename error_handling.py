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

def setup_error_handling():
    """Setup global error handling"""
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        logging.critical("Uncaught exception", 
                        exc_info=(exc_type, exc_value, exc_traceback))
    
    sys.excepthook = handle_exception
