#!/usr/bin/env python3
"""
Enhanced Performance Monitoring System for SCAPA
Provides real-time system resource monitoring with alerts and optimization
"""
import psutil
import time
import threading
import logging
from collections import deque
from datetime import datetime, timedelta
import configparser

class PerformanceMonitor:
    def __init__(self, config_file="config.ini"):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        
        # Configuration
        self.memory_threshold = float(self.config.get('performance', 'memory_threshold', fallback=512))
        self.cpu_threshold = float(self.config.get('performance', 'cpu_threshold', fallback=80))
        self.monitoring_enabled = self.config.getboolean('performance', 'enable_monitoring', fallback=True)
        
        # Monitoring data
        self.cpu_history = deque(maxlen=60)  # Last 60 readings
        self.memory_history = deque(maxlen=60)
        self.network_history = deque(maxlen=60)
        self.packet_count_history = deque(maxlen=60)
        
        # State
        self.monitoring = False
        self.monitor_thread = None
        self.last_alert_time = {}
        self.alert_cooldown = 30  # seconds
        
        # Statistics
        self.start_time = None
        self.total_packets_processed = 0
        self.peak_memory_usage = 0
        self.peak_cpu_usage = 0
        
        logging.info("Performance Monitor initialized")
    
    def start_monitoring(self):
        """Start performance monitoring"""
        if not self.monitoring_enabled:
            logging.info("Performance monitoring is disabled in config")
            return
            
        if self.monitoring:
            return
            
        self.monitoring = True
        self.start_time = datetime.now()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logging.info("Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logging.info("Performance monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                self._collect_metrics()
                self._check_thresholds()
                time.sleep(1)  # Monitor every second
            except Exception as e:
                logging.error(f"Error in performance monitoring: {e}")
                time.sleep(5)  # Wait longer on error
    
    def _collect_metrics(self):
        """Collect system metrics"""
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=None)
        self.cpu_history.append(cpu_percent)
        if cpu_percent > self.peak_cpu_usage:
            self.peak_cpu_usage = cpu_percent
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_mb = memory.used / (1024 * 1024)
        self.memory_history.append(memory_mb)
        if memory_mb > self.peak_memory_usage:
            self.peak_memory_usage = memory_mb
        
        # Network I/O
        network = psutil.net_io_counters()
        if network:
            network_total = (network.bytes_sent + network.bytes_recv) / (1024 * 1024)  # MB
            self.network_history.append(network_total)
        
        # Current packet processing rate (if available)
        current_time = time.time()
        self.packet_count_history.append((current_time, self.total_packets_processed))
    
    def _check_thresholds(self):
        """Check if any thresholds are exceeded"""
        current_time = time.time()
        
        # Check CPU threshold
        if self.cpu_history and self.cpu_history[-1] > self.cpu_threshold:
            if self._should_alert('cpu', current_time):
                self._alert(f"High CPU usage: {self.cpu_history[-1]:.1f}%", 'cpu')
        
        # Check memory threshold
        if self.memory_history and self.memory_history[-1] > self.memory_threshold:
            if self._should_alert('memory', current_time):
                self._alert(f"High memory usage: {self.memory_history[-1]:.1f} MB", 'memory')
    
    def _should_alert(self, alert_type, current_time):
        """Check if enough time has passed since last alert"""
        last_time = self.last_alert_time.get(alert_type, 0)
        return current_time - last_time > self.alert_cooldown
    
    def _alert(self, message, alert_type):
        """Send performance alert"""
        self.last_alert_time[alert_type] = time.time()
        logging.warning(f"Performance Alert: {message}")
        
        # Could integrate with main application's alert system here
        try:
            from plyer import notification
            notification.notify(
                title="SCAPA Performance Warning",
                message=message,
                timeout=5
            )
        except:
            pass  # Fall back to logging only
    
    def increment_packet_count(self, count=1):
        """Increment the packet processing counter"""
        self.total_packets_processed += count
    
    def get_current_stats(self):
        """Get current performance statistics"""
        if not self.cpu_history or not self.memory_history:
            return None
            
        # Calculate averages
        cpu_avg = sum(self.cpu_history) / len(self.cpu_history)
        memory_avg = sum(self.memory_history) / len(self.memory_history)
        
        # Calculate packet processing rate
        packet_rate = 0
        if len(self.packet_count_history) >= 2:
            recent = self.packet_count_history[-1]
            older = self.packet_count_history[-10] if len(self.packet_count_history) >= 10 else self.packet_count_history[0]
            time_diff = recent[0] - older[0]
            packet_diff = recent[1] - older[1]
            if time_diff > 0:
                packet_rate = packet_diff / time_diff
        
        uptime = datetime.now() - self.start_time if self.start_time else timedelta(0)
        
        return {
            'cpu_current': self.cpu_history[-1] if self.cpu_history else 0,
            'cpu_average': cpu_avg,
            'cpu_peak': self.peak_cpu_usage,
            'memory_current': self.memory_history[-1] if self.memory_history else 0,
            'memory_average': memory_avg,
            'memory_peak': self.peak_memory_usage,
            'total_packets': self.total_packets_processed,
            'packet_rate': packet_rate,
            'uptime': str(uptime).split('.')[0],  # Remove microseconds
            'monitoring_enabled': self.monitoring
        }
    
    def get_optimization_suggestions(self):
        """Get performance optimization suggestions"""
        suggestions = []
        stats = self.get_current_stats()
        
        if not stats:
            return suggestions
            
        if stats['cpu_average'] > self.cpu_threshold * 0.8:
            suggestions.append("Consider reducing packet capture rate or filtering")
            suggestions.append("Close unnecessary applications to free CPU resources")
        
        if stats['memory_current'] > self.memory_threshold * 0.8:
            suggestions.append("Consider reducing packet buffer size")
            suggestions.append("Enable feature caching to reduce memory usage")
        
        if stats['packet_rate'] > 1000:
            suggestions.append("High packet rate detected - consider network filtering")
        
        return suggestions
    
    def export_stats(self, filename=None):
        """Export performance statistics to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"logs/performance_report_{timestamp}.txt"
        
        stats = self.get_current_stats()
        suggestions = self.get_optimization_suggestions()
        
        with open(filename, 'w') as f:
            f.write("SCAPA Performance Report\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if stats:
                f.write("System Performance:\n")
                f.write(f"  Uptime: {stats['uptime']}\n")
                f.write(f"  CPU Usage: {stats['cpu_current']:.1f}% (avg: {stats['cpu_average']:.1f}%, peak: {stats['cpu_peak']:.1f}%)\n")
                f.write(f"  Memory Usage: {stats['memory_current']:.1f} MB (avg: {stats['memory_average']:.1f} MB, peak: {stats['memory_peak']:.1f} MB)\n")
                f.write(f"  Packets Processed: {stats['total_packets']}\n")
                f.write(f"  Processing Rate: {stats['packet_rate']:.1f} packets/sec\n\n")
            
            if suggestions:
                f.write("Optimization Suggestions:\n")
                for i, suggestion in enumerate(suggestions, 1):
                    f.write(f"  {i}. {suggestion}\n")
            else:
                f.write("No optimization suggestions - performance is good!\n")
        
        logging.info(f"Performance report exported to {filename}")
        return filename

# Global instance for easy access
monitor = PerformanceMonitor()
