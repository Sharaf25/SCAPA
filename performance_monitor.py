"""
Performance monitoring and optimization for SCAPA
"""
import time
import threading
import logging
from collections import deque, defaultdict
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class PerformanceMetric:
    """Performance metric data"""
    name: str
    value: float
    timestamp: datetime
    unit: str = ""

class PerformanceMonitor:
    """Monitor and track SCAPA performance metrics"""
    
    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_history))
        self.counters: Dict[str, int] = defaultdict(int)
        self.timers: Dict[str, float] = {}
        self.lock = threading.Lock()
        
        # Start monitoring thread
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_system, daemon=True)
        self.monitor_thread.start()
    
    def add_metric(self, name: str, value: float, unit: str = "") -> None:
        """Add a performance metric"""
        with self.lock:
            metric = PerformanceMetric(
                name=name,
                value=value,
                timestamp=datetime.now(),
                unit=unit
            )
            self.metrics[name].append(metric)
    
    def increment_counter(self, name: str, amount: int = 1) -> None:
        """Increment a counter metric"""
        with self.lock:
            self.counters[name] += amount
    
    def start_timer(self, name: str) -> None:
        """Start a timer for measuring duration"""
        self.timers[name] = time.time()
    
    def end_timer(self, name: str) -> Optional[float]:
        """End a timer and record the duration"""
        if name in self.timers:
            duration = time.time() - self.timers[name]
            self.add_metric(f"{name}_duration", duration, "seconds")
            del self.timers[name]
            return duration
        return None
    
    def get_metric_stats(self, name: str, window_minutes: int = 5) -> Dict:
        """Get statistics for a metric within a time window"""
        with self.lock:
            if name not in self.metrics:
                return {}
            
            cutoff_time = datetime.now() - timedelta(minutes=window_minutes)
            recent_metrics = [
                m for m in self.metrics[name] 
                if m.timestamp > cutoff_time
            ]
            
            if not recent_metrics:
                return {}
            
            values = [m.value for m in recent_metrics]
            return {
                "count": len(values),
                "min": min(values),
                "max": max(values),
                "avg": sum(values) / len(values),
                "total": sum(values),
                "unit": recent_metrics[0].unit if recent_metrics else ""
            }
    
    def get_packet_rate(self, window_minutes: int = 1) -> float:
        """Get packets per second rate"""
        stats = self.get_metric_stats("packets_processed", window_minutes)
        if stats and stats["count"] > 0:
            return stats["total"] / (window_minutes * 60)
        return 0.0
    
    def get_alert_rate(self, window_minutes: int = 5) -> float:
        """Get alerts per minute rate"""
        stats = self.get_metric_stats("alerts_generated", window_minutes)
        if stats and stats["count"] > 0:
            return stats["total"] / window_minutes
        return 0.0
    
    def get_ml_performance(self) -> Dict:
        """Get ML model performance metrics"""
        prediction_stats = self.get_metric_stats("ml_prediction_duration", 5)
        accuracy_stats = self.get_metric_stats("ml_accuracy", 10)
        
        return {
            "prediction_time": prediction_stats,
            "accuracy": accuracy_stats,
            "predictions_per_minute": self.get_metric_stats("ml_predictions", 1).get("total", 0)
        }
    
    def _monitor_system(self) -> None:
        """Background system monitoring"""
        import psutil
        
        while self.monitoring:
            try:
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                self.add_metric("cpu_usage", cpu_percent, "%")
                
                # Memory usage
                memory = psutil.virtual_memory()
                self.add_metric("memory_usage", memory.percent, "%")
                self.add_metric("memory_available", memory.available / (1024**3), "GB")
                
                # Network I/O
                net_io = psutil.net_io_counters()
                self.add_metric("network_bytes_sent", net_io.bytes_sent, "bytes")
                self.add_metric("network_bytes_recv", net_io.bytes_recv, "bytes")
                
                time.sleep(5)  # Update every 5 seconds
                
            except Exception as e:
                logging.error(f"Error in system monitoring: {e}")
                time.sleep(10)  # Wait longer on error
    
    def get_performance_report(self) -> str:
        """Generate a performance report"""
        report = []
        report.append("=== SCAPA Performance Report ===")
        report.append(f"Generated at: {datetime.now()}")
        report.append("")
        
        # Packet processing stats
        packet_rate = self.get_packet_rate(1)
        report.append(f"Packet Rate: {packet_rate:.2f} packets/second")
        
        alert_rate = self.get_alert_rate(5)
        report.append(f"Alert Rate: {alert_rate:.2f} alerts/minute")
        
        # ML performance
        ml_perf = self.get_ml_performance()
        pred_time = ml_perf["prediction_time"]
        if pred_time:
            report.append(f"ML Prediction Time: {pred_time['avg']:.4f}s (avg)")
        
        # System resources
        cpu_stats = self.get_metric_stats("cpu_usage", 5)
        if cpu_stats:
            report.append(f"CPU Usage: {cpu_stats['avg']:.1f}% (avg)")
        
        memory_stats = self.get_metric_stats("memory_usage", 5)
        if memory_stats:
            report.append(f"Memory Usage: {memory_stats['avg']:.1f}% (avg)")
        
        # Counters
        report.append("\n=== Counters ===")
        with self.lock:
            for name, count in self.counters.items():
                report.append(f"{name}: {count}")
        
        return "\n".join(report)
    
    def reset_metrics(self) -> None:
        """Reset all metrics and counters"""
        with self.lock:
            self.metrics.clear()
            self.counters.clear()
            self.timers.clear()
    
    def stop(self) -> None:
        """Stop the performance monitor"""
        self.monitoring = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)

# Decorator for timing function execution
def timed_execution(monitor: PerformanceMonitor, metric_name: str):
    """Decorator to time function execution"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            monitor.start_timer(metric_name)
            try:
                result = func(*args, **kwargs)
                monitor.increment_counter(f"{metric_name}_success")
                return result
            except Exception as e:
                monitor.increment_counter(f"{metric_name}_error")
                raise
            finally:
                monitor.end_timer(metric_name)
        return wrapper
    return decorator
