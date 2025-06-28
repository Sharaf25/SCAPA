#!/usr/bin/env python3
"""
Simple network traffic generator for testing SCAPA packet capture
"""
import socket
import time
import threading
import subprocess
import sys

def generate_dns_traffic():
    """Generate some DNS traffic"""
    hostnames = ['google.com', 'github.com', 'stackoverflow.com', 'python.org', 'wikipedia.org']
    
    for i in range(15):
        try:
            for hostname in hostnames:
                print(f"DNS lookup for {hostname}")
                socket.gethostbyname(hostname)
                time.sleep(0.5)
        except Exception as e:
            print(f"DNS lookup failed: {e}")
        time.sleep(1)

def generate_ping_traffic():
    """Generate ping traffic"""
    hosts = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
    
    for i in range(3):
        for host in hosts:
            try:
                print(f"Pinging {host}")
                subprocess.run(['ping', '-c', '2', host], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL)
                time.sleep(1)
            except Exception as e:
                print(f"Ping failed: {e}")

def generate_tcp_traffic():
    """Generate some TCP traffic"""
    ports_and_hosts = [
        ('google.com', 80),
        ('github.com', 443),
        ('stackoverflow.com', 80),
    ]
    
    for host, port in ports_and_hosts:
        try:
            print(f"Connecting to {host}:{port}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"Connection to {host}:{port} successful")
            sock.close()
            time.sleep(1)
        except Exception as e:
            print(f"TCP connection failed: {e}")

if __name__ == "__main__":
    print("Starting network traffic generation...")
    print("This will generate DNS, ping, and TCP traffic for testing")
    
    # Start different types of traffic in parallel
    threads = [
        threading.Thread(target=generate_dns_traffic, daemon=True),
        threading.Thread(target=generate_ping_traffic, daemon=True),
        threading.Thread(target=generate_tcp_traffic, daemon=True)
    ]
    
    for thread in threads:
        thread.start()
    
    # Run for 30 seconds
    try:
        time.sleep(30)
    except KeyboardInterrupt:
        print("\nTraffic generation stopped by user")
    
    print("Traffic generation completed")
