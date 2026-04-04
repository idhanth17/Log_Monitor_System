"""
Node Heartbeat Simulator
Sends regular pulses to the collector to keep services 'Online' in the registry.
No randomized log generation — only real user logs are shown in the dashboard.
"""
import os
import time
import requests
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Configuration
COLLECTOR_URL = os.getenv("HEARTBEAT_URL", "http://localhost:8000/api/heartbeat")
PLATFORM_SERVICES = ["auth-service", "data-vault", "payment-gateway", "ml-inference-node", "worker-pool-01"]

def run():
    logging.info("Heartbeat Simulator initialized. Monitoring platform nodes...")
    
    while True:
        for svc in PLATFORM_SERVICES:
            try:
                requests.post(
                    COLLECTOR_URL,
                    json={
                        "service_name": svc,
                        "host_id": "sim-node-01",
                        "status": "active"
                    },
                    timeout=2
                )
            except Exception as e:
                logging.debug(f"Heartbeat failed for {svc}: {e}")
        
        time.sleep(10)

if __name__ == "__main__":
    run()
