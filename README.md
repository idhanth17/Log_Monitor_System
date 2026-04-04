# Distributed Log Monitoring & Access Platform

A modern, access-controlled platform for distributed logging and service monitoring.

## Features
- **Centralized Ingestion**: Distributed nodes send logs to a central collector.
- **RBAC & Auth**: Role-based access control with Admin and User roles.
- **Service Registry**: Public, Private, and Managed (Protected) service modes.
- **Live Monitoring**: Real-time session tracking, kick functionality, and log streams.
- **Docker Ready**: Fully containerized with SQLite persistence.

## Development
```bash
# Start the server
./venv/Scripts/python collector/server.py
```

## Deployment
See [deployment_guide.md](./deployment_guide.md) for instructions on Railway, Render, and VPS.
