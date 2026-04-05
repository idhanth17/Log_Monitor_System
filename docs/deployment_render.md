# Render Deployment Guide — Log Monitor System

This guide explains how to deploy the platform to **Render** as a high-availability "Web Service".

## 🏗 Setup & Configuration

### 1. Create a New Web Service
- Connect your GitHub repository to Render.
- Select your `Log_Monitor_System` repository.

### 2. Runtime Configuration
- **Runtime**: `Docker`
- **Region**: Any (choose one close to you)
- **Branch**: `main`

### 3. Environment Variables
Add the following in the **Environment** tab:
- `ADMIN_PASSWORD`: Your secret admin password.
- `DB_PATH`: `/data/logs.db` (Crucial for persistence)
- `PYTHONUNBUFFERED`: `1`

### 4. Setting up Persistence (Important!)
Since SQLite is a file-based database, you **must** attach a persistent disk to your Render service to prevent data loss on restarts.

1. Go to the **Disks** tab in your Render service settings.
2. Click **Add Disk**.
3. Name: `log-data`
4. Mount Path: `/data`
5. Size: `1 GB` (More than enough for logs)

### 5. Deployment
- Click **Manual Deploy** -> **Deploy Latest Commit**.

---

## 🤖 How Node Scaling Works on Render

I have implemented an **Automated Scaling & Rehydration** system specifically for these types of deployments:

- **Add Node via UI**: When you are in the Admin Dashboard and click "Register Node", the server will spawn a background simulator process *inside* your Render container.
- **Failover**: If you stop a node or it crashes, another background process will automatically take over as leader.
- **Persistence**: Because we configured the persistent disk at `/data/logs.db`, the server will remember every node you've added. 
- **Auto-Restart**: If Render restarts your service (e.g., during a sleep cycle or new deploy), the server will automatically scan the database and **re-spawn all your simulators** on boot!

---

## 🔗 Accessing the Service
Once deployed, your URL will look like: 
`https://your-app-name.onrender.com/login.html`

> [!TIP]
> Use Render's **Log Stream** to watch the background simulators initialize and start their leader elections in real-time.
