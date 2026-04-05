# Free Persistence Guide — Neon.tech + Render

If you are using Render's free tier, you cannot use persistent disks for SQLite. Instead, use this guide to set up a **free PostgreSQL database** on Neon.tech.

## 🐘 1. Set up Neon.tech
1. Go to [Neon.tech](https://neon.tech) and sign up for a free account.
2. Create a new project (e.g., `log-monitor-db`).
3. In the Neon Dashboard, find your **Connection String**. It should look like this:
   `postgresql://alex:AbC123dEf@ep-cool-darkness-123456.us-east-2.aws.neon.tech/neondb?sslmode=require`
4. Copy this string.

## 🚀 2. Configure Render
1. Go to your **Web Service** on Render.
2. Navigate to the **Environment** tab.
3. Click **Add Environment Variable**.
4. Key: `DATABASE_URL`
5. Value: (Paste your Neon connection string here)
6. Click **Save Changes**.

## 🛠 3. How it Works
- **Auto-Detection**: My updated code now checks for `DATABASE_URL`. If it's found, the app automatically switches from SQLite to PostgreSQL.
- **Persistent Logs**: Since Neon is an external database, your logs, users, and node registry will stay safe even if Render restarts your app or you deploy new code.
- **Zero Cost**: Both Render (Web Service) and Neon (Database) have generous free tiers that work together perfectly.

---

> [!IMPORTANT]
> **Database Initialization**: On the first boot with a fresh Neon database, the server will automatically create all necessary tables and seed the default admin account.
> 
> **Admin Password**: Your `ADMIN_PASSWORD` environment variable still works as expected to secure the dashboard.
