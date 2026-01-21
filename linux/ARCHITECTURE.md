# Architecture Overview (ARCHITECTURE.md)

High-level overview of the monitoring system architecture.

---

## 🧱 Components

1. **Monitoring Agent**
   - Runs on each server
   - Collects metrics locally
   - Sends JSON payloads on a fixed interval

2. **Ingest API**
   - Authenticated via Bearer token
   - Validates and stores metrics
   - Applies rate limits and auth rules

3. **Central Storage**
   - Database / time-series store
   - Retains historical metrics

4. **Dashboard / API**
   - Displays server health
   - Alerts and reporting

---

## 🔄 Data Flow

```
+-------------------+
|   Linux Server    |
|                   |
|  monitor-agent.py |
+---------+---------+
          |
          | HTTPS POST (JSON)
          | Authorization: Bearer TOKEN
          v
+----------------------------+
|   Monitoring Ingest API   |
|   /v1/ingest.php          |
+-------------+--------------+
              |
              v
+----------------------------+
|      Metrics Storage       |
|   (DB / Time-Series)       |
+-------------+--------------+
              |
              v
+----------------------------+
|  Dashboard / Admin API     |
+----------------------------+
```

---

## 🔐 Security Model

- One token per server
- Tokens scoped to ingest only
- HTTPS strongly recommended
- Optional IP allowlisting
- Rate limiting at ingress

---

## 📈 Scaling Notes

- Agents are stateless (except network counters)
- Horizontal scaling supported
- Same token format works across environments
