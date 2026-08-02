🛡️ Threat System

A backend threat intelligence and security API built with Python and Flask.

The project has now reached an important milestone: it is deployed and running in production, with authentication, role-based access control, PostgreSQL, Docker, logging, and real-time threat intelligence ingestion from URLhaus.

Current capabilities

- 🔐 Password hashing
- 🎫 JWT authentication
- 👥 Role-Based Access Control (RBAC)
- 🛡️ Protected API endpoints
- 🗄️ PostgreSQL database
- 🏗️ Repository + Service Layer architecture
- 🧪 Automated tests
- 📝 Application logging
- 🐳 Docker
- ☁️ Production deployment
- 🌐 REST API
- 🕵️ URLhaus threat intelligence integration
- 📥 CSV threat-intelligence parsing
- 🚨 Import of real malicious URL indicators into the database

Threat Intelligence Pipeline

URLhaus
   ↓
CSV Data
   ↓
Parser
   ↓
Threat Intelligence Service
   ↓
Repository
   ↓
PostgreSQL
   ↓
REST API
   ↓
Future Web UI

A production test successfully imported 10 threat intelligence records from URLhaus.

Architecture

Client
  ↓
Flask REST API
  ↓
Authentication / JWT
  ↓
RBAC
  ↓
Service Layer
  ↓
Repository Layer
  ↓
PostgreSQL

Next step

The next major milestone is building the web UI on top of the existing API.

After that, development will pause so I can study and understand the complete system I've built from end to end.

This project is being developed as a learning project focused on understanding backend engineering, security, APIs, databases, deployment, and threat intelligence.
## 🚀 Current Progress

The web UI milestone is now complete.

### 🛡️ Working Features

- 🔐 JWT authentication
- 👥 Role-based access control
- 🌐 URLhaus threat-intelligence ingestion
- 🗃️ PostgreSQL persistence
- ⚡ Flask REST API
- 📊 Authenticated web dashboard
- 🔴 Threat severity display
- 📡 Online/offline indicator status
- ☁️ Render deployment

### 🔄 End-to-End Pipeline

URLhaus
→ Threat Intelligence Service
→ PostgreSQL
→ Flask REST API
→ JWT Authentication
→ Web Dashboard

The deployed system is successfully importing and displaying real URLhaus threat intelligence through the authenticated dashboard.

### 📈 Current Status

The core backend, database, authentication, threat-intelligence pipeline, deployment, and initial web UI are now working together.

Development will pause here so the complete system can be studied and understood end to end before adding further functionality.

