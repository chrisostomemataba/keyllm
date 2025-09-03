
# 🔑 KeyLLM

KeyLLM is a lightweight, self-hosted API gateway designed to provide secure, managed access to your local Large Language Models (LLMs).  
Built with a performance-first mindset, it allows developers and organizations to use in-house AI models with the same convenience as cloud-hosted services, while ensuring data privacy and compliance.

This system is built to be:
- **Minimal & Fast**: Uses Go (Fiber) and SQLite for a very low memory footprint.
- **Easy to Deploy**: Runs anywhere in a small Docker container.
- **Simple to Manage**: A clean web UI for managing API keys, models, and usage logs.

---

## 🚀 Features

- ✅ **Secure API Gateway** – Expose local LLMs (like Ollama, LM Studio) via API keys instead of direct model access.  
- ✅ **Model Configuration** – Connect to multiple LLM backends and switch the active model through the UI.  
- ✅ **Usage Monitoring** – Track API calls, token counts, and latency for compliance and analytics.  
- ✅ **Access Control** – Restrict API access using an IP allowlist for enhanced security.  
- ✅ **Simple Admin UI** – A straightforward web dashboard to manage the entire system without coding.  
- ✅ **Dockerized** – Deployable in seconds with Docker Compose.  

---

## 🏗️ Tech Stack

| Component          | Technology Used        |
|--------------------|------------------------|
| **Backend**        | Go (Fiber Framework)   |
| **Database**       | SQLite                 |
| **Frontend**       | Vanilla JS & Tailwind CSS |
| **Containerization** | Docker & Docker Compose |

---

## 📦 Installation & Setup

You can run KeyLLM in two ways: using **Docker** (recommended) or running from **Go source** (for development).

### 1. Running with Docker (Recommended)

**Prerequisites:**
- Docker & Docker Compose installed

**Instructions:**
```bash
# Clone repository
git clone https://github.com/your-username/keyllm.git
cd keyllm

# Start with Docker Compose
docker-compose up --build
````

Once running, the application will be available at:
👉 **[http://localhost:8080](http://localhost:8080)**

**Default Admin Credentials:**

* Email: `admin@local`
* Password: `admin`

---

### 2. Running Locally from Source

**Prerequisites:**

* Go version 1.25+

**Instructions:**

```bash
# Clone repository
git clone https://github.com/your-username/keyllm.git
cd keyllm

# Install dependencies
go mod tidy

# Run the app
go run .
```

Server will be available at:
👉 **[http://localhost:8080](http://localhost:8080)**

---

## 📜 License

MIT License – free to use, modify, and distribute.

---



