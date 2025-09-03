# 🔑 KeyLLM

KeyLLM is a lightweight **AI-driven compliance and knowledge management system**, built for speed, simplicity, and clarity.  
It is designed to demonstrate how a modern backend can combine **LLM integration**, **structured compliance data**, and **simple APIs** in a project that anyone can set up and run.

---

## 📖 About KeyLLM

KeyLLM was created as a student research project by a developer from a Chinese university.  
The goal was to explore how lightweight architectures (Go + Svelte + SQLite) could be used to build real-world systems that combine **fast APIs**, **clean UI**, and **AI-powered compliance workflows** without heavy infrastructure.  

This system is meant to be:
- **Minimal** – as few files as possible, yet fully functional.  
- **Understandable** – simple syntax that beginners can read and extend.  
- **Docker-friendly** – runs in small containers with very low memory usage.  
- **Scalable enough** – supports Swagger for documentation, and SQLite for persistence.  

---

## 🚀 Features

- ✅ RESTful API with **Go Fiber**
- ✅ Interactive API docs via **Swagger**
- ✅ Lightweight database using **SQLite**
- ✅ Compliance management endpoints
- ✅ LLM endpoints (AI assistance)
- ✅ Simple structure: easy to deploy, easy to extend
- ✅ Perfect for learning **modern lightweight architectures**

---

## 🏗️ Tech Stack

KeyLLM uses only a few, modern, lightweight technologies:

| Component          | Technology Used       | Version   |
|--------------------|-----------------------|-----------|
| **Backend**        | [Go](https://go.dev) | 1.22+     |
| **Web Framework**  | [Fiber](https://gofiber.io) | v2.x |
| **Database**       | [SQLite](https://www.sqlite.org/) | 3.x |
| **API Docs**       | [Swagger](https://swagger.io/) | Latest |
| **Frontend**       | [Svelte](https://svelte.dev) | 5 (planned) |
| **Containerization** | [Docker](https://www.docker.com/) | 24+ |

---

## 📂 Project Structure

```plaintext
keyllm/
│── main.go          # Entry point for the Fiber server
│── database.go      # SQLite connection setup
│── models.go        # Data models (Compliance, LLM, Users)
│── routes.go        # Routes and endpoints
│── go.mod           # Dependencies
│── go.sum
│── README.md        # This file
│── docs/            # Swagger API definitions
└── client/          # Planned Svelte frontend
