# README

<div align="center">

# 🛡️ RiskCodeAI

**100% Open-Source, Privacy-First Dependency Analysis Platform**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Rust 1.80+](https://img.shields.io/badge/rust-1.80+-orange.svg)](https://www.rust-lang.org/)
[![FastAPI 0.115](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com/)

[Features](#features) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Architecture](#architecture) • [Contributing](#contributing)

</div>

---

## 🎯 What is RiskCodeAI?

RiskCodeAI is a **privacy-first**, **AI-powered** dependency analysis platform that helps developers:

✅ **Detect vulnerabilities** in dependencies (npm, pypi, Maven, Go)  
✅ **Analyze reachability** — verify if vulnerabilities are actually exploitable in your code  
✅ **Generate AI changelogs** — understand breaking changes, features, bugfixes  
✅ **Zero infrastructure cost** — 100% open-source, self-hosted, $0 to run  
✅ **Privacy-first** — Source code never leaves your machine (local LLM)

---

## 🚀 Quick Start

### Option 1: CLI Only (Primary - Zero Cost)

```bash
# Install via pip
pip install riskcodeai

# Setup local LLM (Ollama)
curl -sSL https://ollama.ai/install.sh | sh
ollama pull deepseek-coder-v2:16b-q4

# Analyze your project
riskcodeai scan ./your-project

# View report
riskcodeai report --format html
```

**Requirements:**
- Python 3.12+
- 16GB RAM (for DeepSeek 16B quantized)
- Docker (optional, for web dashboard)

---

### Option 2: Docker Compose (Small Teams)

```bash
# Clone repository
git clone https://github.com/riskcodeai/riskcodeai.git
cd riskcodeai

# Start all services
docker compose up -d

# Access web dashboard
open http://localhost:8080
```

**Services:**
- PostgreSQL 17 + pgvector
- Ollama (local LLM)
- FastAPI backend
- Next.js web dashboard

---

## ✨ Features

### 🔍 Smart Dependency Analysis
- **Multi-ecosystem**: npm, PyPI, Maven, Go modules
- **Behavioral analysis**: Detects malicious install scripts, obfuscation
- **Supply chain security**: Monitors for suspicious patterns

### 🎯 Reachability Analysis (Tier 2)
- **Call graph analysis**: Determines if vulnerable code is actually called
- **False positive reduction**: <20% false positive rate
- **Full call stacks**: Shows exact execution paths to vulnerabilities

### 🤖 AI-Powered Insights
- **Local LLM** (Ollama + DeepSeek-Coder-V2)
- **Changelog generation**: Breaking changes, features, bugfixes
- **Impact assessment**: Upgrade difficulty scoring
- **Auto-fix suggestions**: Agentic repair for common issues

### 🔒 Privacy-First
- **No telemetry**: Zero data collection
- **On-premise LLM**: Code never uploaded to cloud
- **Self-hosted**: Full control over your data

### 💰 Zero Cost
- **100% open-source**: All technologies (Python, Rust, PostgreSQL, Ollama)
- **No API fees**: Local LLM instead of OpenAI ($0 vs $0.01/1k tokens)
- **Self-hosted**: No SaaS subscription ($0 vs Snyk $25-99/user/month)

---

## 📖 Documentation

### Getting Started
- [Installation Guide](docs/deployment/options.md)
- [CLI Reference](docs/api/cli-interface.md)
- [Configuration](docs/operations/documentation-plan.md)

### Architecture
- [Folder Structure](docs/architecture/01-folder-structure.md)
- [Technology Stack](docs/architecture/02-tech-stack.md)
- [Core Workflow](docs/architecture/03-core-workflow.md)
- [Python-Rust Interface](docs/architecture/04-python-rust-interface.md)

### Development
- [Sprint Plan](docs/development/sprint-plan.md) (5 sprints, 12 weeks)
- [Testing Strategy](docs/development/testing-strategy.md)
- [CI/CD Pipeline](docs/development/ci-cd.md)

### Deployment
- [Deployment Options](docs/deployment/options.md) (CLI / Docker / Kubernetes)
- [Monitoring](docs/deployment/monitoring.md) (Prometheus + Grafana)
- [Security](docs/deployment/security.md)

### Operations
- [Budget & Scenarios](docs/operations/budget.md) (Solo $0 → Enterprise $90k)
- [Risk Management](docs/operations/risks.md)

---

## 🏗️ Architecture

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│   CLI/IDE   │─────▶│  Core Engine │─────▶│   Ollama    │
│  (Python)   │      │ (Python+Rust)│      │ (Local LLM) │
└─────────────┘      └──────────────┘      └─────────────┘
                            │
                            ▼
                     ┌──────────────┐      ┌─────────────┐
                     │   FastAPI    │─────▶│ PostgreSQL  │
                     │   Backend    │      │  + pgvector │
                     └──────────────┘      └─────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │   Next.js    │
                     │  Dashboard   │
                     └──────────────┘
```

**Hybrid Python + Rust:**
- **Python**: Business logic, AI orchestration, API
- **Rust**: AST parsing, graph algorithms (via PyO3)

For detailed architecture, see [Technical Design](TECHNICAL_DESIGN.md).

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Development Setup:**
```bash
# Clone repository
git clone https://github.com/riskcodeai/riskcodeai.git
cd riskcodeai

# Install dependencies (Python)
cd packages/core-engine
poetry install

# Install dependencies (Rust)
cd rust_native
cargo build

# Run tests
pytest
cargo test
```

---

## 🌐 Community

- **GitHub Discussions**: Ask questions, share ideas
- **Discord**: Real-time chat (coming soon)
- **Twitter/X**: [@riskcodeai](https://twitter.com/riskcodeai) (coming soon)

---

## 📊 Roadmap

**MVP (Sprints 1-5, 12 weeks):**
- [x] Manifest parsing (npm, PyPI)
- [x] OSV.dev integration
- [x] AI changelog generation
- [x] Reachability analysis (Tier 2)
- [ ] Web dashboard
- [ ] VS Code extension

**Phase 2:**
- [ ] Tier 3 dataflow analysis
- [ ] Multi-language support (Java, Go)
- [ ] Agentic auto-fix
- [ ] Semantic vulnerability search (pgvector)

See [Release Strategy](docs/development/release-strategy.md) for details.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- **OSV.dev**: Free vulnerability database
- **Ollama**: Local LLM runtime
- **DeepSeek**: Code-specialized LLM
- **tree-sitter**: Fast AST parsing

---

<div align="center">

**Built with ❤️ by the open-source community**

[⭐ Star us on GitHub](https://github.com/riskcodeai/riskcodeai) • [📖 Read the Docs](docs/) • [🐛 Report Bug](https://github.com/riskcodeai/riskcodeai/issues)

</div>
