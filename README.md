# 🧠 GhostTrace

**Semi-Automated Memory Forensics Tool for Fileless Malware Detection**

[![CI](https://github.com/your-org/GhostTrace/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/GhostTrace/actions)

> A prompt-driven, AI-powered CLI framework that automates Volatility memory analysis, threat scoring, timeline reconstruction, and mandatory PDF forensic report generation.

---

## Architecture

```
User Prompt
    │
    ▼
MemForensicAgent (ReAct Loop)  ─── OpenAI / Ollama
    │  ↕ tool calls
Tool Executor
    ├── volatility_runner    (pslist, pstree, malfind, netscan, dlllist, cmdline, handles)
    ├── acquisition          (verify_dump_integrity, get_dump_info)
    ├── process_inspector    (detect_process_anomalies)
    ├── network_inspector    (detect_suspicious_connections)
    ├── powershell_decoder   (decode_powershell_commands, extract_iocs)
    ├── threat_scorer        (score_threats → 0-100 / LOW-CRITICAL)
    ├── timeline_builder     (build_attack_timeline)
    └── report_generator     → PDF + HTML + JSON
```

---

## Quick Start

### 1. Setup Environment

```bash
# Clone the project
cd "e:/New folder"

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# or: source .venv/bin/activate  (Linux/Mac)

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Configure environment
copy .env.example .env
# Edit .env: set OPENAI_API_KEY and VOLATILITY_PATH
```

### 2. Run Interactive Mode (REPL)

```bash
# With a real memory dump
python -m cli.main interactive --dump "C:/evidence/memdump.mem"

# Mock mode (no VM/Volatility needed — demo mode)
python -m cli.main interactive --mock
```

### 3. One-Shot Analysis

```bash
python -m cli.main analyze \
  --dump "C:/evidence/memdump.mem" \
  --query "Perform complete forensic analysis and generate a PDF report" \
  --output "./output"
```

### 4. Verify Dump Integrity

```bash
python -m cli.main verify-dump "C:/evidence/memdump.mem" \
  --hash "abc123...sha256hash"
```

### 5. Available CLI Commands

| Command | Description |
|---------|-------------|
| `interactive` | Rich-powered REPL forensic session |
| `analyze` | One-shot analysis with LLM agent |
| `score` | Score threats from artefacts JSON |
| `report` | Generate report from saved session |
| `verify-dump` | Verify dump integrity (SHA-256) |

---

## Interactive REPL Commands

| Command | Action |
|---------|--------|
| `!help` | Show commands |
| `!status` | Session statistics |
| `!save` | Save session to JSON |
| `!report` | Generate PDF forensic report |
| `!reset` | Start new investigation |
| `!tools` | List all forensic tools |
| `!quit` | Exit |

---

## Threat Scoring Model

| Category | Weight | Indicator |
|----------|--------|-----------|
| Malfind injections | 30 | Code injection / shellcode |
| Encoded PowerShell | 20 | Fileless payload delivery |
| Process anomalies | 20 | Hollowing, spoofing, orphans |
| Network anomalies | 15 | C2 connections |
| DLL anomalies | 10 | Reflective injection |
| Handle anomalies | 5 | Privilege escalation |

| Score | Level | Action |
|-------|-------|--------|
| 0–30 | 🟢 LOW | Monitor |
| 31–65 | 🟡 MEDIUM | Investigate |
| 66–89 | 🔴 HIGH | Contain immediately |
| 90–100 | 💀 CRITICAL | Incident response |

---

## Configuration

Edit `.env`:

```env
LLM_PROVIDER=openai          # or: ollama
OPENAI_API_KEY=sk-...
LLM_MODEL=gpt-4o

# For Ollama (local, no API key):
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3

VOLATILITY_PATH=C:/volatility3/vol.py
VOLATILITY_VERSION=vol3      # or vol2
MEMORY_DUMP_PATH=
REPORT_OUTPUT_DIR=./output
```

---

## Running Without Volatility / API (Demo Mode)

```bash
# Uses fixture data from tests/fixtures/
python -m cli.main interactive --mock
```

This demonstrates the full pipeline — process analysis, scoring, timeline, PDF report — without any real memory dump or API calls.

---

## Development

```bash
# Run tests
pytest tests/ -v --cov=. --cov-report=term-missing

# Lint
ruff check .

# Type check
mypy core/ tools/ cli/ reporting/

# Or use Makefile
make test
make lint
make mock     # run in demo mode
```

---

## Project Structure

```
GhostTrace/
├── cli/                    # CLI entry point & REPL
│   ├── main.py             # Click commands
│   ├── interactive.py      # Rich REPL
│   └── banner.py           # ASCII banner
├── core/                   # Agent engine
│   ├── agent.py            # ReAct loop (OpenAI/Ollama)
│   ├── system_prompt.py    # Investigator persona & protocol
│   ├── tool_registry.py    # JSON schema for all 20 tools
│   └── tool_executor.py    # Tool dispatch + error handling
├── tools/                  # Forensic tool wrappers
│   ├── volatility_runner.py
│   ├── acquisition.py
│   ├── process_inspector.py
│   ├── network_inspector.py
│   ├── powershell_decoder.py
│   ├── threat_scorer.py
│   └── timeline_builder.py
├── reporting/              # Report generation
│   ├── report_generator.py
│   ├── pdf_exporter.py     # WeasyPrint + ReportLab
│   └── templates/report.html
├── tests/                  # Unit tests
│   └── fixtures/           # Mock Volatility outputs
├── config/config.yaml
├── .env.example
├── requirements.txt
└── .github/workflows/ci.yml
```

---

## Supported Memory Dump Formats

`.mem`, `.raw`, `.dmp`, `.vmem`, `.lime`

## Memory Acquisition Tools (external)

- **DumpIt** (Windows — recommended)
- **WinPMEM** (open source)
- **FTK Imager**

Always compute and record the dump's SHA-256 hash immediately after acquisition for chain-of-custody.
