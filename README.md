# Multi-Agent AI Cybersecurity Framework

An automated AI security framework featuring two specialized, autonomous agents built in pure Python. This framework coordinates an offensive **Penetration Testing Agent** to execute infrastructure scans and a defensive **Cyber Analysis Agent** to evaluate outputs and compile actionable remediation reports. 

By avoiding heavy third-party framework orchestration dependencies, this architecture grants security engineers direct control over script executions, prompt styling, and custom tool integrations.

---

## 🚀 Key Features

* **Multi-Agent Orchestration**: Native Python state loop managing handoffs between offensive and defensive agents.
* **Autonomous Tool Routing**: Automated parsing of structured JSON decisions to deploy standard security tooling.
* **Input Defense & Guardrails**: Strict regex-based shell injection defense and input sanitization layers.
* **Zero Heavy Dependencies**: Lightweight, transparent code infrastructure using standard Python libraries.

---

## 🛠️ Framework Architecture

The ecosystem functions in three primary sequential phases:
1. **Discovery (Penetration Testing Agent)**: Evaluates targets using structured tools and logs raw execution telemetry.
2. **Handoff & Context Assembly**: Aggregates disparate log inputs into standard markdown payload contexts.
3. **Analysis (Cyber Analysis Agent)**: Assesses exposure levels, maps attack vectors, and structures strategic patch playbooks.

---

## 📦 Component Implementation

### 1. Secure Execution Tools (`kali_scripts.py`)

This core module handles process execution and enforces strict parameter sanitization to block malicious command injections (`&`, `;`, `|`, `$`).

```python
import subprocess
import re
import shlex
import os

class KaliScripts:
    """Secure automation scripts for Kali Linux pentesting tools."""

    @staticmethod
    def validate_target(target: str) -> str:
        """Validates that input is a clean IP address or domain name."""
        clean = target.strip()
        if not re.match(r"^[a-zA-Z0-9.-]+$", clean):
            raise ValueError(f"Malicious target input detected: {clean}")
        return clean

    @classmethod
    def run_nmap_stealth(cls, target: str) -> str:
        """Runs a fast, stealthy Syn port scan on common ports."""
        target = cls.validate_target(target)
        cmd = ["nmap", "-sS", "-F", "--open", target]
        return cls._execute(cmd)

    @classmethod
    def run_sqlmap_auto(cls, url: str) -> str:
        """Scans a URL for SQL injection vulnerabilities non-interactively."""
        if not re.match(r"^https?://[a-zA-Z0-9.-]+(?:/[^\s]*)?$", url):
            return "Error: Invalid URL format provided for SQLMap."
        
        cmd = ["sqlmap", "-u", url, "--batch", "--banner", "--risk=1", "--level=1"]
        return cls._execute(cmd, timeout=400)

    @classmethod
    def run_hydra_ssh(cls, target: str, username: str, wordlist_path: str) -> str:
        """Attempts an automated SSH brute force scan against a target."""
        target = cls.validate_target(target)
        if not os.path.exists(wordlist_path):
            return f"Error: Wordlist not found at {wordlist_path}"
        
        cmd = ["hydra", "-l", username, "-P", wordlist_path, f"ssh://{target}", "-t", "4"]
        return cls._execute(cmd, timeout=300)

    @classmethod
    def run_searchsploit(cls, service_name: str) -> str:
        """Queries the Exploit Database for known public exploits."""
        clean_service = re.sub(r"[^a-zA-Z0-9\s-]", "", service_name)
        cmd = ["searchsploit", clean_service]
        return cls._execute(cmd)

    @staticmethod
    def _execute(cmd: list, timeout: int = 200) -> str:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            if result.returncode != 0 and not result.stdout:
                return f"Execution Error (Code {result.returncode}): {result.stderr}"
            return result.stdout
        except subprocess.TimeoutExpired:
            return "Error: Script execution timed out."
        except FileNotFoundError:
            return f"Error: The system command '{cmd[0]}' is not installed in this environment."
```

### 2. Multi-Agent AI Core Framework (`agent_framework.py`)

Manages individual agent prompt context profiles and routes automated decision cycles.

```python
import json

class CyberAgentFramework:
    def __init__(self, target_asset: str, llm_client=None):
        self.target = target_asset
        self.llm = llm_client
        self.history = []

    def get_pen_tester_prompt(self, objective: str) -> str:
        return f"""
        You are an automated Penetration Testing AI Agent. Your objective: {objective}
        Target Asset: {self.target}

        Available Tools:
        1. "run_nmap_stealth" -> Scans for open ports.
        2. "run_sqlmap_auto" -> Tests a web URL for SQL Injection. Input parameter format: "url"
        3. "run_hydra_ssh" -> Tests SSH login strength. Input parameters format: "username", "wordlist_path"
        4. "run_searchsploit" -> Searches for public exploits. Input parameter format: "service_name"

        You must respond in pure JSON. Choose ONE tool to execute next.
        Format: {{"reasoning": "Why you chose this", "tool_name": "name", "arguments": {{"arg_name": "value"}}}}
        If your task is complete or you cannot proceed, respond with: {{"status": "COMPLETE", "findings": "Summary"}}
        """

    def get_analyst_prompt(self, raw_tool_logs: str) -> str:
        return f"""
        You are a Cyber Security Analysis AI Agent. 
        Review the following raw output logs collected from tool scans on the asset: {self.target}.

        Logs to Analyze:
        ---
        {raw_tool_logs}
        ---

        Provide a structured assessment report covering:
        1. Identified Vulnerabilities & Risk Levels (High/Med/Low)
        2. Threat Vectors and potential impacts
        3. Immediate, actionable remediation and patching recommendations.
        """

    def execute_pentest_loop(self, objective: str, max_turns: int = 3):
        """Orchestrates the Pentesting agent's discovery phase."""
        print(f"[*] Starting Penetration Testing Session against: {self.target}")
        context_prompt = self.get_pen_tester_prompt(objective)
        collected_logs = ""

        for turn in range(max_turns):
            print(f"\n[Turn {turn + 1}] Querying Penetration Testing Agent...")
            
            # Simulated agent logic loop; integrate your LLM client chat completions here:
            if turn == 0:
                agent_decision = {
                    "reasoning": "Need to map the target attack surface first.",
                    "tool_name": "run_nmap_stealth",
                    "arguments": {}
                }
            elif turn == 1:
                agent_decision = {
                    "reasoning": "Found port 22 open. Testing for weak remote admin credentials.",
                    "tool_name": "run_hydra_ssh",
                    "arguments": {"username": "root", "wordlist_path": "/usr/share/wordlists/rockyou.txt"}
                }
            else:
                agent_decision = {"status": "COMPLETE", "findings": "Scans finished. Potential weak SSH configs flagged."}

            if "status" in agent_decision and agent_decision["status"] == "COMPLETE":
                print(f"[+] Pentest Agent declared completion: {agent_decision['findings']}")
                break

            tool_name = agent_decision.get("tool_name")
            args = agent_decision.get("arguments", {})
            print(f"[Agent Decision]: Running {tool_name} with args: {args}")

            try:
                if tool_name == "run_nmap_stealth":
                    output = KaliScripts.run_nmap_stealth(self.target)
                elif tool_name == "run_sqlmap_auto":
                    output = KaliScripts.run_sqlmap_auto(args.get("url"))
                elif tool_name == "run_hydra_ssh":
                    output = KaliScripts.run_hydra_ssh(self.target, args.get("username"), args.get("wordlist_path"))
                elif tool_name == "run_searchsploit":
                    output = KaliScripts.run_searchsploit(args.get("service_name"))
                else:
                    output = f"Error: Tool '{tool_name}' is unauthorized or unknown."
            except Exception as e:
                output = f"Execution Exception: {str(e)}"

            print(f"[{tool_name} Execution Complete. Data logged.]")
            collected_logs += f"\n--- Script execution output for {tool_name} ---\n{output}\n"

        return collected_logs

    def run_analysis_phase(self, raw_logs: str):
        """Hands off the penetration testing telemetry data to the analyst agent."""
        print("\n[*] Handing off raw intelligence to Cyber Analysis Agent...")
        analyst_prompt = self.get_analyst_prompt(raw_logs)
        print("[+] Analyst Agent prompt generated successfully. Framework ready to output final report mapping.")
        return analyst_prompt
```

---

## 🏁 Getting Started

To verify the end-to-end orchestration orchestration logic out of the box, run the module directly:

```python
if __name__ == "__main__":
    # Define a safe domain or IP you own or have legal authorization to test
    TARGET_ASSET = "192.168.1.55"
    MISSION = "Audit open attack surfaces and verify host resilience."

    # Initialize the framework
    framework = CyberAgentFramework(target_asset=TARGET_ASSET)
    
    # Phase 1: Automated Pentester Runs the Scripts
    raw_telemetry = framework.execute_pentest_loop(objective=MISSION, max_turns=3)
    
    # Phase 2: Cyber Analyst Builds a Vulnerability & Patch Report
    analyst_context = framework.run_analysis_phase(raw_telemetry)
```

---

## 🛡️ Safety, Sandboxing, & Security Guardrails

Running autonomous agents with access to offensive tooling poses real operational risks. Strictly implement the following deployment checklist before production use:

* **Docker Network Isolation**: Build your agent execution container with a restricted bridge network. Enforce specific `iptables` rules to explicitly drop unauthorized outbound routes to the public internet.
* **Strict Parameter Sanitization**: Keep `KaliScripts.validate_target` active and expand it to cover all custom inputs. This locks down parameters against characters like `;`, `&`, `|`, and `$`, stopping rogue tool logic or prompt-injection exploits from breaking out of the container workspace.
* **Non-Root Runtime Constraints**: Never run this orchestration suite under system root privileges. Enforce a dedicated, low-privilege service account inside your Kali Linux container ecosystem.

---

## ⚖️ Disclaimer

This framework is developed strictly for **authorized security testing, educational validation, and defense hardening optimization**. Executing offensive penetration scanning tools against infrastructure without explicit, written prior authorization from the asset owners is illegal. Developers assume no liability for misuse or damage caused by this orchestration software.
