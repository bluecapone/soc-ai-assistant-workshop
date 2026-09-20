#!/usr/bin/env python3

import json
import os
import re
import sys
from pathlib import Path

# Resolve paths relative to this file
checkpoints_dir = Path(__file__).parent
lab_dir = checkpoints_dir.parent

# Track failures
failures = []

def log_ok(msg):
    print(f"ok: {msg}")

def log_fail(msg, detail=""):
    print(f"FAIL: {msg}: {detail}")
    failures.append((msg, detail))

# Check 1: JSON parsing and id/name pairs
files_to_check = [
    (checkpoints_dir / "module-2" / "triage-m2-chain.json", "soctriagem2chk01", "SOC triage, Module 2 checkpoint (LLM chain)"),
    (checkpoints_dir / "module-3" / "triage-m3-agent.json", "soctriagem3chk01", "SOC triage, Module 3 checkpoint (AI Agent)"),
    (lab_dir / "exercises" / "module-2" / "skeleton.json", "soctriageskel001", "SOC triage, build here (skeleton)"),
]

for filepath, expected_id, expected_name in files_to_check:
    try:
        with open(filepath) as f:
            data = json.load(f)
        
        if data.get("id") != expected_id:
            log_fail(f"Check 1: {filepath.name} id", f"expected {expected_id}, got {data.get('id')}")
        elif data.get("name") != expected_name:
            log_fail(f"Check 1: {filepath.name} name", f"expected {expected_name}, got {data.get('name')}")
        elif data.get("active") is not False:
            log_fail(f"Check 1: {filepath.name} active", f"expected False, got {data.get('active')}")
        else:
            log_ok(f"Check 1: {filepath.name} parses with correct id, name, and active=false")
    except Exception as e:
        log_fail(f"Check 1: {filepath.name} parse", str(e))

# Check 2: Credentials use only allowed ids
allowed_cred_ids = {"credWazuhIndex01", "credTheHiveN8n01", "credModelGatewy1"}

files_for_cred_check = [
    checkpoints_dir / "module-2" / "triage-m2-chain.json",
    checkpoints_dir / "module-3" / "triage-m3-agent.json",
    lab_dir / "exercises" / "module-2" / "skeleton.json",
    lab_dir / "platform" / "n8n" / "triage-workflow.json",
]

for filepath in files_for_cred_check:
    try:
        with open(filepath) as f:
            data = json.load(f)
        
        bad_creds = []
        for node in data.get("nodes", []):
            if "credentials" in node:
                for cred_type, cred_info in node.get("credentials", {}).items():
                    cred_id = cred_info.get("id")
                    if cred_id not in allowed_cred_ids:
                        bad_creds.append(cred_id)
        
        if bad_creds:
            log_fail(f"Check 2: {filepath.name} credentials", f"unexpected ids: {', '.join(set(bad_creds))}")
        else:
            log_ok(f"Check 2: {filepath.name} all credentials use allowed ids")
    except Exception as e:
        log_fail(f"Check 2: {filepath.name}", str(e))

# Check 3: SKILL.md sections appear in M2 and M3 system messages
# The finished Module 1 skill is instructor material (instructor-docs/module1/skills/soc-triage), not shipped here.
skill_path = Path(os.environ.get("SOC_TRIAGE_SKILL", checkpoints_dir / ".." / ".." / ".." / "instructor-docs" / "module1" / "skills" / "soc-triage" / "SKILL.md"))
try:
    with open(skill_path) as f:
        skill_content = f.read()
    
    # Remove frontmatter
    lines = skill_content.split('\n')
    frontmatter_count = 0
    start_idx = 0
    for i, line in enumerate(lines):
        if line.strip().startswith('---'):
            frontmatter_count += 1
            if frontmatter_count == 2:
                start_idx = i + 1
                break
    
    content_without_fm = '\n'.join(lines[start_idx:])
    
    # Split by sections
    sections = {}
    current_section = None
    current_body = []
    
    for line in content_without_fm.split('\n'):
        if line.startswith('## '):
            if current_section:
                sections[current_section] = '\n'.join(current_body).strip()
            current_section = line[3:]
            current_body = []
        else:
            current_body.append(line)
    
    if current_section:
        sections[current_section] = '\n'.join(current_body).strip()
    
    # Extract needed sections
    task_full = sections.get('Task', '')
    task_match = re.search(r'^\s*(.+?\.\s+)', task_full, re.DOTALL)
    if task_match:
        task_body = task_full[task_match.end():].strip()
    else:
        task_body = task_full
    
    how_to_judge = sections.get('How to judge', '')
    verdict_contract = sections.get('Verdict contract', '')
    guardrails = sections.get('Guardrails', '')
    
    sections_to_check = [
        ('Task (after first sentence)', task_body),
        ('How to judge', how_to_judge),
        ('Verdict contract', verdict_contract),
        ('Guardrails', guardrails),
    ]
    
    # Check M2
    with open(checkpoints_dir / "module-2" / "triage-m2-chain.json") as f:
        m2_data = json.load(f)
    
    m2_node_found = False
    for node in m2_data['nodes']:
        if node.get('name') == 'Triage (LLM chain)':
            m2_node_found = True
            msg_values = node.get('parameters', {}).get('messages', {}).get('messageValues', [])
            if not msg_values:
                log_fail("Check 3: M2 node", "messageValues is empty")
            else:
                m2_message = msg_values[0].get('message', '')
                
                for section_name, section_text in sections_to_check:
                    if not section_text:
                        log_fail(f"Check 3: M2 {section_name}", "section text is empty")
                    elif section_text not in m2_message:
                        log_fail(f"Check 3: M2 {section_name}", f"not found in Triage (LLM chain) node")
                    else:
                        log_ok(f"Check 3: M2 {section_name} in node message")
            break
    
    if not m2_node_found:
        log_fail("Check 3: M2 node", "Triage (LLM chain) node not found")
    
    # Check M3
    with open(checkpoints_dir / "module-3" / "triage-m3-agent.json") as f:
        m3_data = json.load(f)
    
    m3_node_found = False
    for node in m3_data['nodes']:
        if node.get('name') == 'Triage (AI Agent)':
            m3_node_found = True
            sys_msg = node.get('parameters', {}).get('options', {}).get('systemMessage', '')
            if not sys_msg:
                log_fail("Check 3: M3 node", "systemMessage is empty")
            else:
                for section_name, section_text in sections_to_check:
                    if not section_text:
                        log_fail(f"Check 3: M3 {section_name}", "section text is empty")
                    elif section_text not in sys_msg:
                        log_fail(f"Check 3: M3 {section_name}", f"not found in Triage (AI Agent) node")
                    else:
                        log_ok(f"Check 3: M3 {section_name} in systemMessage")
            break
    
    if not m3_node_found:
        log_fail("Check 3: M3 node", "Triage (AI Agent) node not found")
except Exception as e:
    log_fail("Check 3: SKILL.md parsing", str(e))

# Check 4: Webhook path "thehive-alert"
webhook_files = [
    (checkpoints_dir / "module-2" / "triage-m2-chain.json", "soctriagem2chk01"),
    (checkpoints_dir / "module-3" / "triage-m3-agent.json", "soctriagem3chk01"),
    (lab_dir / "exercises" / "module-2" / "skeleton.json", "soctriageskel001"),
    (lab_dir / "platform" / "n8n" / "triage-workflow.json", "soctriageref001"),
]

for filepath, workflow_id in webhook_files:
    try:
        with open(filepath) as f:
            data = json.load(f)
        
        webhook_nodes = []
        for node in data.get("nodes", []):
            if node.get("type") == "n8n-nodes-base.webhook":
                path = node.get("parameters", {}).get("path")
                if path == "thehive-alert":
                    webhook_nodes.append(node.get("name"))
        
        if len(webhook_nodes) != 1:
            log_fail(f"Check 4: {filepath.name} webhook", f"expected 1 node with path thehive-alert, found {len(webhook_nodes)}")
        else:
            log_ok(f"Check 4: {filepath.name} has exactly one webhook with path thehive-alert")
    except Exception as e:
        log_fail(f"Check 4: {filepath.name}", str(e))

# Check 5: Node shape validation
try:
    # M2 Triage node shape
    with open(checkpoints_dir / "module-2" / "triage-m2-chain.json") as f:
        m2_data = json.load(f)
    
    m2_triage_found = False
    for node in m2_data['nodes']:
        if node.get('name') == 'Triage (LLM chain)':
            m2_triage_found = True
            
            # Check type and typeVersion
            if node.get('type') != "@n8n/n8n-nodes-langchain.chainLlm":
                log_fail("Check 5: M2 Triage type", f"expected @n8n/n8n-nodes-langchain.chainLlm, got {node.get('type')}")
            elif node.get('typeVersion') != 1.7:
                log_fail("Check 5: M2 Triage typeVersion", f"expected 1.7, got {node.get('typeVersion')}")
            else:
                log_ok("Check 5: M2 Triage type and typeVersion correct")
            
            # Check parameters
            params = node.get('parameters', {})
            if params.get('promptType') != "define":
                log_fail("Check 5: M2 Triage promptType", f"expected 'define', got {params.get('promptType')}")
            else:
                log_ok("Check 5: M2 Triage promptType correct")
            
            if params.get('hasOutputParser') is not True:
                log_fail("Check 5: M2 Triage hasOutputParser", f"expected True, got {params.get('hasOutputParser')}")
            else:
                log_ok("Check 5: M2 Triage hasOutputParser correct")
            
            if params.get('text') != "={{ JSON.stringify($json, null, 2) }}":
                log_fail("Check 5: M2 Triage text", f"expected '={{ JSON.stringify($json, null, 2) }}', got {params.get('text')}")
            else:
                log_ok("Check 5: M2 Triage text correct")
            
            if 'prompt' in params:
                log_fail("Check 5: M2 Triage parameters", "unexpected 'prompt' key in parameters")
            else:
                log_ok("Check 5: M2 Triage no unexpected 'prompt' key")
            break
    
    if not m2_triage_found:
        log_fail("Check 5: M2 Triage node", "Triage (LLM chain) node not found")
    
    # M3 Triage node shape
    with open(checkpoints_dir / "module-3" / "triage-m3-agent.json") as f:
        m3_data = json.load(f)
    
    m3_triage_found = False
    for node in m3_data['nodes']:
        if node.get('name') == 'Triage (AI Agent)':
            m3_triage_found = True
            
            # Check type and typeVersion
            if node.get('type') != "@n8n/n8n-nodes-langchain.agent":
                log_fail("Check 5: M3 Triage type", f"expected @n8n/n8n-nodes-langchain.agent, got {node.get('type')}")
            elif node.get('typeVersion') != 2.2:
                log_fail("Check 5: M3 Triage typeVersion", f"expected 2.2, got {node.get('typeVersion')}")
            else:
                log_ok("Check 5: M3 Triage type and typeVersion correct")
            
            # Check parameters
            params = node.get('parameters', {})
            if params.get('promptType') != "define":
                log_fail("Check 5: M3 Triage promptType", f"expected 'define', got {params.get('promptType')}")
            else:
                log_ok("Check 5: M3 Triage promptType correct")
            
            if params.get('hasOutputParser') is not True:
                log_fail("Check 5: M3 Triage hasOutputParser", f"expected True, got {params.get('hasOutputParser')}")
            else:
                log_ok("Check 5: M3 Triage hasOutputParser correct")
            
            if params.get('text') != "={{ JSON.stringify($json, null, 2) }}":
                log_fail("Check 5: M3 Triage text", f"expected '={{ JSON.stringify($json, null, 2) }}', got {params.get('text')}")
            else:
                log_ok("Check 5: M3 Triage text correct")
            
            options = params.get('options', {})
            if options.get('maxIterations') != 10:
                log_fail("Check 5: M3 Triage maxIterations", f"expected 10, got {options.get('maxIterations')}")
            else:
                log_ok("Check 5: M3 Triage maxIterations correct")
            
            if options.get('returnIntermediateSteps') is not True:
                log_fail("Check 5: M3 Triage returnIntermediateSteps", f"expected True, got {options.get('returnIntermediateSteps')}")
            else:
                log_ok("Check 5: M3 Triage returnIntermediateSteps correct")
            
            if 'prompt' in params:
                log_fail("Check 5: M3 Triage parameters", "unexpected 'prompt' key in parameters")
            else:
                log_ok("Check 5: M3 Triage no unexpected 'prompt' key")
            break
    
    if not m3_triage_found:
        log_fail("Check 5: M3 Triage node", "Triage (AI Agent) node not found")
    
    # Check OutputParserStructured nodes (skip skeleton)
    for file_label, file_path in [("M2", checkpoints_dir / "module-2" / "triage-m2-chain.json"), 
                                   ("M3", checkpoints_dir / "module-3" / "triage-m3-agent.json")]:
        with open(file_path) as f:
            data = json.load(f)
        
        parser_nodes = [n for n in data['nodes'] if n.get('type') == "@n8n/n8n-nodes-langchain.outputParserStructured"]
        
        if len(parser_nodes) != 1:
            log_fail(f"Check 5: {file_label} parser node", f"expected 1 OutputParserStructured node, found {len(parser_nodes)}")
        else:
            parser = parser_nodes[0]
            try:
                schema = json.loads(parser.get('parameters', {}).get('inputSchema', '{}'))
                props = schema.get('properties', {})
                
                if 'suggested_close_state' not in props:
                    log_fail(f"Check 5: {file_label} schema", "missing 'suggested_close_state' property")
                else:
                    enum = props['suggested_close_state'].get('enum', [])
                    expected_enum = ["true positive", "false positive", "true positive not malicious", "other"]
                    if enum != expected_enum:
                        log_fail(f"Check 5: {file_label} schema enum", f"expected {expected_enum}, got {enum}")
                    else:
                        log_ok(f"Check 5: {file_label} schema suggested_close_state enum correct")
                
                if file_label == "M3":
                    if 'determination' not in props:
                        log_fail(f"Check 5: M3 schema", "missing 'determination' property")
                    else:
                        log_ok(f"Check 5: M3 schema has 'determination' property")
                else:
                    if 'determination' in props:
                        log_fail(f"Check 5: {file_label} schema", "unexpected 'determination' property")
                    else:
                        log_ok(f"Check 5: {file_label} schema no 'determination' property")
            except Exception as e:
                log_fail(f"Check 5: {file_label} schema parse", str(e))
    
    # Check tool connections in M3
    m3_connections = m3_data.get('connections', {})
    
    tool_names = ["wazuh_events_for_ip", "wazuh_events_for_host", "ip_reputation"]
    for tool_name in tool_names:
        if tool_name not in m3_connections:
            log_fail(f"Check 5: M3 tool connection", f"tool '{tool_name}' has no connection entry")
        else:
            tool_conns = m3_connections[tool_name].get('ai_tool', [[]])
            found_triage = False
            if tool_conns and tool_conns[0]:
                for conn in tool_conns[0]:
                    if conn.get('node') == 'Triage (AI Agent)' and conn.get('type') == 'ai_tool':
                        found_triage = True
                        break
            
            if not found_triage:
                log_fail(f"Check 5: M3 tool connection", f"tool '{tool_name}' not connected to Triage (AI Agent) via ai_tool")
            else:
                log_ok(f"Check 5: M3 tool '{tool_name}' connected via ai_tool")
    
    # Check for ".item.json" in all generated files
    for file_label, file_path in [("M2", checkpoints_dir / "module-2" / "triage-m2-chain.json"),
                                   ("M3", checkpoints_dir / "module-3" / "triage-m3-agent.json"),
                                   ("skeleton", lab_dir / "exercises" / "module-2" / "skeleton.json")]:
        with open(file_path) as f:
            file_content = f.read()
        
        if ".item.json" in file_content:
            log_fail(f"Check 5: {file_label} substring", "contains '.item.json' substring")
        else:
            log_ok(f"Check 5: {file_label} no '.item.json' substring")

except Exception as e:
    log_fail("Check 5: node shape validation", str(e))

# Exit with appropriate code
if failures:
    sys.exit(1)
else:
    sys.exit(0)
