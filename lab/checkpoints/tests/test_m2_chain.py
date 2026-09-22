"""Structural checks for the Module 2 checkpoint workflow JSON.

The tests read the workflow file as data. They catch broken node wiring,
dangling $('...') references, and drifted field expressions before an
import into n8n would.
"""
import json
import re
from pathlib import Path

import pytest

WF_PATH = Path(__file__).resolve().parents[1] / "module-2" / "triage-m2-chain.json"


@pytest.fixture(scope="module")
def wf():
    return json.loads(WF_PATH.read_text())


def node(wf, name):
    matches = [n for n in wf["nodes"] if n["name"] == name]
    assert matches, f"node {name!r} not found"
    return matches[0]


def assignment(wf, node_name, field):
    n = node(wf, node_name)
    for a in n["parameters"]["assignments"]["assignments"]:
        if a["name"] == field:
            return a["value"]
    raise AssertionError(f"assignment {field!r} not found on {node_name!r}")


def targets(wf, source, conn_type="main", output_index=0):
    conns = wf["connections"].get(source, {}).get(conn_type, [])
    if len(conns) <= output_index or conns[output_index] is None:
        return []
    return [(c["node"], c.get("index", 0)) for c in conns[output_index]]


def test_connections_reference_existing_nodes(wf):
    names = {n["name"] for n in wf["nodes"]}
    for source, types in wf["connections"].items():
        assert source in names, f"connection source {source!r} is not a node"
        for conn_type, outputs in types.items():
            for output in outputs:
                for target in output or []:
                    assert target["node"] in names, (
                        f"{source} -> {target['node']} ({conn_type}) targets a missing node")


def test_expression_references_resolve(wf):
    names = {n["name"] for n in wf["nodes"]}
    blob = json.dumps(wf)
    for ref in set(re.findall(r"\$\('([^']+)'\)", blob)):
        assert ref in names, f"$('{ref}') references a missing node"


def test_hash_field_extracted(wf):
    value = assignment(wf, "Extract case", "hash")
    assert "has sha256" in value
    assert "[0-9a-f]{64}" in value
    assert "/has sha256 `([0-9a-f]{64})`/" in value


def test_domain_field_falls_back_to_url_host(wf):
    value = assignment(wf, "Extract case", "domain")
    assert "host=" in value
    assert "https?" in value


def test_wazuh_fans_out_to_indicator_gates(wf):
    t = [name for name, _ in targets(wf, "Enrich: Wazuh")]
    for gate in ("IP present?", "Hash present?", "Domain present?"):
        assert gate in t, f"{gate} not fed from Enrich: Wazuh"


def test_indicator_gates_test_the_extracted_field(wf):
    for gate, field in (("IP present?", "srcip"), ("Hash present?", "hash"),
                        ("Domain present?", "domain")):
        cond = node(wf, gate)["parameters"]["conditions"]["conditions"][0]
        assert f"$('Extract case').first().json.{field}" in cond["leftValue"]
        assert cond["operator"]["operation"] == "notEmpty"


def test_lookups_survive_api_failure(wf):
    for name in ("Lookup IP: AbuseIPDB", "Lookup hash: VirusTotal",
                 "Lookup domain: ThreatFox"):
        n = node(wf, name)
        assert n.get("onError") == "continueRegularOutput", name
        assert n.get("alwaysOutputData") is True, name


def test_lookups_use_the_right_service_and_key(wf):
    checks = (
        ("Lookup IP: AbuseIPDB", "api.abuseipdb.com", "ABUSEIPDB_API_KEY"),
        ("Lookup hash: VirusTotal", "www.virustotal.com/api/v3/files", "VT_API_KEY"),
        ("Lookup domain: ThreatFox", "threatfox-api.abuse.ch", "ABUSECH_AUTH_KEY"),
    )
    for name, host, key in checks:
        blob = json.dumps(node(wf, name)["parameters"])
        assert host in blob, name
        assert key in blob, name


def test_gate_false_paths_emit_not_present(wf):
    for gate, setter, itype in (("IP present?", "IP not present", "ip"),
                                ("Hash present?", "Hash not present", "hash"),
                                ("Domain present?", "Domain not present", "domain")):
        assert targets(wf, gate, output_index=1) == [(setter, 0)]
        value = assignment(wf, setter, "output")
        assert "'not present'" in value
        assert f"'{itype}'" in value


def test_gate_true_paths_reach_the_lookups(wf):
    for gate, lookup in (("IP present?", "Lookup IP: AbuseIPDB"),
                         ("Hash present?", "Lookup hash: VirusTotal"),
                         ("Domain present?", "Lookup domain: ThreatFox")):
        assert targets(wf, gate, output_index=0) == [(lookup, 0)]


def test_lookups_feed_the_mini_chains(wf):
    for lookup, chain in (("Lookup IP: AbuseIPDB", "IP verdict"),
                          ("Lookup hash: VirusTotal", "Hash verdict"),
                          ("Lookup domain: ThreatFox", "Domain verdict")):
        assert targets(wf, lookup) == [(chain, 0)]


def test_mini_chains_are_parsed_llm_chains(wf):
    for name in ("IP verdict", "Hash verdict", "Domain verdict"):
        n = node(wf, name)
        assert n["type"] == "@n8n/n8n-nodes-langchain.chainLlm", name
        assert n["parameters"]["hasOutputParser"] is True, name


def test_one_model_node_feeds_all_four_chains(wf):
    fed = {name for name, _ in targets(wf, "OpenAI Chat Model", "ai_languageModel")}
    assert fed == {"IP verdict", "Hash verdict", "Domain verdict", "Triage (LLM chain)"}
    models = [n for n in wf["nodes"] if n["type"] == "@n8n/n8n-nodes-langchain.lmChatOpenAi"]
    assert len(models) == 1


def test_shared_parser_feeds_the_mini_chains(wf):
    fed = {name for name, _ in targets(wf, "Mini-verdict parser", "ai_outputParser")}
    assert fed == {"IP verdict", "Hash verdict", "Domain verdict"}
    schema = node(wf, "Mini-verdict parser")["parameters"]["inputSchema"]
    for field in ("indicator_type", "indicator", "verdict", "evidence"):
        assert field in schema
    assert "malicious" in schema and "clean" in schema and "unknown" in schema


def test_verdicts_and_skips_converge_on_the_merge(wf):
    pairs = ((("IP verdict", "IP not present"), 0),
             (("Hash verdict", "Hash not present"), 1),
             (("Domain verdict", "Domain not present"), 2))
    for (chain, setter), merge_input in pairs:
        assert targets(wf, chain) == [("Merge verdicts", merge_input)]
        assert targets(wf, setter) == [("Merge verdicts", merge_input)]


def test_merge_has_three_inputs_and_feeds_collect(wf):
    n = node(wf, "Merge verdicts")
    assert n["type"] == "n8n-nodes-base.merge"
    assert n["parameters"]["numberInputs"] == 3
    assert targets(wf, "Merge verdicts") == [("Collect verdicts", 0)]


def test_no_code_nodes_anywhere(wf):
    code_nodes = [n["name"] for n in wf["nodes"] if n["type"] == "n8n-nodes-base.code"]
    assert code_nodes == [], f"workflow must stay low-code, found Code nodes: {code_nodes}"


def test_collect_aggregates_the_three_verdicts(wf):
    n = node(wf, "Collect verdicts")
    assert n["type"] == "n8n-nodes-base.aggregate"
    agg = n["parameters"]["fieldsToAggregate"]["fieldToAggregate"][0]
    assert agg["fieldToAggregate"] == "output"
    assert agg["outputFieldName"] == "indicatorVerdicts"
    assert targets(wf, "Collect verdicts") == [("Assemble verdicts", 0)]


def test_assemble_builds_the_gather_document(wf):
    n = node(wf, "Assemble verdicts")
    assert n["type"] == "n8n-nodes-base.set"
    fields = {a["name"]: a["value"] for a in n["parameters"]["assignments"]["assignments"]}
    assert set(fields) == {"caseId", "case", "wazuhEvents", "indicatorVerdicts"}
    assert "$('Extract case')" in fields["caseId"]
    assert "descriptionForModel" in fields["case"]
    assert "hash" in fields["case"]
    assert "_source" in fields["wazuhEvents"]
    assert targets(wf, "Assemble verdicts") == [("Triage (LLM chain)", 0)]


def test_old_single_lookup_path_is_gone(wf):
    names = {n["name"] for n in wf["nodes"]}
    assert "Enrich: reputation" not in names
    assert "Assemble context" not in names


def test_gather_prompt_covers_indicator_verdicts(wf):
    msg = node(wf, "Triage (LLM chain)")["parameters"]["messages"]["messageValues"][0]["message"]
    assert "indicator verdicts" in msg.lower()
    assert "indicatorVerdicts" in msg


def test_render_comment_is_plain_text(wf):
    value = assignment(wf, "Render verdict", "comment")
    for token in ("###", "**", "|---|", "| Type |", "`"):
        assert token not in value, f"comment must be plain text, found {token!r}"
    assert "Indicator verdicts" in value
    assert "Suggested close state" in value
    assert "$('Assemble verdicts')" in value


def test_render_description_appends_the_markdown_table(wf):
    value = assignment(wf, "Render verdict", "description")
    assert "$('Webhook')" in value, "must start from the original case description"
    assert "### Indicator verdicts" in value
    assert "| Type | Indicator | Verdict | Evidence |" in value
    assert "chain per indicator" in value
    assert value.index("### Indicator verdicts") < value.index("### Summary")


def test_render_fans_out_to_both_writebacks(wf):
    fed = {name for name, _ in targets(wf, "Render verdict")}
    assert fed == {"Write verdict to TheHive", "Update case description"}


def test_comment_write_posts_the_plain_text(wf):
    n = node(wf, "Write verdict to TheHive")
    assert n["parameters"]["method"] == "POST"
    assert "/comment" in n["parameters"]["url"]
    assert "$json.comment" in n["parameters"]["jsonBody"]


def test_description_write_patches_the_case(wf):
    n = node(wf, "Update case description")
    assert n["parameters"]["method"] == "PATCH"
    assert "/api/v1/case/" in n["parameters"]["url"]
    assert "/comment" not in n["parameters"]["url"]
    assert "$json.description" in n["parameters"]["jsonBody"]
    assert n["credentials"]["httpHeaderAuth"]["id"] == "credTheHiveN8n01"


def test_filter_matches_thehive_payload(wf):
    conds = node(wf, "Case created only")["parameters"]["conditions"]["conditions"]
    by_left = {c["leftValue"]: c for c in conds}
    ot = by_left["={{ $json.body.objectType }}"]
    assert ot["rightValue"] == "case"
    op = by_left["={{ $json.body.operation }}"]
    assert op["rightValue"] == "Creation"
