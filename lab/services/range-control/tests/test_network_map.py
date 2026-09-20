import importlib.util, pathlib

BASE = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("network", BASE / "network.py")
net = importlib.util.module_from_spec(spec); spec.loader.exec_module(net)

HOSTNAMES = {row[0] for row in net.NETWORK}
ZONES = {row[2] for row in net.NETWORK}


def test_network_lists_every_host():
    for h in ["web-prod-01", "mail-gateway-01", "vpn-corp-01", "proxy-01", "dc-01",
              "database-01", "fileserver-01", "backup-01", "workstation-finance-01",
              "workstation-finance-02", "workstation-hr-01", "workstation-it-01",
              "workstation-sales-01", "wazuh.manager"]:
        assert h in HOSTNAMES


def test_zones_are_the_expected_columns():
    assert "DMZ" in ZONES
    assert "Core servers" in ZONES
    assert "Endpoints" in ZONES
    assert "Security" in ZONES


def test_backup_and_mail_use_the_new_names_and_ips():
    rows = {row[0]: row for row in net.NETWORK}
    assert rows["backup-01"][1] == "10.20.10.40"
    assert rows["mail-gateway-01"][1] == "10.20.0.20"


def test_html_contains_every_host_and_its_ip():
    html = net.network_map_html(net.NETWORK, "10.9.9.9")
    for hostname, ip, zone, *_ in net.NETWORK:
        assert hostname in html
        # Endpoint workstations are grouped into one cluster node that shows the
        # subnet (10.20.20.0/24) rather than each individual IP.
        if zone != "Endpoints":
            assert ip in html


def test_column_labels_appear_in_the_map():
    html = net.network_map_html(net.NETWORK, "10.9.9.9")
    assert "DMZ" in html
    assert "Core" in html
    assert "Endpoints" in html


def test_dynamic_attacker_ip():
    html = net.network_map_html(net.NETWORK, "10.9.9.9")
    assert "10.9.9.9" in html
    assert "203.0.113" not in html


def test_svg_edge_layer_present():
    html = net.network_map_html(net.NETWORK, "10.9.9.9")
    assert "<svg" in html
    assert "<path" in html or "<line" in html


def test_no_copy_affordance():
    html = net.network_map_html(net.NETWORK, "10.9.9.9")
    assert "cp(event" not in html


def test_map_has_vertical_section_dividers():
    html = net.network_map_html(net.NETWORK, "10.9.9.9")
    # Four dashed column dividers plus the amber SIEM tap line = 5 dashed paths.
    assert html.count("stroke-dasharray") >= 5


def test_network_table_lists_every_host_and_ip():
    html = net.network_table_html(net.NETWORK)
    assert "<table" in html
    for hostname, ip, zone, *_ in net.NETWORK:
        assert hostname in html
        assert ip in html


def test_network_table_shows_every_zone():
    html = net.network_table_html(net.NETWORK)
    for zone in ZONES:
        assert zone in html


def test_html_never_reveals_the_build_detail():
    html = net.network_map_html(net.NETWORK, "10.9.9.9").lower()
    assert "paper" not in html
    assert "monitored" not in html
    assert "container" not in html
