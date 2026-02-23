"""
ZeroThreat Network Plugin: Memcached UDP Amplification Check
Drop any .py file in checks/network/ — it gets auto-loaded.
Each plugin must expose: run(open_ports, port_map) -> list[dict] | dict | None
"""

import socket, copy

FINDING = {
    "id":"PLG-NET-001","title":"Memcached UDP Amplification Risk",
    "severity":"HIGH","cvss_score":7.5,
    "description":"Memcached responding on UDP port 11211 can be abused for massive DDoS amplification attacks (up to 51,200x amplification factor). CVE-2018-1000115 affected millions of servers.",
    "affected":"Memcached UDP (Port 11211)",
    "recommendation":"Disable UDP support (--listen=127.0.0.1 --disable-udp). Firewall UDP 11211.",
    "cve_ids":["CVE-2018-1000115"],"cwe_ids":["CWE-400"],
    "confidence":"MEDIUM","evidence":"","evidence_detail":{},
    "adjusted_score":7.5,"internet_exposed":False,"auth_required":False,"pii_involved":False,
}

def run(open_ports, port_map):
    if 11211 not in port_map:
        return None
    # Try UDP probe
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        # Memcached stats request over UDP
        host = "127.0.0.1"
        payload = b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"
        s.sendto(payload, (host, 11211))
        data, _ = s.recvfrom(1024)
        s.close()
        if data:
            v = copy.deepcopy(FINDING)
            v["evidence"]        = f"Memcached UDP responded on port 11211. Response: {data[:80]}"
            v["confidence"]      = "HIGH"
            v["adjusted_score"]  = 8.5
            v["evidence_detail"] = {"check_id":"PLG-NET-001","endpoint":"udp://localhost:11211",
                                    "triggered_by":"UDP probe","confidence":"HIGH"}
            return v
    except:
        pass
    # Port is open TCP - flag as potential risk even without UDP confirmation
    v = copy.deepcopy(FINDING)
    v["evidence"] = "Memcached TCP port open. UDP amplification risk if UDP is also enabled."
    v["confidence"] = "LOW"
    v["adjusted_score"] = 6.0
    v["evidence_detail"] = {"check_id":"PLG-NET-001","endpoint":"tcp://localhost:11211",
                            "triggered_by":"Port detection","confidence":"LOW"}
    return v
