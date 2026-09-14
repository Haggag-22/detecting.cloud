"""
Lambda Internet Egress to Unapproved or Suspicious Destination
Trigger: VPC Flow Logs delivered to a Lambda analytics pipeline.
Use for: Stateful or streaming analytics over Lambda-attributed egress traffic.
"""

PRIVATE_PREFIXES = ("10.", "192.168.")
SUSPICIOUS_PORTS = {4444, 8080, 8443}

def lambda_handler(event, context):
    record = event.get("detail", event)
    interface_id = record.get("interfaceId", "")
    dst_addr = record.get("dstAddr", "")
    dst_port = int(record.get("dstPort", 0) or 0)
    bytes_sent = int(record.get("bytes", 0) or 0)

    if record.get("action") != "ACCEPT" or record.get("flowDirection") != "egress":
        return {"matched": False}
    if not interface_id.startswith("eni-"):
        return {"matched": False}
    if dst_addr.startswith(PRIVATE_PREFIXES) or dst_addr.startswith("172.16."):
        return {"matched": False}
    if dst_port not in SUSPICIOUS_PORTS and bytes_sent <= 10485760:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-005",
            "title": "Lambda Internet Egress to Unapproved or Suspicious Destination",
            "severity": "High",
            "interface_id": interface_id,
            "destination_ip": dst_addr,
            "destination_port": dst_port,
            "bytes": bytes_sent,
        },
    }
