"""
Orphaned Origin on Sensitive or Public Distribution
Trigger: Scheduled posture or inventory prioritization workflow.
Use for: Elevating orphaned-origin findings on critical distributions.
"""

def lambda_handler(event, context):
    return {
        "matched": "requires-orphaned-origin-plus-distribution-criticality-check",
        "alert": {
            "rule_id": "det-138",
            "title": "Orphaned Origin on Sensitive or Public Distribution",
            "severity": "Critical",
        },
    }
