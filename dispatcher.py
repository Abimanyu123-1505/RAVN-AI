import json
from datetime import datetime, timezone

def dispatch_alert(alert_id: str, website_id: str, website_name: str, severity: str, title: str, description: str, channel: str = "slack") -> None:
    print(f"\n[DISPATCHER] Dispatching {severity.upper()} alert for {website_name} via {channel}...")
    
    payload = {
        "text": f"*{severity.upper()} ALERT - {website_name}*",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Website:* {website_name}\n*Alert:* {title}\n*Details:* {description}"
                }
            }
        ]
    }
    
    # In a real application, we would use requests.post(WEBHOOK_URL, json=payload)
    print(f"[DISPATCHER] Simulated payload: {json.dumps(payload, indent=2)}")
    print("[DISPATCHER] Alert dispatched successfully.\n")
