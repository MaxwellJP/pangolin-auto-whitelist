import os
import sys
import json
import requests
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

print(f"[INFO] [{datetime.now(timezone.utc).isoformat()}] Script started", file=sys.stderr)

# ─── Configuration ──────────────────────────────────────────────────────────────

load_dotenv()
PANGOLIN_API_URL   = os.getenv('API_URL')
PANGOLIN_API_TOKEN = os.getenv('API_KEY')
RESOURCE_ID        = "1"
LOG_FILE           = os.getenv('LOG_PATH')
STATE_FILE         = os.getenv('STATE_PATH')
TTL_MINUTES        = 360

if not all([PANGOLIN_API_URL, PANGOLIN_API_TOKEN, RESOURCE_ID, LOG_FILE, STATE_FILE]):
    print("[ERROR] One or more required environment variables are missing.", file=sys.stderr)
    print("[ERROR] Required: PANGOLIN_API_URL, PANGOLIN_API_TOKEN, RESOURCE_ID, LOG_FILE, STATE_FILE", file=sys.stderr)
    sys.exit(1)

HEADERS = {
    "Authorization": f"Bearer {PANGOLIN_API_TOKEN}",
    "Content-Type": "application/json",
}

# ─── Helper Functions ────────────────────────────────────────────────────────────

def load_state(path):

    default = {"last_position": 0, "rules": {}}

    try:
        with open(path, "r") as f:
            data = json.load(f)
            if "last_position" in data and "rules" in data:
                return data

    except (FileNotFoundError, json.JSONDecodeError):
        pass

    return default

def save_state(path, state):

    print(f"[INFO] Saving state to {path}", file=sys.stderr)
    print(f"[INFO] State content: {json.dumps(state, indent=2)}", file=sys.stderr)
    
    tmp_path = f"{path}.tmp"

    with open(tmp_path, "w") as f:
        json.dump(state, f, indent=2)

    os.replace(tmp_path, path)
    print(f"[INFO] State saved successfully", file=sys.stderr)

def parse_log_line(line):

    try:
        return json.loads(line)
    
    except json.JSONDecodeError:
        return None

def extract_login_ip(line):

    if "Exchange session: Badger sent " not in line:
        return None

    # Extract the JSON substring.
    try:
        json_part = line[line.index("{") : line.rindex("}") + 1]
        payload = json.loads(json_part)
        ip_port = payload.get("requestIp", "")
        ip = ip_port.split(":")[0]

        # Basic sanity check: must contain at least one dot
        if ip and "." in ip:
            return ip
        
    except (ValueError, json.JSONDecodeError):
        pass

    return None

def create_rule(ip):

    url = f"{PANGOLIN_API_URL}/resource/{RESOURCE_ID}/rule"
    body = {
        "action": "ACCEPT",
        "match": "IP",
        "value": f"{ip}",
        "priority": 0,
        "enabled": True
    }
    
    try:
        print(f"[INFO] Creating rule for IP: {ip}", file=sys.stderr)
        print(f"[INFO] API URL: {url}", file=sys.stderr)
        print(f"[INFO] Request Body: {json.dumps(body)}", file=sys.stderr)
        
        resp = requests.put(url, headers=HEADERS, json=body, timeout=10)
        
        print(f"[INFO] Response Status: {resp.status_code}", file=sys.stderr)
        print(f"[INFO] Response Text: {resp.text}", file=sys.stderr)
        
        if resp.status_code in (200, 201):
            data = resp.json()
            rule_id = data.get('data', {}).get('ruleId')
            
            if not rule_id:
                rule_id = data.get('id')
                
            if rule_id:
                return str(rule_id)
            
            print(f"[ERROR] Rule created but no ID found in response: {data}", file=sys.stderr)
            return None
            
        print(f"[ERROR] Rule creation failed for {ip}: {resp.status_code} {resp.text}", file=sys.stderr)
        return None

    except Exception as e:
        print(f"[ERROR] API call failed for {ip}: {str(e)}", file=sys.stderr)
        return None

def delete_rule(rule_id):

    url = f"{PANGOLIN_API_URL}/resource/{RESOURCE_ID}/rule/{rule_id}"
    resp = requests.delete(url, headers=HEADERS, timeout=10)

    if resp.status_code in (200, 204):
        print(f"[INFO] Deleting expired rule {rule_id}: {resp.status_code} {resp.text}", file=sys.stderr)
        return True
    
    else:
        print(f"[ERROR] Failed to delete rule {rule_id}: {resp.status_code} {resp.text}", file=sys.stderr)
        return False

# ─── Main Logic ─────────────────────────────────────────────────────────────────

def main():

    state = load_state(STATE_FILE)
    last_position = state.get("last_position", 0)
    active_rules = state.get("rules", {})
    now = datetime.now(timezone.utc)

    # Check if log was rotated (file size < last_position)
    try:
        current_size = os.path.getsize(LOG_FILE)

    except FileNotFoundError:
        print(f"[ERROR] [{now.isoformat()}] Log file not found: {LOG_FILE}", file=sys.stderr)
        sys.exit(1)

    if current_size < last_position:
        print(f"[INFO] [{now.isoformat()}] Log rotation detected: resetting offset from {last_position} to 0", file=sys.stderr)
        last_position = 0
        state["last_position"] = 0

    # Prune expired rules
    updated_rules = {}
    for ip, info in active_rules.items():
        expires_at = datetime.fromisoformat(info["expires_at"])
        rule_id = info["rule_id"]

        if now >= expires_at:
            success = delete_rule(rule_id)

            if not success:
                updated_rules[ip] = info
        else:
            updated_rules[ip] = info

    # Replace active_rules with the pruned set
    active_rules = updated_rules

    try:
        f = open(LOG_FILE, "r", encoding="utf-8")

    except FileNotFoundError:
        print(f"[ERROR] [{now.isoformat()}] Log file not found: {LOG_FILE}", file=sys.stderr)
        sys.exit(1)

    f.seek(last_position)
    new_position = last_position

    for line in f:
        new_position += len(line.encode("utf-8"))
        ip = extract_login_ip(line)

        if ip:
            if ip not in active_rules:
                print(f"[INFO] [{now.isoformat()}] Detected login from IP {ip}", file=sys.stderr)
                rule_id = create_rule(ip)

                if rule_id:
                    exp_time = (datetime.now(timezone.utc) + timedelta(minutes=TTL_MINUTES)).isoformat()
                    active_rules[ip] = {"rule_id": rule_id, "expires_at": exp_time}
                    print(f"[INFO] [{now.isoformat()}] Created rule {rule_id} for {ip}, expires at {exp_time}", file=sys.stderr)

                else:
                    print(f"[ERROR] [{now.isoformat()}] Failed to create rule for {ip}", file=sys.stderr)
            else:
                pass

    f.close()

    state["last_position"] = new_position
    state["rules"] = active_rules
    save_state(STATE_FILE, state)

    print(f"[INFO] [{now.isoformat()}] Script completed. Rules active: {len(active_rules)}", file=sys.stderr)

if __name__ == "__main__":
    main()
