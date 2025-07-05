# Pangolin Auto-Whitelist

A simple Python script that monitors Pangolin logs and automatically whitelists IP addresses after successful authentication. This serves as a workaround for devices that cannot handle Pangolin's authentication redirect, such as many TVs.

It allows the user to authenticate on any device and temporarily grant network-wide access for other devices on the same IP.

---

## 📦 Features

- Dynamically creates temporary `ACCEPT` rules via the Pangolin API
- Automatically deletes expired rules after a configurable TTL
- Maintains state between runs to avoid duplication
- Resilient to log rotation

---

## 🔧 Requirements

- Python 3.7+
- Pangolin 1.4.0+
- A Pangolin API key with resource rule permissions
- A `.env` file with your configuration (see below)
- A `.json` file to track log position and IP rules (see auth-state.json)

API_URL=http://your-pangolin-domain/v1

API_KEY=your_api_token

LOG_PATH=/path/to/your/logfile.log

STATE_PATH=/path/to/store/script_state.json

---

## 💡 Current Issues / Ideas

- Currently can only manage the rules of a single, predefined resource in Pangolin.
- Cannot parse _which_ resource the user authenticated on, which may give undesired access.
- Designed to run with time-based scheduling, like cron. This results in a delay from successful authentication to full access depending on how often the script is scheduled.
- End users with CGNAT would pose security concerns, although any real risk is likely minimal.
