import requests
import json
import hashlib
import hmac
import base64
from datetime import datetime

# --- Configuration ---
OTX_API_KEY = "55bb174d9c701930c0f8f40f1c7e6dbb1f021a86a82e********************"
OTX_PULSE_ID = "682c98241f65c1**********"
otx_url = f"https://otx.alienvault.com/api/v1/pulses/{OTX_PULSE_ID}"

workspace_id = "97dd4e69-b6bb-4333-bc39-**********"
shared_key = "nEdGaI4Q+Yl9dM/jsV4bk6NGtdYfYopyRq8q4fGqAcTXrQMZDFFkCYLOgQ***************"
log_type = "OTX_IOCs"

# --- Fetch IOCs from OTX ---
headers = {"X-OTX-API-KEY": OTX_API_KEY}
response = requests.get(otx_url, headers=headers)
data = response.json()
indicators = data.get("indicators", [])

print(f"\nFetched {len(indicators)} indicators from OTX pulse '{OTX_PULSE_ID}'")

# --- Azure Signature Helper ---
def build_signature(date, content_length, method, content_type, resource):
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = string_to_hash.encode("utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, hashlib.sha256).digest()).decode()
    return f"SharedKey {workspace_id}:{encoded_hash}"

# --- Send to Sentinel ---
def post_data_to_sentinel(ioc):
    body = json.dumps(ioc)
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(rfc1123date, content_length, method, content_type, resource)

    uri = f"https://{workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
    headers = {
        "Content-Type": content_type,
        "Authorization": signature,
        "Log-Type": log_type,
        "x-ms-date": rfc1123date
    }

    response = requests.post(uri, data=body, headers=headers)
    if response.status_code in [200, 202]:
        print(f"✔️ Sent: {ioc['indicator']}")
    else:
        print(f"❌ Failed to send {ioc['indicator']}: {response.status_code} - {response.text}")

# --- Send each IOC ---
for ioc in indicators:
    post_data_to_sentinel(ioc)
