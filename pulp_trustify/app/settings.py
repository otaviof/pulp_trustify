"""Plugin settings for pulp_trustify.

These settings are loaded via dynaconf overlay and can be overridden in
the Pulp settings.py or via environment variables (PULP_TRUSTIFY_URL, etc).
"""

TRUSTIFY_URL = ""
TRUSTIFY_API_VERSION = "v2"
TRUSTIFY_CLIENT_ID = "cli"
TRUSTIFY_CLIENT_SECRET = ""
TRUSTIFY_ISSUER_URL = ""
TRUSTIFY_CA_BUNDLE = ""
TRUSTIFY_SEVERITY_THRESHOLD = "critical"
TRUSTIFY_FAIL_OPEN = False
TRUSTIFY_GATE_UPLOADS = True
TRUSTIFY_SCAN_ENABLED = True
TRUSTIFY_BATCH_SIZE = 100
