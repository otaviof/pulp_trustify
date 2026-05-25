"""Plugin settings for pulp_trustify.

These settings are loaded via dynaconf overlay and can be overridden in
the Pulp settings.py or via environment variables (PULP_TRUSTIFY_URL, etc).
"""

TRUSTIFY_URL = ""
TRUSTIFY_SEVERITY_THRESHOLD = "critical"
TRUSTIFY_FAIL_OPEN = False
