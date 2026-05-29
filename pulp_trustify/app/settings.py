"""Plugin settings for pulp_trustify.

Loaded via dynaconf overlay — every variable can be overridden
in the Pulp settings file or via ``PULP_<NAME>`` environment
variables on the pod (e.g. ``PULP_TRUSTIFY_URL``).

Connection
----------
TRUSTIFY_URL
    Base URL of the Trustify API (e.g.
    ``https://trustify.example.com``).  Empty disables all
    Trustify integration; the upload gate, download guard,
    and scanner become no-ops.
TRUSTIFY_API_VERSION
    Trustify REST API version path segment (default ``v2``).
TRUSTIFY_CLIENT_ID
    OIDC client ID used to authenticate with Trustify.
TRUSTIFY_CLIENT_SECRET
    OIDC client secret.  Leave empty when Trustify does not
    require authentication.
TRUSTIFY_ISSUER_URL
    Keycloak realm URL for OIDC token exchange.  When empty
    no ``Authorization`` header is sent.
TRUSTIFY_CA_BUNDLE
    Filesystem path to a PEM CA bundle for Trustify's TLS
    certificate.  Useful for internal CAs.

Detection
---------
TRUSTIFY_SEVERITY_THRESHOLD
    Minimum CVE severity that triggers blocking (``low``,
    ``medium``, ``high``, ``critical``).
TRUSTIFY_FAIL_OPEN
    When ``True``, allow operations if the Trustify API is
    unreachable.  When ``False`` (default), treat API errors
    as a hard block.

Protection layers
-----------------
TRUSTIFY_GATE_UPLOADS
    Block vulnerable packages at upload time via Django's
    ``pre_save`` signal on ``PythonPackageContent``.
TRUSTIFY_YANK_VULNERABLE
    Inject PEP 592 ``data-yanked`` attributes into the
    Simple API index so pip shows an inline warning before
    attempting the download.
TRUSTIFY_YANK_MAX_CVES
    Maximum number of CVE URLs to include in the yanked
    reason string shown by pip.  Each CVE is rendered as
    a clickable Trustify URL.

Scanner
-------
TRUSTIFY_SCAN_ENABLED
    Enable the ``POST /trustify/scan/`` endpoint.
TRUSTIFY_SCAN_REMOVE_CONTENT
    Create a new repository version excluding vulnerable
    content after a scan.
TRUSTIFY_SCAN_QUARANTINE_REPO
    Name prefix for typed quarantine repositories (e.g.
    ``quarantine`` creates ``quarantine-python``).  Empty
    disables quarantine.
TRUSTIFY_SCAN_LABEL_CONTENT
    Tag vulnerable content with ``trustify.*`` labels in
    ``pulp_labels``.
TRUSTIFY_SCAN_ADVISORY
    Record a ``ScanAdvisory`` per finding.
TRUSTIFY_BATCH_SIZE
    Number of PURLs sent per ``/analyze`` API call during
    scanning.

Observability
-------------
TRUSTIFY_LOG_LEVEL
    Python logging level for the ``pulp_trustify`` logger
    (``DEBUG``, ``INFO``, ``WARNING``, …).
TRUSTIFY_ENRICH_DETAILS
    Include Trustify vulnerability URLs in error messages,
    logs, and advisory records.

Middleware
----------
MIDDLEWARE
    Appended to Django's middleware stack via dynaconf merge.
    Registers ``YankMiddleware`` for PEP 592 injection.
"""

dynaconf_merge = True

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
TRUSTIFY_SCAN_REMOVE_CONTENT = True
TRUSTIFY_SCAN_QUARANTINE_REPO = ""
TRUSTIFY_SCAN_LABEL_CONTENT = True
TRUSTIFY_SCAN_ADVISORY = True
TRUSTIFY_BATCH_SIZE = 100
TRUSTIFY_LOG_LEVEL = "INFO"
TRUSTIFY_ENRICH_DETAILS = True
TRUSTIFY_YANK_VULNERABLE = True
TRUSTIFY_YANK_MAX_CVES = 3

MIDDLEWARE = ["pulp_trustify.yank.YankMiddleware"]

LOGGING = {
    "dynaconf_merge": True,
    "loggers": {
        "pulp_trustify": {
            "handlers": ["console"],
            "level": "@format {this.TRUSTIFY_LOG_LEVEL}",
        },
    },
}
