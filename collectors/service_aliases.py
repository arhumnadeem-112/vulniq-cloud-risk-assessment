"""
service_aliases.py
------------------
Vendor/package alias configuration for multi-source collectors.

Each entry maps a canonical service name to:
  nvd_keywords   -- list of NVD keyword searches; all results stored under the
                    canonical service_name (covers subsidiaries / product lines)
  kev_vendors    -- list of vendorProject/product substrings to match in CISA KEV
  packages       -- {ecosystem: [package_names]} for GHSA/OSV package-registry lookup
  status_url     -- root URL passed to the status collector (Statuspage.io-compatible
                    or provider-specific)
  status_provider -- named provider shorthand for built-in handlers
                     (aws | azure | gcp | salesforce)

For services not listed here every collector falls back to its original behaviour
(treat service_name as the sole vendor / package name).
"""

from __future__ import annotations

SERVICE_ALIASES: dict[str, dict] = {
    "salesforce": {
        # NVD keyword searches — all results stored under service_name="salesforce".
        # Tableau alone contributed 30-50 CVEs per 6-month period historically;
        # MuleSoft/Heroku add a further handful each window.
        "nvd_keywords": [
            "salesforce",
            "tableau",
            "mulesoft",
            "heroku",
            "slack technologies",  # more specific than "slack" to avoid false positives
        ],
        # KEV catalog vendorProject / product substrings (case-insensitive)
        # Covers the Salesforce family: core platform + major acquisitions
        "kev_vendors": [
            "salesforce",
            "heroku",
            "mulesoft",
            "tableau",
            "slack technologies",
            "slack",
            "exacttarget",
            "demandware",
        ],
        # Known open-source packages that ship Salesforce platform code or SDKs.
        # Vulnerabilities here surface platform-level issues (SOQL injection, auth
        # flaws in SDK, XSS in embedded components) that affect Salesforce deployments.
        "packages": {
            "PyPI": [
                "simple-salesforce",   # most widely used Salesforce Python SDK
                "salesforce-bulk",     # bulk-API client; common ETL attack surface
                "aiosfstream",         # async streaming; CVE history for authn bypass
                "salesforce-bulk2",
                "pysftp",
            ],
            "npm": [
                "jsforce",                       # dominant Node.js Salesforce SDK
                "@salesforce/core",              # Salesforce CLI core; wide install base
                "@salesforce/sf-plugins-core",
                "nforce",
                "node-salesforce",
            ],
        },
        "status_url": "https://api.status.salesforce.com/v1",
        "status_provider": "salesforce",
        "github_repos": [
            "forcedotcom/salesforcedx-vscode",
            "salesforce/cli",
            "simple-salesforce/simple-salesforce",
        ],
    },
    "stripe": {
        "kev_vendors": ["stripe"],
        "packages": {
            "PyPI": ["stripe"],
            "npm": ["stripe"],
        },
        "status_url": "https://status.stripe.com",
        "github_repos": [
            "stripe/stripe-python",
            "stripe/stripe-node",
        ],
    },
    "aws": {
        "nvd_keywords": ["amazon web services", "aws", "amazon ec2", "amazon s3",
                         "amazon lambda", "amazon rds"],
        "kev_vendors": ["amazon", "aws", "amazon web services"],
        "packages": {},
        "status_provider": "aws",
        "github_repos": [
            "aws/aws-cli",
            "boto/boto3",
        ],
    },
    "azure": {
        "nvd_keywords": ["microsoft azure", "azure active directory", "azure devops",
                         "azure kubernetes"],
        "kev_vendors": ["microsoft", "azure"],
        "packages": {},
        "status_provider": "azure",
        "github_repos": [
            "Azure/azure-cli",
            "Azure/azure-sdk-for-python",
        ],
    },
    "gcp": {
        "nvd_keywords": ["google cloud", "google kubernetes engine", "google cloud run"],
        "kev_vendors": ["google", "gcp", "google cloud"],
        "packages": {},
        "status_provider": "gcp",
        "github_repos": [
            "googleapis/google-cloud-python",
            "GoogleCloudPlatform/functions-framework-python",
        ],
    },
    "github": {
        "kev_vendors": ["github", "microsoft"],
        "packages": {},
        "status_url": "https://githubstatus.com",
        "github_repos": [
            "cli/cli",
            "github/codeql-action",
        ],
    },
    "okta": {
        "kev_vendors": ["okta", "auth0"],
        "packages": {
            "PyPI": ["okta"],
            "npm": ["@okta/okta-sdk-nodejs", "@okta/okta-auth-js"],
        },
        "status_url": "https://status.okta.com",
        "github_repos": [
            "okta/okta-sdk-python",
            "okta/okta-auth-js",
        ],
    },
    "twilio": {
        "kev_vendors": ["twilio", "sendgrid"],
        "packages": {
            "PyPI": ["twilio"],
            "npm": ["twilio"],
        },
        "status_url": "https://status.twilio.com",
        "github_repos": [
            "twilio/twilio-python",
            "twilio/twilio-node",
        ],
    },

    # ── Enterprise & Operations (ERP/HR) ──────────────────────────────────────

    "workday": {
        "nvd_keywords": [
            "workday",
            "adaptive insights",  # acquired 2018; planning/analytics subsidiary
            "peakon",             # acquired 2021; employee engagement
        ],
        "kev_vendors": [
            "workday",
            "adaptive insights",
        ],
        "packages": {
            "PyPI": [
                "workday",         # unofficial community SDK
                "prism-python",    # Workday Prism Analytics API client
            ],
            "npm": [
                "workday-prism",
            ],
        },
        "status_url": "https://status.workday.com",
        "github_repos": [],
    },

    "servicenow": {
        "nvd_keywords": [
            "servicenow",
        ],
        "kev_vendors": [
            "servicenow",
        ],
        "packages": {
            "PyPI": [
                "pysnow",             # dominant ServiceNow Python client
                "python-servicenow",
            ],
            "npm": [
                "@servicenow/cli-profile-middleware",
                "sn-client",
            ],
        },
        "status_url": "https://status.servicenow.com",
        "github_repos": [
            "ServiceNow/servicenow-sdk-python",
        ],
    },

    "deel": {
        "nvd_keywords": [
            "deel",
        ],
        "kev_vendors": [
            "deel",
        ],
        # Deel does not publish prominent open-source SDKs; revisit as ecosystem matures
        "packages": {
            "PyPI": [],
            "npm": [],
        },
        "status_url": "https://status.deel.com",
        "github_repos": [],
    },

    # ── Sales & Marketing (CRM) ───────────────────────────────────────────────

    "hubspot": {
        "nvd_keywords": [
            "hubspot",
        ],
        "kev_vendors": [
            "hubspot",
        ],
        "packages": {
            "PyPI": [
                "hubspot-api-client",  # official HubSpot Python SDK
                "hubspot3",            # widely-used community client
            ],
            "npm": [
                "@hubspot/api-client",  # official HubSpot Node.js SDK
            ],
        },
        "status_url": "https://status.hubspot.com",
        "github_repos": [
            "HubSpot/hubspot-api-client-python",
            "HubSpot/hubspot-api-client-nodejs",
        ],
    },

    # ── Data, Analytics & Security ────────────────────────────────────────────

    "snowflake": {
        "nvd_keywords": [
            "snowflake",
            "streamlit",  # acquired 2022; open-source data app framework
        ],
        "kev_vendors": [
            "snowflake",
            "streamlit",
        ],
        "packages": {
            "PyPI": [
                "snowflake-connector-python",  # official Snowflake Python connector
                "snowflake-sqlalchemy",        # SQLAlchemy dialect; wide ORM attack surface
                "snowflake-ml-python",         # ML/AI feature store SDK
                "snowflake-cli-labs",          # CLI tooling
                "streamlit",                   # Snowflake-owned; broad install base
            ],
            "npm": [
                "snowflake-sdk",               # official Node.js driver
            ],
        },
        "status_url": "https://status.snowflake.com",
        "github_repos": [
            "snowflakedb/snowflake-connector-python",
            "snowflakedb/snowflake-sqlalchemy",
        ],
    },

    "datadog": {
        "nvd_keywords": [
            "datadog",
            "sqreen",    # acquired 2021; RASP/AppSec library
        ],
        "kev_vendors": [
            "datadog",
            "sqreen",
        ],
        "packages": {
            "PyPI": [
                "datadog",             # official Datadog Python SDK
                "datadog-api-client",  # OpenAPI-generated API client
                "ddtrace",             # APM/distributed tracing agent; high-privilege process
            ],
            "npm": [
                "dd-trace",            # Node.js APM agent; high-privilege process
                "datadog-metrics",     # metrics client
            ],
        },
        "status_url": "https://status.datadoghq.com",
        "github_repos": [
            "DataDog/dd-trace-py",
            "DataDog/datadog-agent",
        ],
    },

    # ── Cloud & Infrastructure (Big Tech OSS) ─────────────────────────────────
    # Note: "aws", "azure", "gcp" entries above cover cloud-infra CVEs.
    # These entries target each company's broader open-source portfolio.

    "google": {
        "nvd_keywords": [
            "google",
            "chromium",          # browser engine; historically high CVE volume
            "kubernetes",        # originated at Google; enormous attack surface
            "tensorflow",        # ML framework; supply-chain target
            "grpc",              # RPC framework; wide enterprise adoption
            "golang",            # Go language runtime
        ],
        "kev_vendors": [
            "google",
            "chromium",
            "kubernetes",
        ],
        "packages": {
            "PyPI": [
                "kubernetes",          # official Python k8s client
                "tensorflow",          # ML framework; pip install base > 200M/month
                "grpcio",              # gRPC Python runtime
                "google-auth",         # OAuth2/OIDC library; auth flaw surface
                "google-cloud-core",
            ],
            "npm": [
                "@kubernetes/client-node",
                "@grpc/grpc-js",       # pure-JS gRPC; replaces grpc native module
                "firebase",            # Firebase JS SDK
            ],
        },
        "status_url": "https://status.cloud.google.com",
        "status_provider": "gcp",
        "github_repos": [
            "kubernetes/kubernetes",
            "tensorflow/tensorflow",
        ],
    },

    "microsoft": {
        "nvd_keywords": [
            "microsoft",
            "visual studio code",   # most-installed editor; extension attack surface
            "typescript",
            "powershell",
            "dotnet",
            ".net",
            "playwright",
        ],
        "kev_vendors": [
            "microsoft",
            "visual studio",
            "powershell",
        ],
        "packages": {
            "PyPI": [
                "playwright",          # browser automation; high-privilege process
                "azure-identity",      # MSAL-based credential library
                "pyright",             # Python type checker from Microsoft
            ],
            "npm": [
                "typescript",          # compiler; wide transitive install base
                "@playwright/test",
                "@microsoft/signalr",  # real-time web library
            ],
        },
        "status_provider": "azure",
        "status_url": "https://status.azure.com",
        "github_repos": [
            "microsoft/TypeScript",
            "microsoft/vscode",
            "microsoft/playwright",
        ],
    },

    "amazon": {
        "nvd_keywords": [
            "amazon",
            "opensearch",        # AWS-managed Elasticsearch fork
            "firecracker",       # microVM; Lambda/Fargate isolation layer
            "aws cdk",
            "bottlerocket",      # container-optimised Linux
        ],
        "kev_vendors": [
            "amazon",
            "aws",
            "opensearch",
        ],
        "packages": {
            "PyPI": [
                "opensearch-py",       # official OpenSearch Python client
                "aws-cdk-lib",         # CDK infrastructure-as-code
                "boto3",               # AWS SDK; most-used Python cloud library
                "botocore",
            ],
            "npm": [
                "aws-cdk",
                "opensearch-js",       # official OpenSearch JS client
                "@aws-sdk/client-s3",  # modular AWS SDK v3
            ],
        },
        "status_provider": "aws",
        "github_repos": [
            "opensearch-project/OpenSearch",
            "aws/aws-cdk",
        ],
    },

    "meta": {
        "nvd_keywords": [
            "meta",
            "facebook",
            "react",             # dominant UI framework; XSS/prototype-pollution history
            "pytorch",           # ML framework; supply-chain target
            "rocksdb",           # embedded KV store; used in many OSS databases
        ],
        "kev_vendors": [
            "facebook",
            "meta",
        ],
        "packages": {
            "PyPI": [
                "torch",               # PyTorch; massive install base
                "torchvision",
                "cassandra-driver",    # Meta-originated; used in Cassandra deployments
            ],
            "npm": [
                "react",               # top-5 most downloaded npm package globally
                "react-dom",
                "react-native",
                "jest",                # test runner originated at Meta
            ],
        },
        "status_url": "https://metastatus.com",
        "github_repos": [
            "facebook/react",
            "pytorch/pytorch",
        ],
    },

    "ibm": {
        "nvd_keywords": [
            "ibm",
            "red hat",           # acquired 2019; RHEL/OpenShift CVE volume is high
            "openshift",
            "websphere",
            "db2",
        ],
        "kev_vendors": [
            "ibm",
            "red hat",
            "redhat",
            "websphere",
            "db2",
        ],
        "packages": {
            "PyPI": [
                "ibm-watson",
                "ibm-cloud-sdk-core",
                "openshift",           # OpenShift Python client
            ],
            "npm": [
                "ibm-watson",
                "@ibm-cloud/openapi-validator",
            ],
        },
        "status_url": "https://status.ibm.com",
        "github_repos": [
            "IBM/ibm-watson-sdk-core",
        ],
    },

    # ── Security & Observability ──────────────────────────────────────────────

    "cloudflare": {
        "nvd_keywords": [
            "cloudflare",
        ],
        "kev_vendors": [
            "cloudflare",
        ],
        "packages": {
            "PyPI": [
                "cloudflare",          # official Cloudflare Python SDK
            ],
            "npm": [
                "wrangler",            # Workers CLI; developer attack surface
                "@cloudflare/workers-types",
            ],
        },
        "status_url": "https://www.cloudflarestatus.com",
        "github_repos": [
            "cloudflare/cloudflare-python",
            "cloudflare/workers-sdk",
        ],
    },

    "elastic": {
        "nvd_keywords": [
            "elastic",
            "elasticsearch",    # frequently in KEV; RCE/auth-bypass CVEs historically
            "kibana",           # XSS/SSRF CVEs historically
            "logstash",
        ],
        "kev_vendors": [
            "elastic",
            "elasticsearch",
            "kibana",
        ],
        "packages": {
            "PyPI": [
                "elasticsearch",       # official Python client
                "elastic-apm",         # APM agent; high-privilege process
                "ecs-logging",
            ],
            "npm": [
                "@elastic/elasticsearch",
                "@elastic/apm-agent-nodejs",
            ],
        },
        "status_url": "https://status.elastic.co",
        "github_repos": [
            "elastic/elasticsearch-py",
            "elastic/kibana",
        ],
    },

    "crowdstrike": {
        "nvd_keywords": [
            "crowdstrike",
            "falcon",           # EDR sensor; kernel-level; high-severity when vulnerable
        ],
        "kev_vendors": [
            "crowdstrike",
        ],
        "packages": {
            "PyPI": [
                "crowdstrike-falconpy",  # official Falcon SDK; broad enterprise use
            ],
            "npm": [],
        },
        "status_url": "https://status.crowdstrike.com",
        "github_repos": [
            "CrowdStrike/falconpy",
        ],
    },

    # ── Data & AI ─────────────────────────────────────────────────────────────

    "databricks": {
        "nvd_keywords": [
            "databricks",
            "mlflow",            # ML lifecycle; model-serving attack surface
            "delta lake",
            "apache spark",      # Databricks originated Spark
        ],
        "kev_vendors": [
            "databricks",
            "apache",
        ],
        "packages": {
            "PyPI": [
                "databricks-sdk",      # official SDK
                "mlflow",              # most-downloaded MLOps library; RCE history
                "delta",               # Delta Lake Python client
                "databricks-cli",
                "pyspark",
            ],
            "npm": [
                "@databricks/sql",
            ],
        },
        "status_url": "https://status.databricks.com",
        "github_repos": [
            "databricks/databricks-sdk-py",
            "mlflow/mlflow",
        ],
    },

    "mongodb": {
        "nvd_keywords": [
            "mongodb",
        ],
        "kev_vendors": [
            "mongodb",
        ],
        "packages": {
            "PyPI": [
                "pymongo",             # official driver; injection/deserialization history
                "motor",               # async pymongo wrapper
            ],
            "npm": [
                "mongodb",             # official Node.js driver
                "mongoose",            # ODM; prototype-pollution CVEs historically
            ],
        },
        "status_url": "https://status.mongodb.com",
        "github_repos": [
            "mongodb/mongo-python-driver",
            "mongodb/mongoose",
        ],
    },

    "confluent": {
        "nvd_keywords": [
            "confluent",
            "apache kafka",      # originated at LinkedIn; Confluent is primary steward
        ],
        "kev_vendors": [
            "confluent",
            "apache kafka",
        ],
        "packages": {
            "PyPI": [
                "confluent-kafka",     # official high-performance Python client
                "kafka-python",        # pure-Python client; wide install base
            ],
            "npm": [
                "kafkajs",             # dominant Node.js Kafka client
                "node-rdkafka",        # librdkafka bindings
            ],
        },
        "status_url": "https://status.confluent.io",
        "github_repos": [
            "confluentinc/confluent-kafka-python",
            "confluentinc/librdkafka",
        ],
    },

    "redis": {
        "nvd_keywords": [
            "redis",
        ],
        "kev_vendors": [
            "redis",
        ],
        "packages": {
            "PyPI": [
                "redis",               # official Python client
                "hiredis",             # C-extension parser; memory-safety relevant
            ],
            "npm": [
                "redis",               # official Node.js client
                "ioredis",             # alternative client; wide adoption
            ],
        },
        "status_url": "https://status.redis.io",
        "github_repos": [
            "redis/redis-py",
            "redis/ioredis",
        ],
    },

    "palantir": {
        "nvd_keywords": [
            "palantir",
        ],
        "kev_vendors": [
            "palantir",
        ],
        "packages": {
            "PyPI": [
                "palantir-oauth-client",
                "foundry-dev-tools",   # community SDK for Foundry platform
            ],
            "npm": [
                "@palantir/conjure-typescript-runtime",
                "@palantir/blueprint",  # UI component library; XSS surface
            ],
        },
        "status_url": "https://status.palantir.com",
        "github_repos": [
            "palantir/blueprint",
            "palantir/conjure",
        ],
    },

    # ── Dev Tools & Platform ──────────────────────────────────────────────────

    "hashicorp": {
        "nvd_keywords": [
            "hashicorp",
            "terraform",         # IaC; supply-chain and provider-plugin attack surface
            "vault",             # secrets manager; auth-bypass CVEs historically
            "consul",
            "nomad",
        ],
        "kev_vendors": [
            "hashicorp",
        ],
        "packages": {
            "PyPI": [
                "hvac",               # HashiCorp Vault API client; credential access
                "python-hcl2",        # HCL parser
            ],
            "npm": [],
        },
        "status_url": "https://status.hashicorp.com",
        "github_repos": [
            "hashicorp/terraform",
            "hashicorp/vault",
        ],
    },

    "gitlab": {
        "nvd_keywords": [
            "gitlab",
        ],
        "kev_vendors": [
            "gitlab",
        ],
        "packages": {
            "PyPI": [
                "python-gitlab",       # official Python API client
            ],
            "npm": [
                "@gitbeaker/rest",     # GitLab API Node.js client
            ],
        },
        "status_url": "https://status.gitlab.com",
        "github_repos": [
            "python-gitlab/python-gitlab",
            "gitlabhq/gitlabhq",
        ],
    },

    "shopify": {
        "nvd_keywords": [
            "shopify",
            "liquid",            # Shopify's template language; SSTI-adjacent issues
        ],
        "kev_vendors": [
            "shopify",
        ],
        "packages": {
            "PyPI": [
                "ShopifyAPI",          # official Python SDK
            ],
            "npm": [
                "@shopify/shopify-api",  # official Node.js SDK
                "@shopify/cli",
                "@shopify/polaris",     # React component library
            ],
        },
        "status_url": "https://www.shopifystatus.com",
        "github_repos": [
            "Shopify/shopify_python_api",
            "Shopify/shopify-api-node",
        ],
    },

    "atlassian": {
        "nvd_keywords": [
            "atlassian",
            "jira",              # frequent CVEs; RCE/auth-bypass history
            "confluence",        # frequent CVEs; multiple KEV entries historically
            "bitbucket",
        ],
        "kev_vendors": [
            "atlassian",
            "jira",
            "confluence",
            "bitbucket",
        ],
        "packages": {
            "PyPI": [
                "atlassian-python-api",  # dominant Atlassian Python client
                "jira",                  # JIRA Python library
            ],
            "npm": [
                "@atlassianlabs/atlassian-frontend-eslint-config",
            ],
        },
        "status_url": "https://status.atlassian.com",
        "github_repos": [
            "atlassian-api/atlassian-python-api",
        ],
    },
}

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

_ECO_NORM: dict[str, str] = {
    "pypi": "PyPI", "pip": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "go": "Go",
    "cargo": "Cargo", "rust": "Cargo",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "composer": "Composer",
}


def normalize_ecosystem(eco: str) -> str:
    return _ECO_NORM.get(eco.lower(), eco)


def get_nvd_keywords(service_name: str) -> list[str]:
    """
    Return NVD keywordSearch terms for a service.
    All results should be stored under the canonical service_name.
    Falls back to [service_name] if no alias is configured.
    """
    cfg = SERVICE_ALIASES.get(service_name.lower(), {})
    keywords: list[str] = list(cfg.get("nvd_keywords", []))
    if not keywords:
        keywords = [service_name]
    return keywords


def get_kev_vendors(service_name: str) -> list[str]:
    """
    Return KEV vendorProject substrings to match for a service.
    Always includes service_name itself as a fallback.
    """
    cfg = SERVICE_ALIASES.get(service_name.lower(), {})
    vendors: list[str] = list(cfg.get("kev_vendors", []))
    if service_name.lower() not in vendors:
        vendors.insert(0, service_name.lower())
    return vendors


def get_packages(service_name: str, ecosystem: str | None = None) -> dict[str, list[str]]:
    """
    Return {ecosystem: [package_names]} for a service.

    - If ecosystem is given, return only that ecosystem's package list.
    - If the service has no alias config, fall back to {ecosystem: [service_name]}.
    """
    cfg = SERVICE_ALIASES.get(service_name.lower(), {})
    all_pkgs: dict[str, list[str]] = cfg.get("packages", {})

    if not all_pkgs:
        eco = normalize_ecosystem(ecosystem) if ecosystem else "PyPI"
        return {eco: [service_name]}

    if ecosystem:
        eco_key = normalize_ecosystem(ecosystem)
        pkgs = all_pkgs.get(eco_key, [service_name])
        return {eco_key: pkgs}

    return all_pkgs


def get_github_repos(service_name: str) -> list[str]:
    """Return the list of public GitHub owner/repo slugs for a service."""
    cfg = SERVICE_ALIASES.get(service_name.lower(), {})
    return list(cfg.get("github_repos", []))
