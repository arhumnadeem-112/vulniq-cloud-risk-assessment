"""
entrypoint.py
-------------
Container entrypoint for the cloudrisk pipeline.

Reads CLOUDRISK_COMMAND from the environment and routes to the correct handler.
shlex-aware splitting handles URLs and quoted strings safely.

─── Direct module dispatch (pass-through to collect_* / pipeline scripts) ───
    # --service is the NVD keyword search term; change 'salesforce' to any vendor name
    CLOUDRISK_COMMAND='collect_nvd --service salesforce'
    CLOUDRISK_COMMAND='collect_nvd --service salesforce "salesforce commerce cloud"'

    # --service is the canonical service name; packages are resolved via service_aliases
    # (covers simple-salesforce, salesforce-bulk, jsforce, @salesforce/core, etc.)
    # Use --packages to override: --packages simple-salesforce,salesforce-bulk
    CLOUDRISK_COMMAND='collect_osv --service salesforce'

    # Same alias-driven multi-package expansion for GHSA
    CLOUDRISK_COMMAND='collect_ghsa --service salesforce'

    # KEV collector now matches Salesforce + subsidiaries (Heroku, MuleSoft, Tableau, Slack)
    CLOUDRISK_COMMAND='collect_kev --service salesforce'

    # --repo is the GitHub owner/repo slug to profile; change to any Salesforce OSS repo
    CLOUDRISK_COMMAND='collect_github --service salesforce --repo forcedotcom/SalesforceMobileSDK-iOS'

    # --service must match the service_name stored in the vulnerabilities table
    CLOUDRISK_COMMAND='collect_vuln_text --service salesforce'

    # Salesforce has a custom status API — use --provider salesforce instead of --status-url
    CLOUDRISK_COMMAND='collect_status --service salesforce --provider salesforce'

    # --urls is one or more security/documentation pages to scrape; change URLs to target different docs
    CLOUDRISK_COMMAND='collect_docs --service salesforce --urls https://help.salesforce.com/s/articleView?id=sf.security_overview.htm https://developer.salesforce.com/docs/atlas.en-us.secure_coding_guide.meta/secure_coding_guide/'

    # --urls is one or more trust-center / compliance pages to scrape; change URLs as needed
    CLOUDRISK_COMMAND='collect_trust --service salesforce --urls https://trust.salesforce.com https://www.salesforce.com/company/privacy/'

    # General risk assessment: no vendor targeting, last 6 months of CVEs from NVD/KEV/GHSA
    CLOUDRISK_COMMAND='collect_general'
    CLOUDRISK_COMMAND='collect_general --sources nvd,kev'
    CLOUDRISK_COMMAND='collect_general --start-date 2024-11-01'

    CLOUDRISK_COMMAND='db_migrate'
    CLOUDRISK_COMMAND='monitor_nvd --service salesforce'
    CLOUDRISK_COMMAND='etl --ospc /data/config/ospc.json'
    CLOUDRISK_COMMAND='etl --run-id <uuid> --ospc /data/config/ospc.json'
    CLOUDRISK_COMMAND='score --run-id <uuid> --ospc /data/config/ospc.json'

─── Meta-commands (orchestrated inline) ─────────────────────────────────────
    # Validate OSPC config before a run
    CLOUDRISK_COMMAND='validate-ospc --ospc /data/config/ospc.json'

    # Generic collect: dispatches to the correct collect_* module
    # --source selects which data source to hit; --service is the target vendor/package name
    CLOUDRISK_COMMAND='collect --service salesforce --source nvd'
    CLOUDRISK_COMMAND='collect --service salesforce --source all'
    CLOUDRISK_COMMAND='collect --service simple-salesforce --source osv --ecosystem PyPI'

    # Full pipeline: collect → etl → score (single job start)
    # Change --service to the vendor name registered in the services table
    CLOUDRISK_COMMAND='run --service salesforce --ospc /data/config/ospc.json'
    CLOUDRISK_COMMAND='run --service salesforce --ospc /data/config/ospc.json --sources nvd,ghsa,kev'
    CLOUDRISK_COMMAND='run --service salesforce --ospc /data/config/ospc.json --skip-collect'
    CLOUDRISK_COMMAND='run --service salesforce --ospc /data/config/ospc.json --run-id <uuid>'
"""

import argparse
import json
import logging
import os
import shlex
import subprocess
import sys
import uuid

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s entrypoint — %(message)s",
)
log = logging.getLogger("entrypoint")

# ---------------------------------------------------------------------------
# Dispatch tables
# ---------------------------------------------------------------------------

# Direct-dispatch commands: command name → Python module path
MODULE_MAP: dict[str, str] = {
    "collect_nvd":      "collectors.collect_nvd",
    "collect_osv":      "collectors.collect_osv",
    "collect_ghsa":     "collectors.collect_ghsa",
    "collect_kev":      "collectors.collect_kev",
    "collect_general":  "collectors.collect_general",
    "collect_github":   "collectors.collect_github",
    "collect_vuln_text": "collectors.collect_vuln_text",
    "collect_status":   "collectors.collect_status",
    "collect_docs":     "collectors.collect_docs",
    "collect_trust":    "collectors.collect_trust",
    "db_migrate":       "collectors.db_migrate",
    "monitor_nvd":      "collectors.monitor_nvd",
    # Pipeline stages
    "etl":   "collectors.etl",
    "score": "collectors.scoring",
}

# Source alias → collector script name (used by `collect` and `run`)
SOURCE_MAP: dict[str, str] = {
    "nvd":       "collect_nvd",
    "osv":       "collect_osv",
    "ghsa":      "collect_ghsa",
    "kev":       "collect_kev",
    "github":    "collect_github",
    "vuln_text": "collect_vuln_text",
    "status":    "collect_status",
    "docs":      "collect_docs",
    "trust":     "collect_trust",
}

# Sources that only need --service (safe for `run` to call automatically)
RUN_DEFAULT_SOURCES: list[str] = ["nvd", "osv", "ghsa", "kev", "vuln_text"]

# Meta-commands handled inline rather than dispatched to a module
META_COMMANDS: set[str] = {"run", "collect", "validate-ospc"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_module(module: str, args: list[str]) -> int:
    """Run `python -m <module> [args]` and return its exit code."""
    cmd = ["python", "-m", module] + args
    log.info("Executing: %s", " ".join(cmd))
    return subprocess.call(cmd)


# ---------------------------------------------------------------------------
# Meta-command: validate-ospc
# ---------------------------------------------------------------------------


def cmd_validate_ospc(args: list[str]) -> int:
    """
    validate-ospc --ospc <path>

    Loads and validates the OSPC JSON against the scoring schema.
    Exits 0 on success, 1 on any validation failure.
    """
    parser = argparse.ArgumentParser(
        prog="validate-ospc",
        description="Validate the OSPC configuration JSON file",
    )
    parser.add_argument(
        "--ospc",
        default="/data/config/ospc.json",
        help="Path to OSPC JSON config (default: /data/config/ospc.json)",
    )
    parsed = parser.parse_args(args)

    try:
        import jsonschema
        from collectors.scoring import OSPC_SCHEMA  # reuse the canonical schema

        with open(parsed.ospc, encoding="utf-8") as f:
            ospc = json.load(f)

        jsonschema.validate(instance=ospc, schema=OSPC_SCHEMA)

        log.info(
            "OSPC validation passed — org=%s frameworks=%s controls=%s",
            ospc.get("org_name"),
            ospc.get("regulatory_frameworks", []),
            ospc.get("compensating_controls", []),
        )
        return 0

    except FileNotFoundError:
        log.error("OSPC file not found: %s", parsed.ospc)
        return 1
    except json.JSONDecodeError as exc:
        log.error("OSPC is not valid JSON: %s", exc)
        return 1
    except Exception as exc:  # jsonschema.ValidationError or import errors
        log.error("OSPC validation failed: %s", exc)
        return 1


# ---------------------------------------------------------------------------
# Meta-command: collect
# ---------------------------------------------------------------------------


def cmd_collect(args: list[str]) -> int:
    """
    collect --service <svc> --source <src|all> [extra args passed through]

    Dispatches to the correct collect_* module.
    Extra args (e.g. --ecosystem, --repo, --urls) are forwarded verbatim.
    Use --source all to run every source sequentially.
    """
    parser = argparse.ArgumentParser(
        prog="collect",
        description="Generic collect dispatcher — routes to a specific collector module",
    )
    parser.add_argument(
        "--service",
        required=True,
        help="Service name (e.g. stripe, requests)",
    )
    parser.add_argument(
        "--source",
        required=True,
        choices=sorted(SOURCE_MAP.keys()) + ["all"],
        help="Data source to collect from, or 'all' for every source",
    )
    parsed, remaining = parser.parse_known_args(args)

    sources = list(RUN_DEFAULT_SOURCES) if parsed.source == "all" else [parsed.source]

    overall_exit = 0
    for source in sources:
        script = SOURCE_MAP[source]
        module = f"collectors.{script}"
        collector_args = ["--service", parsed.service] + remaining
        exit_code = _run_module(module, collector_args)
        if exit_code != 0:
            log.warning("Collector '%s' exited with code %d", source, exit_code)
            overall_exit = exit_code

    return overall_exit


# ---------------------------------------------------------------------------
# Meta-command: run  (collect → etl → score)
# ---------------------------------------------------------------------------


def cmd_run(args: list[str]) -> int:
    """
    run --service <svc> --ospc <path> [options]

    Full pipeline orchestration:
      1. Invoke self-contained collectors (nvd, osv, ghsa, kev, vuln_text) for <svc>
      2. Run ETL across all services in the database
      3. Run scoring for this ETL run

    Options:
      --sources      Comma-separated list of sources to collect
                     (default: nvd,osv,ghsa,kev,vuln_text)
      --skip-collect Skip collection phase and go straight to etl→score
      --run-id       Explicit UUID for this pipeline run (auto-generated if omitted)
    """
    parser = argparse.ArgumentParser(
        prog="run",
        description="Full pipeline: collect → etl → score",
    )
    parser.add_argument(
        "--service",
        required=True,
        help="Service name to collect data for",
    )
    parser.add_argument(
        "--ospc",
        default="/data/config/ospc.json",
        help="Path to OSPC JSON config (default: /data/config/ospc.json)",
    )
    parser.add_argument(
        "--sources",
        default=",".join(RUN_DEFAULT_SOURCES),
        help=(
            "Comma-separated list of sources to collect "
            f"(default: {','.join(RUN_DEFAULT_SOURCES)})"
        ),
    )
    parser.add_argument(
        "--skip-collect",
        action="store_true",
        help="Skip collection phase — run etl→score only",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Explicit pipeline run UUID (auto-generated if omitted)",
    )
    parsed = parser.parse_args(args)

    run_id = parsed.run_id or str(uuid.uuid4())
    log.info(
        "Pipeline starting — run_id=%s service=%s ospc=%s",
        run_id, parsed.service, parsed.ospc,
    )

    # ── Step 1: Collect ───────────────────────────────────────────────────
    if not parsed.skip_collect:
        sources = [s.strip() for s in parsed.sources.split(",") if s.strip()]
        invalid = [s for s in sources if s not in SOURCE_MAP]
        if invalid:
            log.error(
                "Unknown source(s): %s. Valid sources: %s",
                ", ".join(invalid),
                ", ".join(sorted(SOURCE_MAP.keys())),
            )
            return 1

        log.info("Collection phase — sources: %s", sources)
        for source in sources:
            script = SOURCE_MAP[source]
            module = f"collectors.{script}"
            exit_code = _run_module(module, ["--service", parsed.service])
            if exit_code != 0:
                log.warning(
                    "Collector '%s' exited with code %d — continuing pipeline",
                    source, exit_code,
                )
    else:
        log.info("Collection phase skipped (--skip-collect)")

    # ── Step 2: ETL ───────────────────────────────────────────────────────
    log.info("ETL phase — run_id=%s", run_id)
    etl_exit = _run_module(
        "collectors.etl",
        ["--run-id", run_id, "--ospc", parsed.ospc],
    )
    if etl_exit != 0:
        log.error("ETL failed with exit code %d — aborting pipeline", etl_exit)
        return etl_exit

    # ── Step 3: Score ─────────────────────────────────────────────────────
    log.info("Scoring phase — run_id=%s", run_id)
    score_exit = _run_module(
        "collectors.scoring",
        ["--run-id", run_id, "--ospc", parsed.ospc],
    )
    if score_exit != 0:
        log.error("Scoring failed with exit code %d", score_exit)
        return score_exit

    log.info("Pipeline complete — run_id=%s", run_id)
    return 0


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------


def main() -> None:
    cmd = os.environ.get("CLOUDRISK_COMMAND", "").strip()

    if not cmd:
        log.error(
            "CLOUDRISK_COMMAND is not set.\n"
            "  Examples:\n"
            "    CLOUDRISK_COMMAND='run --service stripe --ospc /data/config/ospc.json'\n"
            "    CLOUDRISK_COMMAND='collect --service stripe --source nvd'\n"
            "    CLOUDRISK_COMMAND='etl --ospc /data/config/ospc.json'\n"
            "    CLOUDRISK_COMMAND='score --run-id <uuid> --ospc /data/config/ospc.json'\n"
            "    CLOUDRISK_COMMAND='validate-ospc --ospc /data/config/ospc.json'\n"
            "    CLOUDRISK_COMMAND='collect_nvd --service stripe'"
        )
        sys.exit(1)

    try:
        parts = shlex.split(cmd)
    except ValueError as exc:
        log.error("Failed to parse CLOUDRISK_COMMAND %r: %s", cmd, exc)
        sys.exit(1)

    command = parts[0]
    args = parts[1:]

    # ── Meta-commands ─────────────────────────────────────────────────────
    if command == "run":
        sys.exit(cmd_run(args))

    if command == "collect":
        sys.exit(cmd_collect(args))

    if command == "validate-ospc":
        sys.exit(cmd_validate_ospc(args))

    # ── Direct module dispatch ────────────────────────────────────────────
    if command not in MODULE_MAP:
        log.error(
            "Unknown command %r.\n"
            "  Direct-dispatch commands: %s\n"
            "  Meta-commands: run, collect, validate-ospc",
            command,
            ", ".join(sorted(MODULE_MAP.keys())),
        )
        sys.exit(1)

    exit_code = _run_module(MODULE_MAP[command], args)

    if exit_code != 0:
        log.error("Command %r exited with code %d", command, exit_code)
    else:
        log.info("Command %r completed successfully", command)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
