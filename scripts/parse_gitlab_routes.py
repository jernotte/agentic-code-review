#!/usr/bin/env python3
"""
Attack Surface Mapper for GitLab CE.

Parses controllers and API endpoints to build a prioritized attack surface map.
Since no Ruby runtime is available, uses regex-based parsing of controller files
and Grape API endpoint files rather than `rails routes`.

Outputs:
  - memory/targets/gitlab/attack_surface.md  (human-readable prioritized list)
  - memory/targets/gitlab/routes_map.jsonl    (structured data)
"""

import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class ControllerInfo:
    file: str
    class_name: str
    parent_class: str = ""
    before_actions: list = field(default_factory=list)
    skip_before_actions: list = field(default_factory=list)
    actions: list = field(default_factory=list)
    has_auth: bool = True
    handles_params: bool = False
    handles_file_upload: bool = False
    is_api: bool = False
    priority: int = 0


@dataclass
class ApiEndpoint:
    file: str
    http_method: str
    path: str
    has_auth: bool = True
    params_used: list = field(default_factory=list)
    priority: int = 0


def find_gitlab_source(base_dir: str) -> str:
    """Locate the GitLab source directory."""
    candidate = os.path.join(base_dir, "gitlab-source")
    if os.path.isdir(candidate):
        return candidate
    raise FileNotFoundError(f"GitLab source not found at {candidate}")


def parse_controller(filepath: str, gitlab_root: str) -> ControllerInfo:
    """Parse a Rails controller file to extract security-relevant info."""
    try:
        with open(filepath) as f:
            content = f.read()
    except (IOError, UnicodeDecodeError):
        return None

    rel_path = os.path.relpath(filepath, gitlab_root)

    # Extract class name and parent
    class_match = re.search(r'class\s+(\w+(?:::\w+)*)\s*<\s*(\S+)', content)
    if not class_match:
        return None

    info = ControllerInfo(
        file=rel_path,
        class_name=class_match.group(1),
        parent_class=class_match.group(2),
    )

    # Extract before_action declarations
    for m in re.finditer(
        r'before_action\s+:(\w+)(?:,\s*(.*?))?$', content, re.MULTILINE
    ):
        action_name = m.group(1)
        opts = m.group(2) or ""
        info.before_actions.append({"filter": action_name, "options": opts.strip()})

        # Track auth-related filters
        if "authenticate" in action_name or "authorize" in action_name:
            info.has_auth = True

    # Extract skip_before_action (weakens auth)
    for m in re.finditer(
        r'skip_before_action\s+:(\w+)(?:,\s*(.*?))?$', content, re.MULTILINE
    ):
        info.skip_before_actions.append({
            "filter": m.group(1),
            "options": (m.group(2) or "").strip(),
        })

    # Check if auth is skipped broadly
    for skip in info.skip_before_actions:
        if "authenticate" in skip["filter"]:
            # Check if it's a broad skip (no only: constraint)
            if "only:" not in skip["options"] and "except:" not in skip["options"]:
                info.has_auth = False

    # Extract action methods (def action_name)
    # Look for public methods that are likely controller actions
    in_private = False
    for line in content.split("\n"):
        stripped = line.strip()
        if stripped in ("private", "protected"):
            in_private = True
        elif not in_private and re.match(r'def\s+(\w+)', stripped):
            method_name = re.match(r'def\s+(\w+)', stripped).group(1)
            # Skip common non-action methods
            if not method_name.startswith("_") and method_name not in (
                "initialize", "self",
            ):
                info.actions.append(method_name)

    # Check for params usage (user input handling)
    if re.search(r'params\[', content) or re.search(r'params\.(?:require|permit|fetch)', content):
        info.handles_params = True

    # Check for file upload handling
    if re.search(r'upload|attachment|file.*param|send_file|send_data', content, re.IGNORECASE):
        info.handles_file_upload = True

    # Check if API controller
    info.is_api = "api" in rel_path.lower() or "API" in info.parent_class

    return info


def parse_grape_api(filepath: str, gitlab_root: str) -> list:
    """Parse a Grape API file to extract endpoints."""
    try:
        with open(filepath) as f:
            content = f.read()
    except (IOError, UnicodeDecodeError):
        return []

    rel_path = os.path.relpath(filepath, gitlab_root)
    endpoints = []

    # Match Grape route declarations: get/post/put/patch/delete 'path'
    for m in re.finditer(
        r'(?:^|\s)(get|post|put|patch|delete)\s+[\'"]([^\'"]+)[\'"]',
        content,
        re.MULTILINE,
    ):
        http_method = m.group(1).upper()
        path = m.group(2)

        ep = ApiEndpoint(
            file=rel_path,
            http_method=http_method,
            path=path,
        )

        endpoints.append(ep)

    # Check for params usage
    params_used = bool(re.search(r'params\[|declared\(params\)|declared_params', content))

    # Check auth
    has_auth = not bool(re.search(r'allow_access_with_scope|skip_authentication', content))

    for ep in endpoints:
        ep.has_auth = has_auth
        if params_used:
            ep.params_used = ["yes"]

    return endpoints


def parse_finder(filepath: str, gitlab_root: str) -> dict:
    """Parse a Finder class for SQL-relevant patterns."""
    try:
        with open(filepath) as f:
            content = f.read()
    except (IOError, UnicodeDecodeError):
        return None

    rel_path = os.path.relpath(filepath, gitlab_root)

    # Look for dangerous SQL patterns
    has_string_interpolation = bool(re.search(r'"\s*.*#\{.*\}.*"', content))
    has_where_string = bool(re.search(r'\.where\s*\(?\s*["\']', content))
    has_order_string = bool(re.search(r'\.order\s*\(?\s*["\'].*#\{', content))
    has_find_by_sql = bool(re.search(r'find_by_sql|connection\.execute|exec_query', content))
    has_arel = bool(re.search(r'Arel\.|arel_table', content))
    uses_params = bool(re.search(r'params|@params|options\[', content))

    risk_score = sum([
        has_string_interpolation * 3,
        has_where_string * 2,
        has_order_string * 3,
        has_find_by_sql * 4,
        has_arel * 1,
        uses_params * 2,
    ])

    if risk_score == 0:
        return None

    return {
        "file": rel_path,
        "risk_score": risk_score,
        "string_interpolation_in_sql": has_string_interpolation,
        "where_with_string": has_where_string,
        "order_with_interpolation": has_order_string,
        "find_by_sql_or_raw": has_find_by_sql,
        "uses_params": uses_params,
    }


def score_controller(info: ControllerInfo) -> int:
    """Assign priority score to a controller. Higher = more interesting."""
    score = 0

    # API endpoints are higher priority (wider attack surface)
    if info.is_api:
        score += 5

    # No auth = higher priority
    if not info.has_auth:
        score += 10

    # Skipped auth filters = interesting
    score += len(info.skip_before_actions) * 3

    # Handles params = processes user input
    if info.handles_params:
        score += 3

    # File uploads = high value target
    if info.handles_file_upload:
        score += 5

    # More actions = more attack surface
    score += min(len(info.actions), 10)

    # Certain controller names indicate high-value targets
    high_value_patterns = [
        "import", "upload", "export", "webhook", "api", "oauth",
        "session", "password", "token", "admin", "snippet",
        "merge_request", "issue", "pipeline", "repository",
        "commit", "blob", "raw", "archive",
    ]
    name_lower = info.class_name.lower()
    for pattern in high_value_patterns:
        if pattern in name_lower:
            score += 3

    return score


def score_api_endpoint(ep: ApiEndpoint) -> int:
    """Assign priority score to an API endpoint."""
    score = 5  # Base score for API endpoints

    if not ep.has_auth:
        score += 10

    if ep.params_used:
        score += 3

    # Write operations are more interesting
    if ep.http_method in ("POST", "PUT", "PATCH"):
        score += 2

    # Certain paths indicate high-value targets
    high_value = [
        "upload", "import", "export", "webhook", "token",
        "session", "password", "admin", "raw", "archive",
        "execute", "merge", "commit",
    ]
    path_lower = ep.path.lower()
    for pattern in high_value:
        if pattern in path_lower:
            score += 3

    return score


def scan_directory(gitlab_root: str) -> tuple:
    """Scan GitLab source for controllers, API endpoints, and finders."""
    controllers = []
    api_endpoints = []
    finders = []

    # Scan controllers
    controllers_dir = os.path.join(gitlab_root, "app", "controllers")
    if os.path.isdir(controllers_dir):
        for root, _dirs, files in os.walk(controllers_dir):
            for fname in files:
                if fname.endswith("_controller.rb"):
                    fpath = os.path.join(root, fname)
                    info = parse_controller(fpath, gitlab_root)
                    if info:
                        info.priority = score_controller(info)
                        controllers.append(info)

    # Scan Grape API endpoints
    api_dir = os.path.join(gitlab_root, "lib", "api")
    if os.path.isdir(api_dir):
        for root, _dirs, files in os.walk(api_dir):
            for fname in files:
                if fname.endswith(".rb"):
                    fpath = os.path.join(root, fname)
                    eps = parse_grape_api(fpath, gitlab_root)
                    for ep in eps:
                        ep.priority = score_api_endpoint(ep)
                        api_endpoints.append(ep)

    # Scan finders for SQL patterns
    finders_dir = os.path.join(gitlab_root, "app", "finders")
    if os.path.isdir(finders_dir):
        for root, _dirs, files in os.walk(finders_dir):
            for fname in files:
                if fname.endswith(".rb"):
                    fpath = os.path.join(root, fname)
                    result = parse_finder(fpath, gitlab_root)
                    if result:
                        finders.append(result)

    return controllers, api_endpoints, finders


def write_routes_map(controllers, api_endpoints, finders, output_path):
    """Write structured JSONL output."""
    with open(output_path, "w") as f:
        for c in sorted(controllers, key=lambda x: -x.priority):
            record = {
                "type": "controller",
                "file": c.file,
                "class": c.class_name,
                "parent": c.parent_class,
                "actions": c.actions[:20],  # Cap to avoid huge records
                "has_auth": c.has_auth,
                "skip_auth_filters": [s["filter"] for s in c.skip_before_actions],
                "handles_params": c.handles_params,
                "handles_file_upload": c.handles_file_upload,
                "is_api": c.is_api,
                "priority": c.priority,
            }
            f.write(json.dumps(record) + "\n")

        for ep in sorted(api_endpoints, key=lambda x: -x.priority):
            record = {
                "type": "api_endpoint",
                "file": ep.file,
                "method": ep.http_method,
                "path": ep.path,
                "has_auth": ep.has_auth,
                "priority": ep.priority,
            }
            f.write(json.dumps(record) + "\n")

        for finder in sorted(finders, key=lambda x: -x["risk_score"]):
            record = {
                "type": "finder",
                **finder,
                "priority": finder["risk_score"],
            }
            f.write(json.dumps(record) + "\n")


def write_attack_surface(controllers, api_endpoints, finders, output_path):
    """Write human-readable attack surface map."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    with open(output_path, "w") as f:
        f.write("# GitLab CE Attack Surface\n\n")
        f.write(f"Generated: {ts}\n\n")

        # Summary stats
        f.write("## Summary\n\n")
        f.write(f"- **Controllers:** {len(controllers)}\n")
        f.write(f"- **API endpoints:** {len(api_endpoints)}\n")
        f.write(f"- **Finders with SQL risk patterns:** {len(finders)}\n")

        no_auth_controllers = [c for c in controllers if not c.has_auth]
        f.write(f"- **Controllers with weakened auth:** {len(no_auth_controllers)}\n")

        upload_controllers = [c for c in controllers if c.handles_file_upload]
        f.write(f"- **Controllers handling file uploads:** {len(upload_controllers)}\n\n")

        # High-priority finders (SQL risk)
        f.write("## Priority 1: Finders with SQL Risk Patterns\n\n")
        f.write("These files construct database queries and show patterns that may indicate SQL injection risk.\n\n")
        for finder in sorted(finders, key=lambda x: -x["risk_score"])[:30]:
            flags = []
            if finder.get("string_interpolation_in_sql"):
                flags.append("string interpolation")
            if finder.get("where_with_string"):
                flags.append("string WHERE")
            if finder.get("order_with_interpolation"):
                flags.append("interpolated ORDER")
            if finder.get("find_by_sql_or_raw"):
                flags.append("raw SQL")
            if finder.get("uses_params"):
                flags.append("uses params")
            f.write(f"- **{finder['file']}** (risk: {finder['risk_score']}) — {', '.join(flags)}\n")
        f.write("\n")

        # High-priority controllers
        f.write("## Priority 2: High-Value Controllers\n\n")
        top_controllers = sorted(controllers, key=lambda x: -x.priority)[:30]
        for c in top_controllers:
            flags = []
            if not c.has_auth:
                flags.append("NO AUTH")
            if c.skip_before_actions:
                flags.append(f"skips: {','.join(s['filter'] for s in c.skip_before_actions[:3])}")
            if c.handles_file_upload:
                flags.append("file upload")
            if c.handles_params:
                flags.append("params")
            if c.is_api:
                flags.append("API")
            flags_str = f" — {', '.join(flags)}" if flags else ""
            f.write(f"- **{c.file}** [{c.class_name}] (score: {c.priority}){flags_str}\n")
        f.write("\n")

        # Controllers with weakened auth
        if no_auth_controllers:
            f.write("## Priority 3: Controllers with Weakened Authentication\n\n")
            for c in sorted(no_auth_controllers, key=lambda x: -x.priority):
                skips = ", ".join(s["filter"] for s in c.skip_before_actions)
                f.write(f"- **{c.file}** [{c.class_name}] — skips: {skips}\n")
            f.write("\n")

        # File upload controllers
        if upload_controllers:
            f.write("## Priority 4: File Upload Handlers\n\n")
            for c in sorted(upload_controllers, key=lambda x: -x.priority):
                f.write(f"- **{c.file}** [{c.class_name}]\n")
            f.write("\n")

        # API endpoint summary (top 30)
        f.write("## API Endpoints (Top 30 by Priority)\n\n")
        top_api = sorted(api_endpoints, key=lambda x: -x.priority)[:30]
        for ep in top_api:
            auth_str = "" if ep.has_auth else " [NO AUTH]"
            f.write(f"- `{ep.http_method} {ep.path}` ({ep.file}){auth_str}\n")
        f.write("\n")


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    gitlab_root = find_gitlab_source(base_dir)

    print(f"Scanning GitLab source at: {gitlab_root}")

    controllers, api_endpoints, finders = scan_directory(gitlab_root)

    print(f"Found {len(controllers)} controllers, {len(api_endpoints)} API endpoints, {len(finders)} finders with SQL risk")

    # Write outputs
    routes_map_path = os.path.join(base_dir, "memory", "targets", "gitlab", "routes_map.jsonl")
    attack_surface_path = os.path.join(base_dir, "memory", "targets", "gitlab", "attack_surface.md")

    write_routes_map(controllers, api_endpoints, finders, routes_map_path)
    print(f"Wrote {routes_map_path}")

    write_attack_surface(controllers, api_endpoints, finders, attack_surface_path)
    print(f"Wrote {attack_surface_path}")


if __name__ == "__main__":
    main()
