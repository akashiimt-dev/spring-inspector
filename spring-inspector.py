#!/usr/bin/env python3
"""
Spring Project Inspector
------------------------
Zero external Python dependencies.
Read-only project analysis.

Run:
    python3 spring-inspector.py

Then open:
    http://localhost:8080

The scanner NEVER writes to the target project.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
import json
import os
import re
import subprocess
import threading
import xml.etree.ElementTree as ET
import html
import socket

HOST = "127.0.0.1"
PORT = 8080

POM_NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def local_name(tag):
    return tag.split("}", 1)[-1]


def text_of(element):
    return (element.text or "").strip() if element is not None else ""


def find_child(parent, name):
    if parent is None:
        return None
    for child in list(parent):
        if local_name(child.tag) == name:
            return child
    return None


def find_children(parent, name):
    if parent is None:
        return []
    return [x for x in list(parent) if local_name(x.tag) == name]


def parse_pom(path):
    tree = ET.parse(path)
    root = tree.getroot()

    model = {
        "groupId": text_of(find_child(root, "groupId")),
        "artifactId": text_of(find_child(root, "artifactId")),
        "version": text_of(find_child(root, "version")),
        "packaging": text_of(find_child(root, "packaging")) or "jar",
        "parent": {},
        "properties": {},
        "dependencies": [],
        "dependencyManagement": [],
        "modules": [],
    }

    parent = find_child(root, "parent")
    if parent is not None:
        model["parent"] = {
            "groupId": text_of(find_child(parent, "groupId")),
            "artifactId": text_of(find_child(parent, "artifactId")),
            "version": text_of(find_child(parent, "version")),
            "relativePath": text_of(find_child(parent, "relativePath")) or "../pom.xml",
        }

    properties = find_child(root, "properties")
    if properties is not None:
        for p in list(properties):
            model["properties"][local_name(p.tag)] = text_of(p)

    dependencies = find_child(root, "dependencies")
    for d in find_children(dependencies, "dependency"):
        model["dependencies"].append(parse_dependency(d, "direct"))

    dm = find_child(root, "dependencyManagement")
    if dm is not None:
        dm_deps = find_child(dm, "dependencies")
        for d in find_children(dm_deps, "dependency"):
            model["dependencyManagement"].append(parse_dependency(d, "managed"))

    modules = find_child(root, "modules")
    if modules is not None:
        model["modules"] = [text_of(x) for x in find_children(modules, "module")]

    return model


def parse_dependency(element, kind):
    exclusions = []
    ex = find_child(element, "exclusions")
    if ex is not None:
        for item in find_children(ex, "exclusion"):
            exclusions.append({
                "groupId": text_of(find_child(item, "groupId")),
                "artifactId": text_of(find_child(item, "artifactId")),
            })

    return {
        "groupId": text_of(find_child(element, "groupId")),
        "artifactId": text_of(find_child(element, "artifactId")),
        "version": text_of(find_child(element, "version")),
        "scope": text_of(find_child(element, "scope")) or "compile",
        "type": text_of(find_child(element, "type")) or "jar",
        "classifier": text_of(find_child(element, "classifier")),
        "optional": text_of(find_child(element, "optional")) == "true",
        "kind": kind,
        "exclusions": exclusions,
    }


def load_properties(path, model):
    """Merge local POM properties and useful Maven built-ins."""
    props = dict(model["properties"])

    if model["version"]:
        props.setdefault("project.version", model["version"])
        props.setdefault("pom.version", model["version"])

    if model["groupId"]:
        props.setdefault("project.groupId", model["groupId"])
        props.setdefault("pom.groupId", model["groupId"])

    if model["artifactId"]:
        props.setdefault("project.artifactId", model["artifactId"])
        props.setdefault("pom.artifactId", model["artifactId"])

    return props


def resolve_property(value, properties):
    if not value:
        return value, []

    sources = []
    result = value

    # Resolve ${foo}; repeat to support nested properties.
    for _ in range(10):
        changed = False

        def repl(match):
            nonlocal changed
            key = match.group(1)
            if key in properties:
                changed = True
                sources.append((key, properties[key]))
                return properties[key]
            return match.group(0)

        new_result = re.sub(r"\$\{([^}]+)\}", repl, result)
        result = new_result
        if not changed:
            break

    return result, sources


def load_parent_chain(project_dir, model):
    """
    Follow relative parent POMs available locally.
    Does not download anything.
    """
    chain = []
    visited = set()

    current_dir = project_dir
    current_model = model

    while current_model.get("parent"):
        p = current_model["parent"]
        rel = p.get("relativePath") or "../pom.xml"
        parent_path = (current_dir / rel).resolve()

        if parent_path.is_dir():
            parent_path = parent_path / "pom.xml"

        if not parent_path.exists():
            break

        key = str(parent_path)
        if key in visited:
            break

        visited.add(key)

        try:
            parent_model = parse_pom(parent_path)
        except Exception:
            break

        chain.append({
            "path": str(parent_path),
            "groupId": parent_model.get("groupId") or p.get("groupId", ""),
            "artifactId": parent_model.get("artifactId") or p.get("artifactId", ""),
            "version": parent_model.get("version") or p.get("version", ""),
            "model": parent_model,
        })

        current_dir = parent_path.parent
        current_model = parent_model

    return chain


def dependency_key(d):
    return f'{d["groupId"]}:{d["artifactId"]}'


def is_version_property(version):
    if not version:
        return None
    m = re.fullmatch(r"\$\{([^}]+)\}", version.strip())
    return m.group(1) if m else None


def analyse(project_path):
    project = Path(project_path).expanduser().resolve()

    if not project.exists():
        raise ValueError("Project path does not exist.")

    if not project.is_dir():
        raise ValueError("Project path is not a directory.")

    pom = project / "pom.xml"
    gradle = project / "build.gradle"
    gradle_kts = project / "build.gradle.kts"

    if not pom.exists():
        return {
            "projectName": project.name,
            "path": str(project),
            "type": "Unknown / Gradle",
            "maven": False,
            "gradle": gradle.exists() or gradle_kts.exists(),
            "javaVersion": None,
            "springBootVersion": None,
            "dependencies": [],
            "managed": [],
            "conflicts": [],
            "inheritance": [],
            "warnings": [
                "No pom.xml found. This first version focuses on Maven projects."
            ],
            "passed": [
                "Project folder is readable."
            ],
            "readOnly": True,
        }

    model = parse_pom(pom)
    parent_chain = load_parent_chain(project, model)

    # Merge properties from local POM and locally available parent POMs.
    effective_properties = load_properties(pom, model)

    for item in reversed(parent_chain):
        parent_model = item["model"]
        for key, value in parent_model.get("properties", {}).items():
            effective_properties.setdefault(key, value)

    # Parent version may itself be property based.
    parent_info = model.get("parent", {})
    parent_version, parent_sources = resolve_property(
        parent_info.get("version", ""), effective_properties
    )

    # Direct + managed dependencies.
    direct = []
    for d in model["dependencies"]:
        resolved, sources = resolve_property(d["version"], effective_properties)
        copy = dict(d)
        copy["resolvedVersion"] = resolved
        copy["versionProperty"] = is_version_property(d["version"])
        copy["propertySources"] = sources
        direct.append(copy)

    managed = []
    for d in model["dependencyManagement"]:
        resolved, sources = resolve_property(d["version"], effective_properties)
        copy = dict(d)
        copy["resolvedVersion"] = resolved
        copy["versionProperty"] = is_version_property(d["version"])
        copy["propertySources"] = sources
        managed.append(copy)

    # Parent-managed dependencies.
    for parent_item in parent_chain:
        pm = parent_item["model"]
        for d in pm.get("dependencyManagement", []):
            resolved, sources = resolve_property(
                d["version"], effective_properties
            )
            copy = dict(d)
            copy["resolvedVersion"] = resolved
            copy["versionProperty"] = is_version_property(d["version"])
            copy["propertySources"] = sources
            copy["sourceParent"] = parent_item["artifactId"]
            managed.append(copy)

    # Detect duplicate direct declarations.
    direct_map = {}
    conflicts = []
    for d in direct:
        key = dependency_key(d)
        direct_map.setdefault(key, []).append(d)

    for key, entries in direct_map.items():
        versions = sorted(set(
            e["resolvedVersion"] for e in entries if e["resolvedVersion"]
        ))
        if len(versions) > 1:
            conflicts.append({
                "type": "DIRECT_VERSION_CONFLICT",
                "dependency": key,
                "versions": versions,
                "details": [
                    f'Declared directly with multiple versions: {", ".join(versions)}'
                ],
                "severity": "HIGH",
            })

    # Managed version vs explicit direct version.
    managed_map = {}
    for d in managed:
        key = dependency_key(d)
        managed_map.setdefault(key, []).append(d)

    inheritance = []

    for d in direct:
        key = dependency_key(d)
        explicit = d["resolvedVersion"]

        if not explicit and key in managed_map:
            candidates = [
                x["resolvedVersion"]
                for x in managed_map[key]
                if x["resolvedVersion"]
            ]
            if candidates:
                selected = candidates[0]
                inheritance.append({
                    "dependency": key,
                    "selectedVersion": selected,
                    "declaredVersion": None,
                    "source": "dependencyManagement",
                    "path": build_source_path(
                        project, key, selected, managed_map[key][0],
                        parent_chain
                    ),
                })

        if explicit and key in managed_map:
            managed_versions = sorted(set(
                x["resolvedVersion"]
                for x in managed_map[key]
                if x["resolvedVersion"]
            ))
            if managed_versions and explicit not in managed_versions:
                conflicts.append({
                    "type": "EXPLICIT_OVERRIDES_MANAGEMENT",
                    "dependency": key,
                    "versions": [explicit] + managed_versions,
                    "details": [
                        f"Project explicitly declares {explicit}.",
                        f"Dependency management provides {', '.join(managed_versions)}."
                    ],
                    "severity": "MEDIUM",
                })

    # Spring Boot detection.
    spring_boot_version = None
    parent_ga = (
        parent_info.get("groupId", ""),
        parent_info.get("artifactId", "")
    )
    if parent_ga == ("org.springframework.boot", "spring-boot-starter-parent"):
        spring_boot_version = parent_version

    # Also detect spring-boot-dependencies BOM.
    for d in managed:
        if (
            d["groupId"] == "org.springframework.boot"
            and d["artifactId"] == "spring-boot-dependencies"
        ):
            spring_boot_version = d["resolvedVersion"] or spring_boot_version

    warnings = []
    passed = []

    if parent_chain:
        passed.append(
            f'Local parent chain resolved: {len(parent_chain)} parent POM(s).'
        )
    else:
        if parent_info:
            warnings.append(
                "Parent POM is declared but its local relative POM was not found. "
                "No network access was used."
            )

    if model["modules"]:
        passed.append(
            f'Multi-module Maven project detected: {len(model["modules"])} module(s).'
        )

    if model["properties"]:
        passed.append(
            f'Found {len(model["properties"])} local Maven properties.'
        )

    if managed:
        passed.append(
            f'Found {len(managed)} dependency-management entries.'
        )

    if conflicts:
        warnings.append(
            f'{len(conflicts)} dependency/version issue(s) require attention.'
        )
    else:
        passed.append("No version conflicts found in the analysed POM.")

    # Detect both application configuration styles.
    if (project / "src/main/resources/application.yml").exists() and \
       (project / "src/main/resources/application.properties").exists():
        warnings.append(
            "Both application.yml and application.properties exist."
        )

    return {
        "projectName": model["artifactId"] or project.name,
        "path": str(project),
        "type": "Maven",
        "maven": True,
        "gradle": False,
        "javaVersion": (
            effective_properties.get("java.version")
            or effective_properties.get("maven.compiler.release")
            or effective_properties.get("maven.compiler.source")
        ),
        "springBootVersion": spring_boot_version,
        "parent": {
            "groupId": parent_info.get("groupId"),
            "artifactId": parent_info.get("artifactId"),
            "version": parent_version,
            "sources": parent_sources,
        },
        "parentChain": [
            {
                "groupId": x["groupId"],
                "artifactId": x["artifactId"],
                "version": x["version"],
                "path": x["path"],
            }
            for x in parent_chain
        ],
        "dependencies": direct,
        "managed": managed,
        "conflicts": conflicts,
        "inheritance": inheritance,
        "warnings": warnings,
        "passed": passed,
        "readOnly": True,
    }


def build_source_path(project, key, selected, managed_entry, parent_chain):
    path = [str(project / "pom.xml")]

    source_parent = managed_entry.get("sourceParent")
    if source_parent:
        for p in parent_chain:
            if p["artifactId"] == source_parent:
                path.append(p["path"])
                break
    else:
        path.append("dependencyManagement")

    property_name = managed_entry.get("versionProperty")
    if property_name:
        path.append(f"${{{property_name}}} = {selected}")

    path.append(f"{key}:{selected}")
    return path


def try_maven_dependency_tree(project):
    """
    Optional deep scan.
    Uses locally installed Maven only.
    Maven itself may use its local ~/.m2 cache.
    No Python package or internet request is made by this script.
    """
    mvn = "mvn.cmd" if os.name == "nt" else "mvn"

    try:
        completed = subprocess.run(
            [mvn, "-q", "dependency:tree", "-DoutputType=text"],
            cwd=project,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if completed.returncode != 0:
        return None

    return completed.stdout

HTML = r"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Spring Project Inspector</title>
<style>
:root {
    --bg:#0b1020;
    --panel:#11182b;
    --panel2:#151e35;
    --border:#293653;
    --text:#edf2ff;
    --muted:#91a0bf;
    --green:#62e69a;
    --yellow:#ffd166;
    --red:#ff6b78;
    --blue:#82a4ff;
}
* { box-sizing:border-box; }
body {
    margin:0;
    background:radial-gradient(circle at top,#182442 0,#0b1020 48%);
    color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
}
.container { max-width:1180px; margin:38px auto; padding:0 22px 60px; }
.hero {
    padding:30px;
    border:1px solid var(--border);
    border-radius:24px;
    background:linear-gradient(145deg,#17223d,#10172a);
    box-shadow:0 20px 60px rgba(0,0,0,.25);
}
.hero h1 { margin:0; font-size:32px; }
.hero p { color:var(--muted); margin:10px 0 18px; }
.badge {
    display:inline-block; padding:7px 12px; border-radius:999px;
    background:#123523; color:var(--green); font-size:12px; font-weight:700;
}
.form { display:flex; gap:10px; margin-top:24px; }
input {
    flex:1; min-width:0; padding:15px 16px; border-radius:12px;
    border:1px solid var(--border); background:#0b1223; color:white;
    outline:none; font-size:14px;
}
button {
    border:0; border-radius:12px; padding:0 22px; cursor:pointer;
    background:var(--blue); color:#081022; font-weight:800;
}
button:disabled { opacity:.5; cursor:wait; }
.grid {
    display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-top:20px;
}
.card {
    background:var(--panel); border:1px solid var(--border);
    border-radius:17px; padding:20px;
}
.card .label { color:var(--muted); font-size:13px; }
.card .num { font-size:28px; font-weight:800; margin-top:7px; }
.green { color:var(--green); } .yellow { color:var(--yellow); } .red { color:var(--red); }
.section {
    margin-top:18px; padding:23px; background:var(--panel);
    border:1px solid var(--border); border-radius:18px;
}
.section h2 { margin:0 0 17px; font-size:18px; }
.project-path { color:var(--muted); font:13px ui-monospace,SFMono-Regular,Menlo,monospace; word-break:break-all; }
.issue {
    border:1px solid #4c2830; background:#21151b;
    border-radius:14px; padding:18px; margin-top:12px;
}
.issue-title { font-weight:800; font-size:16px; }
.row { display:flex; gap:10px; flex-wrap:wrap; margin-top:13px; }
.chip {
    padding:7px 10px; border-radius:9px; background:#1a2640;
    color:#cdd8f5; font:12px ui-monospace,SFMono-Regular,Menlo,monospace;
}
.flow {
    display:flex; align-items:center; flex-wrap:wrap; gap:8px;
    margin-top:14px; color:#dbe4ff;
}
.flow .node {
    background:#18233b; border:1px solid #344668; border-radius:10px;
    padding:9px 12px; font-size:12px;
}
.arrow { color:var(--blue); }
.ok {
    padding:12px 14px; background:#10291d; border:1px solid #1c5a39;
    border-radius:12px; color:var(--green); margin-top:10px;
}
.warn {
    padding:12px 14px; background:#302812; border:1px solid #5a4b1d;
    border-radius:12px; color:var(--yellow); margin-top:10px;
}
.muted { color:var(--muted); }
details { margin-top:12px; }
summary { cursor:pointer; color:#b8c8f0; }
.footer { text-align:center; color:var(--muted); margin-top:20px; font-size:12px; }
@media(max-width:800px) {
    .grid { grid-template-columns:repeat(2,1fr); }
    .form { flex-direction:column; }
    button { padding:14px; }
}
</style>
</head>
<body>
<div class="container">
    <div class="hero">
        <h1>ð Spring Project Inspector</h1>
        <p>Dependency conflicts â¢ Parent POM â¢ BOM â¢ Version inheritance</p>
        <span class="badge">ð READ-ONLY â NO FILE CHANGES</span>

        <div class="form">
            <input id="path" placeholder="/Users/yourname/Projects/my-spring-project">
            <button id="scan" onclick="scan()">Analyse Project</button>
        </div>
    </div>

    <div id="output"></div>
    <div class="footer">Local only â¢ No Python packages â¢ No external API</div>
</div>

<script>
function esc(value) {
    return String(value ?? "")
        .replaceAll("&","&amp;").replaceAll("<","&lt;")
        .replaceAll(">","&gt;").replaceAll('"',"&quot;");
}

function flow(items) {
    return items.map((x,i) =>
        (i ? '<span class="arrow">â</span>' : '') +
        '<span class="node">' + esc(x) + '</span>'
    ).join("");
}

async function scan() {
    const path = document.getElementById("path").value.trim();
    const button = document.getElementById("scan");

    if (!path) {
        alert("Enter a project path.");
        return;
    }

    button.disabled = true;
    button.textContent = "Scanning...";

    document.getElementById("output").innerHTML =
        '<div class="section"><h2>â³ Analysing project...</h2>' +
        '<div class="muted">Read-only scan. Nothing will be changed.</div></div>';

    try {
        const response = await fetch("/api/scan", {
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body:JSON.stringify({path})
        });

        const data = await response.json();

        if (!response.ok) throw new Error(data.error || "Scan failed");

        render(data);
    } catch (e) {
        document.getElementById("output").innerHTML =
            '<div class="section">' +
            '<div class="issue"><div class="issue-title">â Scan failed</div>' +
            '<p>' + esc(e.message) + '</p></div></div>';
    } finally {
        button.disabled = false;
        button.textContent = "Analyse Project";
    }
}

function render(d) {
    const conflicts = d.conflicts || [];
    const warnings = d.warnings || [];
    const passed = d.passed || [];
    const inheritance = d.inheritance || [];

    let conflictHtml = conflicts.length
        ? conflicts.map(c => `
            <div class="issue">
                <div class="issue-title">ð´ ${esc(c.dependency)}</div>
                <div class="row">
                    ${c.versions.map(v => `<span class="chip">${esc(v)}</span>`).join("")}
                </div>
                ${c.details.map(x => `<p class="muted">${esc(x)}</p>`).join("")}
            </div>
          `).join("")
        : '<div class="ok">â No version conflicts found in the analysed POM.</div>';

    let inheritanceHtml = inheritance.length
        ? inheritance.map(x => `
            <div class="section" style="margin-top:12px;background:#0e1526">
                <div class="issue-title">ð¡ ${esc(x.dependency)}</div>
                <p><b>Resolved:</b> ${esc(x.selectedVersion)}</p>
                <div class="flow">${flow(x.path)}</div>
            </div>
          `).join("")
        : '<div class="muted">No direct dependency inheritance cases found.</div>';

    const parentChain = (d.parentChain || []).map(p =>
        `${p.groupId}:${p.artifactId}:${p.version}`
    );

    const score = Math.max(0, 100 - conflicts.length * 15 - warnings.length * 5);

    document.getElementById("output").innerHTML = `
        <div class="grid">
            <div class="card">
                <div class="label">PROJECT HEALTH</div>
                <div class="num ${score >= 80 ? "green" : score >= 60 ? "yellow" : "red"}">${score}/100</div>
            </div>
            <div class="card">
                <div class="label">CONFLICTS</div>
                <div class="num red">${conflicts.length}</div>
            </div>
            <div class="card">
                <div class="label">WARNINGS</div>
                <div class="num yellow">${warnings.length}</div>
            </div>
            <div class="card">
                <div class="label">DEPENDENCIES</div>
                <div class="num">${(d.dependencies || []).length}</div>
            </div>
        </div>

        <div class="section">
            <h2>ð¦ ${esc(d.projectName)}</h2>
            <div class="project-path">${esc(d.path)}</div>
            <div class="row">
                <span class="chip">${esc(d.type)}</span>
                <span class="chip">Java ${esc(d.javaVersion || "not detected")}</span>
                <span class="chip">Spring Boot ${esc(d.springBootVersion || "not detected")}</span>
            </div>
        </div>

        <div class="section">
            <h2>ð´ Dependency Conflicts</h2>
            ${conflictHtml}
        </div>

        <div class="section">
            <h2>ð§¬ Version Inheritance</h2>
            ${inheritanceHtml}
        </div>

        <div class="section">
            <h2>ð Parent POM Chain</h2>
            ${
                parentChain.length
                ? `<div class="flow">${flow(parentChain)}</div>`
                : '<div class="muted">No locally resolvable parent POM chain.</div>'
            }
        </div>

        <div class="section">
            <h2>â  Warnings</h2>
            ${
                warnings.length
                ? warnings.map(x => `<div class="warn">â  ${esc(x)}</div>`).join("")
                : '<div class="ok">â No warnings.</div>'
            }
        </div>

        <div class="section">
            <h2>ð¢ Passed Checks</h2>
            ${
                passed.length
                ? passed.map(x => `<div class="ok">â ${esc(x)}</div>`).join("")
                : '<div class="muted">No additional checks.</div>'
            }
        </div>

        <div class="section">
            <h2>ð Safety</h2>
            <div class="ok">
                Read-only analysis. The scanner does not create, delete, modify,
                format, commit, or push anything in the target project.
            </div>
        </div>
    `;
}
</script>
</body>
</html>
"""
class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Keep terminal output clean.
        pass

    def send_json(self, payload, status=200):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path in ("/", "/index.html"):
            data = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path != "/api/scan":
            self.send_json({"error": "Not found"}, 404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 1024 * 1024:
                raise ValueError("Request too large.")

            body = self.rfile.read(length)
            request = json.loads(body.decode("utf-8"))

            project_path = request.get("path", "").strip()

            if not project_path:
                raise ValueError("Project path is required.")

            result = analyse(project_path)

            self.send_json(result)

        except Exception as exc:
            self.send_json({"error": str(exc)}, 400)


def find_free_port(start=8080):
    for port in range(start, start + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((HOST, port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free local port found.")


def main():
    global PORT
    PORT = find_free_port(PORT)

    server = ThreadingHTTPServer((HOST, PORT), Handler)

    print()
    print("â­âââââââââââââââââââââââââââââââââââââââââââââââ®")
    print("â        ð SPRING PROJECT INSPECTOR           â")
    print("â°âââââââââââââââââââââââââââââââââââââââââââââââ¯")
    print()
    print("  ð READ-ONLY MODE")
    print("  No project files will be modified.")
    print()
    print(f"  Open: http://{HOST}:{PORT}")
    print()
    print("  Press Ctrl+C to stop.")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

