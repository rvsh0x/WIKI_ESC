#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author : rvsh0x - Rachid Ghodbane
# Wiki_esc.py — Privilege Escalation Framework (Shell Base)
#
# Cet outil est fourni a des fins educatives et de recherche en securite informatique uniquement.
# L'utilisation de ce script sur des systemes sans autorisation explicite et prealable de leur proprietaire est :
#
#    x  Illegale dans la majorite des juridictions mondiales
#    x  Passible de poursuites penales et/ou civiles
#    x  Contraire aux chartes d usage des systemes informatiques
#
#  >  Utilisez uniquement sur vos propres systemes ou dans le cadre d'un pentest avec accord écrit du proprietaire
#
#  L'auteur rvsh0x - Rachid Ghodbane et les contributeurs declinent toute responsabilite quant a l'usage illegal ou malveillant de cet outil.
#  Vous etes seul(e) responsable de vos actes.
#

import json
import os
import re
import shlex
import shutil
import sys
import time
import subprocess

# ─── ANSI Colors ────────────────────────────────────────────────────────────────
R  = "\033[91m"
Y  = "\033[93m"
G  = "\033[92m"
C  = "\033[96m"
W  = "\033[97m"
DIM= "\033[2m"
B  = "\033[1m"
RST= "\033[0m"

# ─── Global lang ────────────────────────────────────────────────────────────────
LANG = "FR"   # default, overwritten by choose_lang()

# ─── Helpers ────────────────────────────────────────────────────────────────────
def clear():
    os.system("clear" if os.name != "nt" else "cls")

def typewriter(text, delay=0.012):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def t(fr, en):
    """Return fr or en string depending on global LANG."""
    return en if LANG == "EN" else fr

def _run_cmd(argv, timeout=25):
    """Run a command argv list; return combined stdout/stderr or error placeholder."""
    try:
        r = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "LANG": "C", "LC_ALL": "C"},
        )
        out = (r.stdout or "").strip()
        err = (r.stderr or "").strip()
        if r.returncode == 0:
            return out if out else (err if err else "")
        if out and err:
            return f"{out}\n{err}"
        return out or err or t("(sortie vide, code {code})", "(empty output, code {code})").format(code=r.returncode)
    except FileNotFoundError:
        return t("(commande absente)", "(command not found)")
    except subprocess.TimeoutExpired:
        return t("(delai depasse)", "(timeout)")
    except OSError as e:
        return t("(erreur: {e})", "(error: {e})").format(e=e)

def _output_cmd_missing(text):
    return "(commande absente)" in text or "(command not found)" in text

def _read_file_head(path, max_bytes=16000, max_lines=400):
    """Read beginning of a file safely for display."""
    try:
        with open(path, "rb") as f:
            raw = f.read(max_bytes)
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()
        if len(lines) > max_lines:
            lines = lines[:max_lines]
            extra = t("\n... (tronque)", "\n... (truncated)")
        else:
            extra = ""
        return "\n".join(lines) + extra
    except OSError as e:
        return t("(lecture impossible: {e})", "(cannot read: {e})").format(e=e)

def _section_title(fr, en):
    bar = "─" * 58
    return f"\n{C}{B}{bar}\n  {t(fr, en)}\n{bar}{RST}\n"

def _print_block(label_fr, label_en, body):
    if not (body and str(body).strip()):
        body = t("(aucune donnee)", "(no data)")
    print(f"{W}{t(label_fr, label_en)}{RST}\n{DIM}{body}{RST}\n")

# ─── Local command catalog (vectors_commands.json) — no auto-exploitation ─────
_VECTORS_CATALOG_CACHE = None  # lazy: dict or {}

# Binaires souvent interessants en SUID / shell (indicateur visuel seulement).
_COMMON_SUID_MARKERS = frozenset({
    "find", "vim", "nvim", "nano", "less", "more", "man", "awk", "sed", "grep",
    "cp", "mv", "chmod", "chown", "tar", "zip", "gzip", "xz", "ar", "dd",
    "sh", "bash", "dash", "zsh", "python", "python2", "python3", "perl", "ruby",
    "php", "node", "lua", "tclsh", "wish", "openssl", "socat", "nmap", "gdb",
    "strace", "ltrace", "mawk", "gawk", "rsync", "scp", "ftp", "mysql",
    "sqlite3", "docker", "podman", "pkexec", "su", "sudo", "mount", "umount",
    "systemctl", "journalctl", "passwd", "chfn", "chsh", "newgrp", "watch",
    "emacs", "tee", "nice", "timeout", "taskset", "stdbuf", "env", "run-parts",
})

_VECTOR_FN_FR = {
    "shell": "shell",
    "file-read": "lecture de fichier",
    "file-write": "ecriture de fichier",
    "reverse-shell": "shell inverse",
    "bind-shell": "shell en ecoute",
    "download": "telechargement",
    "upload": "envoi de fichier",
    "library-load": "chargement de bibliotheque",
    "inherit": "heritage (alias)",
    "command": "commande",
    "privilege-escalation": "escalade de privileges",
}
_VECTOR_FN_EN = {
    "shell": "shell",
    "file-read": "file read",
    "file-write": "file write",
    "reverse-shell": "reverse shell",
    "bind-shell": "bind shell",
    "download": "download",
    "upload": "upload",
    "library-load": "library load",
    "inherit": "inherit (alias)",
    "command": "command",
    "privilege-escalation": "privilege escalation",
}
_VECTOR_CTX_FR = {
    "sudo": "sudo",
    "suid": "SUID",
    "unprivileged": "sans privileges",
    "capabilities": "capabilities (fichiers)",
    "general": "general",
}
_VECTOR_CTX_EN = {
    "sudo": "sudo",
    "suid": "SUID",
    "unprivileged": "unprivileged",
    "capabilities": "capabilities (files)",
    "general": "general",
}

def _vector_function_label(name):
    key = str(name).strip().lower()
    tab = _VECTOR_FN_FR if LANG == "FR" else _VECTOR_FN_EN
    return tab.get(key, str(name))

def _vector_context_label(name):
    raw = str(name).strip().lower()
    if not raw or raw == "?":
        return "?"
    if "." in raw:
        sep = t(" / ", " / ")
        return sep.join(_vector_context_label_single(p) for p in raw.split("."))
    return _vector_context_label_single(raw)

def _vector_context_label_single(key):
    tab = _VECTOR_CTX_FR if LANG == "FR" else _VECTOR_CTX_EN
    return tab.get(key, key)

def _vectors_catalog_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors_commands.json")

def _load_vectors_catalog():
    """Load vectors_commands.json next to this script; empty dict if missing or invalid."""
    global _VECTORS_CATALOG_CACHE
    if _VECTORS_CATALOG_CACHE is not None:
        return _VECTORS_CATALOG_CACHE
    try:
        with open(_vectors_catalog_path(), encoding="utf-8") as f:
            _VECTORS_CATALOG_CACHE = json.load(f)
        if not isinstance(_VECTORS_CATALOG_CACHE, dict):
            _VECTORS_CATALOG_CACHE = {}
        _VECTORS_CATALOG_CACHE.setdefault("binaries", {})
    except (OSError, ValueError, json.JSONDecodeError):
        _VECTORS_CATALOG_CACHE = {}
    return _VECTORS_CATALOG_CACHE

def _vectors_catalog_has_data():
    c = _load_vectors_catalog()
    return bool((c.get("binaries") or {}))

def _entries_for_binary_slug(slug):
    slug = (slug or "").strip().lower()
    if not slug:
        return []
    b = (_load_vectors_catalog().get("binaries") or {})
    return list(b.get(slug, ()))

def _pick_catalog_entries(entries, prefer_suid=True):
    if not entries:
        return []
    ctx = lambda e: str(e.get("context", "")).lower()
    if prefer_suid:
        suid_rows = [e for e in entries if ctx(e) == "suid" or ctx(e).endswith(".suid")]
        if suid_rows:
            return suid_rows
    fn = lambda e: str(e.get("function", "")).lower()
    pref = [e for e in entries if fn(e) in ("shell", "reverse-shell", "bind-shell", "file-write", "sudo", "su")]
    return pref[:40] if pref else entries[:40]

def _format_catalog_excerpt(slug, max_blocks=10, max_code=1200):
    rows = _pick_catalog_entries(_entries_for_binary_slug(slug), prefer_suid=True)
    if not rows:
        return ""
    lines = []
    for e in rows[:max_blocks]:
        fn = e.get("function", "?")
        cx = e.get("context", "?")
        code = e.get("code") or ""
        if len(code) > max_code:
            code = code[:max_code] + t("...[tronque]", "...[truncated]")
        lines.append(
            t(
                f"  Fonction : {_vector_function_label(fn)} — Contexte : {_vector_context_label(cx)}",
                f"  Function: {_vector_function_label(fn)} — Context: {_vector_context_label(cx)}",
            )
        )
        lines.append(code)
        cm = e.get("comment")
        if cm:
            lines.append(t(f"  Remarque : {cm}", f"  Note: {cm}"))
        lines.append("")
    return "\n".join(lines).rstrip()

def _vectors_catalog_notice():
    if _vectors_catalog_has_data():
        return t(
            "Fichier vectors_commands.json : commandes associees aux vecteurs d attaque (reference technique). "
            "Ne executez aucune commande sans cadre legal et autorisation explicite.",
            "vectors_commands.json: commands tied to attack vectors (technical reference). "
            "Do not run any command without legal scope and explicit authorization.",
        )
    return t(
        "Fichier vectors_commands.json absent : seuls les chemins des binaires sont listes. "
        "Pour generer les extraits de vecteurs : python3 build_vectors_catalog.py --src <repertoire_yaml>. "
        "Ce script ne lance aucune exploitation automatique.",
        "vectors_commands.json missing: only binary paths are listed. "
        "To generate vector excerpts: python3 build_vectors_catalog.py --src <yaml_dir>. "
        "This script does not run automatic exploitation.",
    )

def _format_suid_vector_paths(paths, max_show=80):
    """Paths on disk + optional command excerpts from vectors_commands.json."""
    uniq = sorted(set(paths))
    lines = []
    has_cat = _vectors_catalog_has_data()
    for p in uniq[:max_show]:
        slug = os.path.basename(p).lower()
        mark = f" {G}*{RST}" if slug in _COMMON_SUID_MARKERS else ""
        lines.append(f"{W}{p}{mark}{RST}")
        if has_cat:
            ex = _format_catalog_excerpt(slug, max_blocks=8, max_code=1000)
            if ex:
                lines.append(f"  {DIM}{ex}{RST}")
            else:
                lines.append(
                    f"  {DIM}{t('(pas d entree catalogue pour ce nom)', '(no catalog entry for this name)')}{RST}"
                )
    if len(uniq) > max_show:
        lines.append(
            t(f"... et {len(uniq) - max_show} autre(s) non affiche(s).", f"... and {len(uniq) - max_show} more not shown.")
        )
    return "\n".join(lines) if lines else t("(aucun)", "(none)")

def _find_special_bits(perm_flag):
    """perm_flag: '-4000' SUID or '-2000' SGID; limited paths for speed."""
    roots = ["/usr/bin", "/bin", "/sbin", "/usr/sbin", "/usr/local/bin"]
    roots = [p for p in roots if os.path.isdir(p)]
    if not roots:
        return []
    try:
        r = subprocess.run(
            ["find"] + roots + ["-xdev", "-type", "f", "-perm", perm_flag],
            capture_output=True,
            text=True,
            timeout=45,
            env={**os.environ, "LANG": "C", "LC_ALL": "C"},
        )
        paths = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
        return sorted(set(paths))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []

def _docker_quick_probe():
    if not shutil.which("docker"):
        return None
    info = _run_cmd(["docker", "info"], timeout=5)
    if "Cannot connect" in info or "permission denied" in info.lower():
        return t("Docker present mais daemon inaccessible ou droits insuffisants", "Docker present but daemon unreachable or permission denied")
    if info and not _output_cmd_missing(info):
        return t("Docker repond (daemon joignable)", "Docker responds (daemon reachable)")
    return t("Binaire docker trouve", "Docker binary found")

def _capabilities_excerpt():
    out = _run_cmd(["getcap", "-r", "/usr/bin"], timeout=20)
    if _output_cmd_missing(out) or not out.strip():
        out = _run_cmd(["getcap", "-r", "/bin"], timeout=15)
    if _output_cmd_missing(out):
        return ""
    lines = [ln for ln in out.splitlines() if ln.strip()]
    return "\n".join(lines[:60]) + (t("\n... (tronque)", "\n... (truncated)") if len(lines) > 60 else "")

def _enumerate_path_writable():
    hits = []
    for p in os.environ.get("PATH", "").split(os.pathsep):
        if not p:
            continue
        try:
            if os.path.isdir(p) and os.access(p, os.W_OK):
                hits.append(p)
        except OSError:
            continue
    if not hits:
        return t("(aucun repertoire du PATH en ecriture)", "(no writable PATH directories)")
    return "\n".join(hits)

def _extract_sudo_binary_paths(sudo_text):
    if not sudo_text or _output_cmd_missing(sudo_text):
        return []
    found = []
    for m in re.finditer(r"(/[\w./-]{2,})", sudo_text):
        p = m.group(1).rstrip("),;:")
        if "/" not in p[1:]:
            continue
        if os.path.basename(p) and len(p) >= 4:
            found.append(p)
    seen = set()
    out = []
    for p in found:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out[:40]

# ─── System enumeration (module 1) ─────────────────────────────────────────────
_NOLOGIN_SHELLS = frozenset({
    "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false",
    "/bin/true", "/usr/bin/true",
})

def _enumerate_login_shell_users():
    users = []
    try:
        with open("/etc/passwd", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                shell = parts[6]
                if shell in _NOLOGIN_SHELLS:
                    continue
                users.append((parts[0], int(parts[2]) if parts[2].isdigit() else parts[2], shell))
    except OSError:
        return t("(impossible de lire /etc/passwd)", "(cannot read /etc/passwd)")
    if not users:
        return t("(aucun compte avec shell de connexion)", "(no interactive login shells)")
    lines = [f"{'USER':<16} {'UID':<8} SHELL"]
    for u, uid, sh in sorted(users, key=lambda x: (isinstance(x[1], int), x[1], x[0])):
        uid_s = str(uid)
        lines.append(f"{u:<16} {uid_s:<8} {sh}")
    return "\n".join(lines)

def _enumerate_sudo_list():
    out = _run_cmd(["sudo", "-n", "-l"], timeout=8)
    low = out.lower()
    if "password is required" in low or "a password is required" in low:
        return t(
            "sudo demande un mot de passe (-n refuse). Tester manuellement: sudo -l",
            "sudo requires a password (-n fails). Try manually: sudo -l",
        )
    return out

def module_system_enumeration():
    """Collect read-only system context useful for privilege escalation review."""
    print(_section_title(
        "ENUMERATION SYSTEME",
        "SYSTEM ENUMERATION",
    ))
    print(f"{DIM}{t('Lecture seule / commandes locales — resultats du systeme courant.', 'Read-only / local commands — results from current host.')}{RST}\n")

    _print_block("Noyau (uname -a)", "Kernel (uname -a)", _run_cmd(["uname", "-a"]))
    _print_block("/etc/os-release", "/etc/os-release", _read_file_head("/etc/os-release", max_lines=80))
    if os.path.exists("/proc/version"):
        _print_block("/proc/version", "/proc/version", _read_file_head("/proc/version", max_lines=5))

    hn_short = _run_cmd(["hostname"])
    _print_block("Hote (hostname)", "Host (hostname)", hn_short)
    hn_f = _run_cmd(["hostname", "-f"])
    if hn_f.strip() and hn_f.strip() != hn_short.strip():
        _print_block("FQDN (hostname -f)", "FQDN (hostname -f)", hn_f)
    _print_block("Utilisateur / groupe effectifs", "Effective user / groups", _run_cmd(["id"]))
    _print_block("Qui suis-je (whoami)", "Whoami", _run_cmd(["whoami"]))
    _print_block("Sessions (who)", "Sessions (who)", _run_cmd(["who"]))

    checks = []
    for label_fr, label_en, path in (
        ("/etc/passwd", "/etc/passwd", "/etc/passwd"),
        ("/etc/shadow", "/etc/shadow", "/etc/shadow"),
        ("/etc/sudoers", "/etc/sudoers", "/etc/sudoers"),
    ):
        try:
            w = os.path.isfile(path) and os.access(path, os.W_OK)
            r = os.path.isfile(path) and os.access(path, os.R_OK)
            checks.append(f"{path}: read={r} write={w}")
        except OSError as e:
            checks.append(f"{path}: ({e})")
    _print_block(
        "Fichiers sensibles (lecture/ecriture)",
        "Sensitive files (read/write)",
        "\n".join(checks),
    )

    _print_block("sudo -n -l (sans mot de passe)", "sudo -n -l (non-interactive)", _enumerate_sudo_list())
    _print_block("PATH", "PATH", os.environ.get("PATH", t("(non defini)", "(not set)")))
    _print_block(
        "Repertoires du PATH en ecriture",
        "Writable PATH directories",
        _enumerate_path_writable(),
    )
    _print_block(
        "Comptes avec shell de connexion (/etc/passwd)",
        "Users with login shells (/etc/passwd)",
        _enumerate_login_shell_users(),
    )
    _print_block("Espace disque (df -h)", "Disk free (df -h)", _run_cmd(["df", "-h"]))
    if os.path.exists("/proc/mounts"):
        _print_block(
            "Montages (/proc/mounts, extrait)",
            "Mounts (/proc/mounts, excerpt)",
            _read_file_head("/proc/mounts", max_lines=40),
        )

    ip_br = _run_cmd(["ip", "-br", "a"], timeout=15)
    if _output_cmd_missing(ip_br):
        ip_br = _run_cmd(["ifconfig", "-a"], timeout=15)
    _print_block("Interfaces reseau", "Network interfaces", ip_br)
    route_out = _run_cmd(["ip", "route"], timeout=10)
    if _output_cmd_missing(route_out):
        route_out = _run_cmd(["route", "-n"], timeout=10)
    _print_block("Routage", "Routing", route_out)

    listeners = _run_cmd(["ss", "-tuln"], timeout=15)
    if _output_cmd_missing(listeners):
        listeners = _run_cmd(["netstat", "-tuln"], timeout=15)
    _print_block("Sockets en ecoute (ss/netstat)", "Listening sockets (ss/netstat)", listeners)

    ps_out = _run_cmd(["ps", "auxww"], timeout=20)
    lines = ps_out.splitlines()
    if len(lines) > 35:
        ps_out = "\n".join(lines[:35]) + t("\n... (tronque, utiliser ps auxww)", "\n... (truncated, use ps auxww)")
    _print_block("Processus (extrait ps auxww)", "Processes (ps auxww excerpt)", ps_out)

    if os.path.isfile("/etc/crontab"):
        _print_block(
            "/etc/crontab (extrait)",
            "/etc/crontab (excerpt)",
            _read_file_head("/etc/crontab", max_lines=30),
        )

    print(f"\n{G}{t('Enumeration terminee.', 'Enumeration complete.')}{RST}\n")

def module_suid_sgid_vectors():
    """
    Liste SUID/SGID et extraits de commandes depuis vectors_commands.json si present.
    Aucune tentative d escalade automatique (pas d execution de payloads).
    """
    print(_section_title(
        "VECTEURS D ATTAQUE — SUID / SGID",
        "ATTACK VECTORS — SUID / SGID",
    ))
    print(
        f"{Y}{t('Rappel :', 'Reminder:')}{RST} "
        f"{t('aucune exploitation automatique, pas de « try until root ». '
            'Detection et extraits des vecteurs (fichier catalogue local optionnel).',
            'no automatic exploitation, no « try until root ». '
            'Detection and vector excerpts only (optional local catalog file).')}{RST}\n"
    )
    suid = _find_special_bits("-4000")
    _print_block(
        "Binaires SUID (scan rapide)",
        "SUID binaries (quick scan)",
        "\n".join(suid) if suid else t("(aucun dans les repertoires parcourus)", "(none in scanned directories)"),
    )
    if suid:
        _print_block(
            "Commandes catalogue — vecteur SUID",
            "Catalog commands — SUID vector",
            _vectors_catalog_notice() + "\n\n" + _format_suid_vector_paths(suid),
        )

    sgid = _find_special_bits("-2000")
    _print_block(
        "Binaires SGID (scan rapide)",
        "SGID binaries (quick scan)",
        "\n".join(sgid) if sgid else t("(aucun dans les repertoires parcourus)", "(none in scanned directories)"),
    )
    if sgid:
        _print_block(
            "Commandes catalogue — vecteur SGID",
            "Catalog commands — SGID vector",
            t(
                "Meme logique que pour SUID : priorite aux lignes « suid » du catalogue, sinon shell / lecture-ecriture fichier.",
                "Same logic as SUID: prefer « suid » rows in the catalog, else shell / file read-write.",
            )
            + "\n\n"
            + _format_suid_vector_paths(sgid),
        )

    print(f"\n{G}{t('Module vecteurs SUID/SGID termine.', 'SUID/SGID vectors module complete.')}{RST}\n")


# ─── Module 9 — Auto PrivEsc step-by-step (documentation uniquement) ────────────

_SEV_COLORS   = {0: R, 1: Y, 2: Y, 3: C}
_SEV_LABEL_FR = {0: "CRITIQUE", 1: "ELEVE", 2: "MOYEN", 3: "INFO"}
_SEV_LABEL_EN = {0: "CRITICAL", 1: "HIGH",  2: "MEDIUM", 3: "INFO"}

def _sev_label(sev):
    return (_SEV_LABEL_FR if LANG == "FR" else _SEV_LABEL_EN).get(sev, "?")

def _build_findings():
    """
    Collecte tous les vecteurs detectables en lecture seule.
    Retourne une liste de dicts triee par severite (0=critique → 3=info).
    Aucune commande offensive n'est lancee.
    """
    findings = []

    def add(sev, title_fr, title_en, what, why_fr, why_en, verify, catalog=None):
        findings.append({
            "severity": sev,
            "title":  t(title_fr, title_en),
            "what":   what,
            "why":    t(why_fr, why_en),
            "verify": verify,
            "catalog": catalog,
        })

    # ── fichiers sensibles en ecriture ───────────────────────────────────────
    for path in ("/etc/passwd", "/etc/shadow", "/etc/sudoers"):
        try:
            if os.path.isfile(path) and os.access(path, os.W_OK):
                add(
                    0,
                    f"Ecriture possible : {path}",
                    f"Writable: {path}",
                    t(
                        f"Le fichier {path} est accessible en ecriture par l'utilisateur courant.",
                        f"File {path} is writable by the current user.",
                    ),
                    f"Un {path} modifiable permet une escalade directe "
                    f"(ajout compte root, modification regles sudo, acces aux hashs).",
                    f"A writable {path} allows direct privilege escalation "
                    f"(add root account, modify sudo rules, access password hashes).",
                    f"ls -la {path}\nstat {path}",
                )
        except OSError:
            pass

    # ── sudo ──────────────────────────────────────────────────────────────────
    sudo_raw = _run_cmd(["sudo", "-n", "-l"], timeout=8)
    low = sudo_raw.lower()
    has_nopasswd = (
        ("nopasswd" in low or "nopassword" in low)
        and "password is required" not in low
        and "a password is required" not in low
        and not _output_cmd_missing(sudo_raw)
    )
    has_review = (
        sudo_raw.strip()
        and not _output_cmd_missing(sudo_raw)
        and "password is required" not in low
        and "a password is required" not in low
    )
    if has_nopasswd:
        cat_lines = []
        for fp in _extract_sudo_binary_paths(sudo_raw):
            slug = os.path.basename(fp).lower()
            ex = _format_catalog_excerpt(slug, max_blocks=3, max_code=800)
            if ex:
                cat_lines.append(f"{W}{fp}{RST}\n{DIM}{ex}{RST}")
        add(
            0,
            "sudo — regles NOPASSWD detectees",
            "sudo — NOPASSWD rules detected",
            sudo_raw,
            "Regles sudo sans mot de passe : execution en tant que root ou autre "
            "utilisateur sans authentification.",
            "Password-less sudo rules allow running commands as root or another "
            "user without authentication.",
            "sudo -l",
            "\n\n".join(cat_lines) if cat_lines else None,
        )
    elif has_review:
        add(
            1,
            "sudo — sortie a examiner manuellement",
            "sudo — output worth reviewing",
            sudo_raw,
            "La sortie de sudo -n -l contient des informations sur les droits sudo "
            "(un mot de passe peut etre requis).",
            "sudo -n -l output contains sudo privilege info "
            "(a password may be required; verify manually).",
            "sudo -l",
        )

    # ── PATH en ecriture ──────────────────────────────────────────────────────
    pw_raw = _enumerate_path_writable()
    pw_l = pw_raw.lower()
    if "aucun repertoire" not in pw_l and "no writable" not in pw_l:
        first_dir = pw_raw.splitlines()[0] if pw_raw.strip() else ""
        add(
            1,
            "Repertoires du PATH en ecriture",
            "Writable PATH directories",
            pw_raw,
            "Un repertoire du PATH en ecriture permet de substituer un binaire "
            "legitime (PATH hijacking).",
            "A writable PATH directory allows substituting a legitimate binary "
            "(PATH hijacking).",
            f"echo $PATH\nls -la {first_dir}",
        )

    # ── SUID ──────────────────────────────────────────────────────────────────
    for p in _find_special_bits("-4000"):
        slug = os.path.basename(p).lower()
        notable = slug in _COMMON_SUID_MARKERS
        ex = _format_catalog_excerpt(slug, max_blocks=4, max_code=1000) if _vectors_catalog_has_data() else None
        add(
            1 if notable else 2,
            f"SUID : {p}",
            f"SUID: {p}",
            t(
                f"Bit SUID positionne{' — binaire connu interessant' if notable else ''}.",
                f"SUID bit set{' — known interesting binary' if notable else ''}.",
            ),
            "Le binaire s'execute avec les privileges de son proprietaire (souvent root). "
            "S'il autorise une sortie shell ou une lecture/ecriture fichier, il peut etre utilise pour escalader.",
            "The binary runs with its owner's privileges (often root). "
            "If it allows a shell escape or file read/write, it can be leveraged.",
            f"ls -la {p}\nstat {p}\nstrings {p} | head -n 40",
            ex if ex else None,
        )

    # ── SGID ──────────────────────────────────────────────────────────────────
    for p in _find_special_bits("-2000"):
        slug = os.path.basename(p).lower()
        ex = _format_catalog_excerpt(slug, max_blocks=3, max_code=800) if _vectors_catalog_has_data() else None
        add(
            2,
            f"SGID : {p}",
            f"SGID: {p}",
            t("Bit SGID positionne.", "SGID bit set."),
            "Le binaire s'execute avec le GID de son groupe proprietaire ; "
            "selon le groupe cela peut donner acces a des ressources sensibles.",
            "The binary runs with its owner group's GID; "
            "depending on the group this may grant access to sensitive resources.",
            f"ls -la {p}\nstat {p}",
            ex if ex else None,
        )

    # ── Capabilities ──────────────────────────────────────────────────────────
    caps = _capabilities_excerpt()
    if caps.strip():
        add(
            2,
            "Capabilities fichiers detectees",
            "File capabilities detected",
            caps,
            "Certaines capabilities (cap_setuid, cap_net_raw…) accordees a un binaire "
            "peuvent permettre une escalade sans bit SUID.",
            "Certain capabilities (cap_setuid, cap_net_raw…) granted to a binary "
            "may allow privilege escalation without the SUID bit.",
            "getcap -r /usr 2>/dev/null\ngetcap -r /bin 2>/dev/null",
        )

    # ── Docker ────────────────────────────────────────────────────────────────
    dock = _docker_quick_probe()
    if dock:
        add(
            3,
            "Docker detecte",
            "Docker detected",
            dock,
            "Si l'utilisateur peut communiquer avec le daemon Docker, il est possible "
            "de monter le systeme de fichiers hote dans un conteneur.",
            "If the current user can talk to the Docker daemon, the host filesystem "
            "can be mounted inside a container.",
            "docker ps\ndocker images\ngroups | grep docker",
        )

    findings.sort(key=lambda f: f["severity"])
    return findings

def _print_finding_screen(idx, total, f):
    """Affiche un finding sur ecran plein."""
    sev   = f["severity"]
    color = _SEV_COLORS[sev]
    label = _sev_label(sev)
    bar   = "─" * 58

    print(f"\n{color}{B}{bar}{RST}")
    print(f"{color}{B}  [{label}]  {t(f'Etape {idx}/{total}', f'Step {idx}/{total}')}{RST}")
    print(f"{W}{B}  {f['title']}{RST}")
    print(f"{color}{B}{bar}{RST}\n")

    print(f"{W}{B}{t('DETECTE', 'DETECTED')}{RST}")
    print(f"{DIM}{f['what']}{RST}\n")

    print(f"{W}{B}{t('POURQUOI C EST INTERESSANT', 'WHY IT MATTERS')}{RST}")
    print(f"{f['why']}\n")

    print(f"{W}{B}{t('VERIFICATION MANUELLE', 'MANUAL VERIFICATION')}{RST}")
    for line in f["verify"].splitlines():
        print(f"  {G}${RST} {DIM}{line}{RST}")
    print()

    if f.get("catalog"):
        print(f"{W}{B}{t('REFERENCE CATALOGUE (documentation)', 'CATALOG REFERENCE (documentation)')}{RST}")
        print(f"{DIM}{f['catalog']}{RST}\n")
        print(f"{Y}{DIM}{t('Aucune commande ci-dessus n est lancee automatiquement.', 'None of the above commands are run automatically.')}{RST}\n")

def _nav_prompt(idx, total):
    """Retourne False si l'utilisateur choisit de quitter."""
    msg = t(
        f"  [{idx}/{total}]  [ENTREE] suivant   [s] sauter   [q] quitter",
        f"  [{idx}/{total}]  [ENTER] next        [s] skip     [q] quit",
    )
    ans = input(f"\n{C}{msg}{RST}  > ").strip().lower()
    return ans not in ("q", "quit", "quitter")

def _run_stepbystep():
    """Coeur du mode pas-a-pas : un finding par ecran, du plus au moins critique."""
    print(_section_title("AUTO PRIVESC — PAS A PAS", "AUTO PRIVESC — STEP BY STEP"))
    print(f"{DIM}{t('Detection en cours...', 'Running detection...')}{RST}")

    findings = _build_findings()

    ident  = _run_cmd(["id"])
    kernel = _run_cmd(["uname", "-rsmo"])
    print(f"\n{W}{t('Contexte', 'Context')}{RST}")
    if ident  and not _output_cmd_missing(ident):
        print(f"  {DIM}{t('Identite :', 'Identity:')} {ident}{RST}")
    if kernel and not _output_cmd_missing(kernel):
        print(f"  {DIM}{t('Noyau    :', 'Kernel  :')} {kernel}{RST}")

    total = len(findings)
    if total == 0:
        print(f"\n{G}{t('Aucun finding detecte.', 'No findings detected.')}{RST}\n")
        return

    print(f"\n{W}{t(f'{total} finding(s) — tries par criticite.', f'{total} finding(s) — sorted by severity.')}{RST}")
    print(f"{DIM}{t('Navigation pas a pas. Aucune commande offensive lancee.', 'Step-by-step. No offensive commands are run.')}{RST}\n")
    input(f"  {C}{t('[ENTREE] pour commencer...', '[ENTER] to start...')}{RST}")

    for idx, f in enumerate(findings, 1):
        clear()
        print(BANNER)
        print(get_subtitle())
        _print_finding_screen(idx, total, f)
        if idx < total:
            if not _nav_prompt(idx, total):
                print(f"\n{DIM}{t('Navigation interrompue.', 'Navigation interrupted.')}{RST}\n")
                return
        else:
            print(f"\n{G}{B}{t('Fin des findings.', 'End of findings.')}{RST}\n")
            input(t("  [ENTREE] pour terminer...", "  [ENTER] to finish..."))

def module_auto_privesc(verbose):
    """Mode Auto: pas-a-pas ou verbose (enumeration complete + pas-a-pas)."""
    if verbose:
        print(_section_title("AUTO PRIVESC — VERBEUX", "AUTO PRIVESC — VERBOSE"))
        print(f"{DIM}{t('Enumeration complete, puis navigation pas a pas des vecteurs.', 'Full enumeration, then step-by-step findings.')}{RST}\n")
        module_system_enumeration()
        input(t("\n  [ENTREE] pour passer aux findings...", "\n  [ENTER] to start findings..."))
        _run_stepbystep()
    else:
        _run_stepbystep()

def auto_privesc_menu(back):
    """Sub-menu: quiet vs verbose automatic privesc."""
    invalid = t("Option invalide", "Invalid option")
    while True:
        clear()
        print(BANNER)
        print(get_subtitle())
        title = t("MODE AUTO PRIVESC", "AUTO PRIVESC MODE")
        print(f"\n{C}{B}  [ {title} ]{RST}\n\n")
        print(f"  {G}[1]{W}  {t('Pas a pas — findings tries par criticite', 'Step by step — findings sorted by severity')}\n")
        print(f"  {G}[2]{W}  {t('Verbose  — enumeration complete + pas a pas', 'Verbose  — full enumeration + step by step')}\n")
        print(f"  {R}[0]{W}  {t('Retour au menu principal', 'Back to main menu')}{RST}\n")
        print(f"{C}" + "─" * 60 + f"{RST}\n")
        c = input(f"  {C}wiki_esc{RST}{W} > {RST}").strip()
        if c == "0":
            return
        if c == "1":
            clear()
            print(BANNER)
            print(get_subtitle())
            module_auto_privesc(verbose=False)
            input(back)
            return
        if c == "2":
            clear()
            print(BANNER)
            print(get_subtitle())
            module_auto_privesc(verbose=True)
            input(back)
            return
        print(f"\n  {R}[x] {invalid}.{RST}\n")
        time.sleep(0.6)


# ─── ASCII Banner ────────────────────────────────────────────────────────────────
BANNER = (
    f"\n{R}{B}"
    " ██╗    ██╗██╗██╗  ██╗██╗    ███████╗███████╗ ██████╗\n"
    " ██║    ██║██║██║ ██╔╝██║    ██╔════╝██╔════╝██╔════╝\n"
    " ██║ █╗ ██║██║█████╔╝ ██║    █████╗  ███████╗██║\n"
    " ██║███╗██║██║██╔═██╗ ██║    ██╔══╝  ╚════██║██║\n"
    " ╚███╔███╔╝██║██║  ██╗██║    ███████╗███████║╚██████╗\n"
    "  ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚═╝    ╚══════╝╚══════╝ ╚═════╝\n"
    f"{RST}"
)

# ─── Language selector ───────────────────────────────────────────────────────────
def lang_screen():
    return (
        f"\n{C}" + "─"*60 + f"\n"
        f"{W}  Select your language / Choisissez votre langue{RST}\n"
        f"{C}" + "─"*60 + f"{RST}\n\n"
        f"  {G}[1]{W}  Francais  FR\n"
        f"  {G}[2]{W}  English   EN\n\n"
        f"{C}" + "─"*60 + f"{RST}\n"
    )

def choose_lang():
    global LANG
    clear()
    print(BANNER)
    print(lang_screen())
    while True:
        choice = input(f"  {C}>{RST} ").strip()
        if choice == "1":
            LANG = "FR"
            break
        elif choice == "2":
            LANG = "EN"
            break
        else:
            print(f"  {R}Invalid / Invalide{RST}")

# ─── Subtitle ────────────────────────────────────────────────────────────────────
def get_subtitle():
    label    = t("Outil d escalade de privileges", "Privilege Escalation Framework")
    note     = t("Usage educatif uniquement",      "Educational Use Only")
    aut_lbl  = t("Auteur",  "Author")
    ver_lbl  = t("Version", "Version")
    tgt_lbl  = t("Cible",   "Target")
    return (
        f"\n{C}" + "─"*60 + f"\n"
        f"{W}  {label}  {DIM}// {note}{RST}\n"
        f"{C}" + "─"*60 + f"{RST}\n"
        f"{DIM}  {aut_lbl}   : {W}rvsh0x{RST}\n"
        f"{DIM}  {ver_lbl}  : {W}0.1-base{RST}\n"
        f"{DIM}  {tgt_lbl}    : {W}Linux / Unix{RST}\n"
        f"{C}" + "─"*60 + f"{RST}\n"
    )

# ─── Disclaimer ─────────────────────────────────────────────────────────────────
def get_disclaimer():
    sep = Y + "─"*60 + RST
    if LANG == "FR":
        return (
            f"\n{Y}{B}  {'╔' + '═'*54 + '╗'}\n"
            f"  {'║'}{'⚠  AVERTISSEMENT LEGAL  ⚠':^54}{'║'}\n"
            f"  {'╚' + '═'*54 + '╝'}{RST}\n\n"
            f"{W}  Cet outil est fourni a des fins {G}educatives et de recherche\n"
            f"  {W}en securite informatique {B}uniquement{RST}{W}.\n\n"
            f"  L utilisation de ce script sur des systemes sans autorisation\n"
            f"  {R}{B}explicite et prealable{RST}{W} de leur proprietaire est :\n\n"
            f"    {R}x{W}  Illegale dans la majorite des juridictions mondiales\n"
            f"    {R}x{W}  Passible de poursuites penales et/ou civiles\n"
            f"    {R}x{W}  Contraire aux chartes d usage des systemes informatiques\n\n"
            f"  {G}>{W}  Utilisez uniquement sur vos propres systemes ou dans le\n"
            f"      cadre d un pentest avec accord ecrit du proprietaire.\n\n"
            f"  {DIM}L auteur {W}rvsh0x{DIM} et les contributeurs declinent toute\n"
            f"  responsabilite quant a l usage illegal ou malveillant\n"
            f"  de cet outil. Vous etes seul(e) responsable de vos actes.{RST}\n\n"
            f"{sep}\n"
        )
    else:
        return (
            f"\n{Y}{B}  {'╔' + '═'*54 + '╗'}\n"
            f"  {'║'}{'⚠  LEGAL DISCLAIMER  ⚠':^54}{'║'}\n"
            f"  {'╚' + '═'*54 + '╝'}{RST}\n\n"
            f"{W}  This tool is provided for {G}educational and cybersecurity\n"
            f"  {W}research purposes {B}only{RST}{W}.\n\n"
            f"  Using this script against systems without {R}{B}explicit prior\n"
            f"  written authorization{RST}{W} from their owner is:\n\n"
            f"    {R}x{W}  Illegal in most jurisdictions worldwide\n"
            f"    {R}x{W}  Subject to criminal and/or civil prosecution\n"
            f"    {R}x{W}  A violation of computer use policies\n\n"
            f"  {G}>{W}  Only use on systems you own or have written permission\n"
            f"      to test (authorized penetration testing).\n\n"
            f"  {DIM}The author {W}rvsh0x{DIM} and contributors disclaim all liability\n"
            f"  for any illegal or malicious use of this tool.\n"
            f"  You are solely responsible for your actions.{RST}\n\n"
            f"{sep}\n"
        )

# ─── Menu ────────────────────────────────────────────────────────────────────────
def get_menu():
    title = t("MENU PRINCIPAL", "MAIN MENU")
    items = [
        t("Enumeration systeme",        "System Enumeration"),
        t("Vecteurs SUID / SGID",       "SUID / SGID Vectors"),
        t("Analyse sudo",               "Sudo Analysis"),
        t("Cron jobs",                  "Cron Jobs"),
        t("Variables d environnement",  "Environment Variables"),
        t("Capabilities Linux",         "Linux Capabilities"),
        t("NFS / partages montes",      "NFS / Mounted Shares"),
        t("Conteneurs & Docker",        "Containers & Docker"),
        t("Auto PrivEsc",               "Auto PrivEsc"),
        t("Quitter",                    "Quit"),
    ]
    lines = f"\n{C}{B}  [ {title} ]{RST}\n\n"
    for i, item in enumerate(items[:-1], 1):
        lines += f"{W}  {G}[{i}]{W}  {item}\n"
    lines += f"  {R}[0]{W}  {items[-1]}{RST}\n"
    lines += f"\n{C}" + "─"*60 + f"{RST}\n"
    return lines

# ─── Disclaimer prompt ───────────────────────────────────────────────────────────
def show_disclaimer():
    prompt_enter  = t(
        f"  Appuie sur {B}[ENTREE]{RST}{Y} pour lire le disclaimer...",
        f"  Press {B}[ENTER]{RST}{Y} to read the disclaimer..."
    )
    prompt_accept = t(
        f"  {W}J accepte les conditions et j utilise cet outil legalement {G}[o/N]{RST} : ",
        f"  {W}I accept the terms and will use this tool legally {G}[y/N]{RST} : "
    )
    denied = t(
        f"\n  {R}Acces refuse. Fermeture.{RST}\n",
        f"\n  {R}Access denied. Exiting.{RST}\n"
    )
    input(f"{Y}{prompt_enter}{RST}")
    clear()
    print(get_disclaimer())
    answer = input(prompt_accept).strip().lower()
    if answer not in ("o", "oui", "y", "yes"):
        print(denied)
        sys.exit(0)

# ─── Main menu loop ──────────────────────────────────────────────────────────────
def main_menu():
    not_impl = t("non implemente", "not implemented")
    invalid  = t("Option invalide", "Invalid option")
    bye      = t(f"  {DIM}A bientot.{RST}\n", f"  {DIM}Goodbye.{RST}\n")
    back     = t("  Appuie sur Entree pour revenir...", "  Press Enter to go back...")

    while True:
        clear()
        print(BANNER)
        print(get_subtitle())
        print(get_menu())
        choice = input(f"  {C}wiki_esc{RST}{W} > {RST}").strip()

        if choice == "0":
            print(f"\n{bye}")
            sys.exit(0)
        elif choice == "1":
            clear()
            print(BANNER)
            print(get_subtitle())
            module_system_enumeration()
            input(back)
        elif choice == "2":
            clear()
            print(BANNER)
            print(get_subtitle())
            module_suid_sgid_vectors()
            input(back)
        elif choice == "9":
            auto_privesc_menu(back)
        elif choice in [str(i) for i in range(3, 9)]:
            print(f"\n  {Y}[!] Module {choice} — {not_impl}.{RST}\n")
            input(back)
        else:
            print(f"\n  {R}[x] {invalid}.{RST}\n")
            time.sleep(0.8)

# ─── Entry point ─────────────────────────────────────────────────────────────────
def main():
    choose_lang()
    clear()
    print(BANNER)
    loading = t("  Chargement de Wiki_esc ...", "  Loading Wiki_esc ...")
    typewriter(f"{DIM}{loading}{RST}", delay=0.02)
    time.sleep(0.4)
    show_disclaimer()
    main_menu()

if __name__ == "__main__":
    main()
