"""Merge rule sources and build compact AdGuard Home domain lists."""

from __future__ import annotations

import argparse
import ipaddress
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
INPUT_DIR, OUTPUT_DIR = ROOT / "input", ROOT / "output"
URLS_FILE, LOCAL_RULES_FILE = INPUT_DIR / "urls.conf", INPUT_DIR / "local-rules.txt"
DOMAIN_RE = re.compile(r"^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
HOSTS_BLOCK_IPS = {"0.0.0.0", "127.0.0.1", "::"}


@dataclass(frozen=True)
class Rule:
    original: str
    domain: str
    is_white: bool
    format_rank: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="合并并生成 AdGuard Home 黑白名单")
    parser.add_argument("--no-download", action="store_true", help="仅处理本地规则")
    return parser.parse_args()


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8-sig", errors="replace").splitlines()


def iter_sources(download: bool) -> list[tuple[str, list[str]]]:
    sources = [(LOCAL_RULES_FILE.name, read_lines(LOCAL_RULES_FILE))]
    if not download:
        return sources
    for number, raw in enumerate(read_lines(URLS_FILE), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "!")):
            continue
        if ":" not in line:
            print(f"[警告] 跳过 urls.conf 第 {number} 行：缺少冒号")
            continue
        name, url = (part.strip() for part in line.split(":", 1))
        try:
            request = Request(url, headers={"User-Agent": "AdGuardHome-rules/1.0"})
            with urlopen(request, timeout=30) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                content = response.read().decode(charset, errors="replace")
            sources.append((name, content.splitlines()))
            print(f"[成功] 已下载 {name}")
        except (HTTPError, URLError, TimeoutError) as exc:
            print(f"[警告] 下载失败 {name}: {exc}")
    return sources


def uncomment(raw: str) -> str:
    line = raw.strip()
    if not line or line.startswith(("!", "#", "[")):
        return ""
    return re.split(r"\s+[#!]", line, maxsplit=1)[0].strip()


def normalize_domain(value: str) -> str | None:
    domain = value.strip().lower().rstrip(".").lstrip(".")
    if domain in {"localhost", "localhost.localdomain"}:
        return None
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        return domain if DOMAIN_RE.fullmatch(domain) else None


def parse_rule(line: str) -> Rule | None:
    parts = line.split()
    if len(parts) == 2:
        try:
            ipaddress.ip_address(parts[0])
        except ValueError:
            pass
        else:
            domain = normalize_domain(parts[1])
            if domain:
                return Rule(line, domain, parts[0] not in HOSTS_BLOCK_IPS, 1)
            return None

    is_white = line.startswith("@@")
    adguard = line[2:] if is_white else line
    if adguard.startswith("||"):
        domain = normalize_domain(adguard[2:].split("^", 1)[0])
        return Rule(line, domain, is_white, 2) if domain else None
    domain = normalize_domain(line.rstrip("^"))
    return Rule(line, domain, False, 0) if domain else None


def collect_rules(sources: list[tuple[str, list[str]]]) -> list[Rule]:
    unique = {line for _, lines in sources for raw in lines if (line := uncomment(raw))}
    rules = [rule for line in unique if (rule := parse_rule(line))]
    return sorted(rules, key=lambda r: (r.is_white, r.format_rank, r.domain, r.original))


def remove_redundant_subdomains(domains: set[str]) -> list[str]:
    ordinary = {domain for domain in domains if not domain.startswith("*.")}
    kept = []
    for domain in sorted(ordinary, key=lambda item: (item.count("."), item)):
        labels = domain.split(".")
        if not any(".".join(labels[i:]) in ordinary for i in range(1, len(labels))):
            kept.append(domain)
    return sorted(kept + list(domains - ordinary))


def clean_lists(rules: list[Rule]) -> tuple[list[str], list[str]]:
    black = {rule.domain for rule in rules if not rule.is_white}
    white = {rule.domain for rule in rules if rule.is_white}
    black -= white  # 精确冲突由白名单优先
    return remove_redundant_subdomains(black), remove_redundant_subdomains(white)


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=path.parent, delete=False) as tmp:
        tmp.write(content.rstrip() + "\n")
        temporary_path = Path(tmp.name)
    temporary_path.replace(path)


def write_raw(filename: str, rules: list[Rule], is_white: bool) -> None:
    """Write exact-deduplicated source rules without domain cleaning."""
    selected = [rule.original for rule in rules if rule.is_white is is_white]
    kind = "白名单" if is_white else "黑名单"
    header = [f"! 类型: 未清洗{kind}", f"! 规则数量: {len(selected)}", ""]
    atomic_write(OUTPUT_DIR / filename, "\n".join(header + selected))


def write_final(filename: str, domains: list[str], is_white: bool) -> None:
    updated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    kind, prefix = ("白名单", "@@||") if is_white else ("黑名单", "||")
    suffix = "^$important" if is_white else "^"
    header = [f"! 更新时间: {updated}", f"! 类型: {kind}", f"! 规则数量: {len(domains)}", ""]
    atomic_write(OUTPUT_DIR / filename, "\n".join(header + [f"{prefix}{d}{suffix}" for d in domains]))


def main() -> int:
    args = parse_args()
    rules = collect_rules(iter_sources(download=not args.no_download))
    black, white = clean_lists(rules)
    write_raw("BlackList_Raw.txt", rules, False)
    write_raw("WhiteList_Raw.txt", rules, True)
    write_final("BlackList.txt", black, False)
    write_final("WhiteList.txt", white, True)
    print(f"完成：合并规则 {len(rules)} 条，最终黑名单 {len(black)} 条，白名单 {len(white)} 条")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
