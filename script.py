"""Build browser-compatible and AdGuard Home domain filtering rules."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
LOOPBACK_BLACKLIST = ipaddress.ip_network("127.0.0.0/8")
UNSPECIFIED_BLACKLIST = ipaddress.ip_address("0.0.0.0")
__all__ = ["ProcessingResult", "RuleProcessor"]


@dataclass(frozen=True)
class Rule:
    """A supported source rule and its normalized classification metadata."""

    original: str
    domain: str
    is_white: bool
    format_rank: int
    host_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None


@dataclass(frozen=True)
class ProcessingResult:
    """Structured result returned to external automation callers."""

    merged_rules: int
    blacklist_rules: int
    whitelist_rules: int
    discarded_non_public_hosts: int
    output_files: tuple[Path, Path, Path, Path]


class RuleProcessor:
    """Download, classify, clean, and write domain filtering rules.

    External programs should instantiate this class and call :meth:`run`.
    No command-line parsing or process spawning is required.
    """

    def __init__(
        self,
        root: str | Path = ROOT,
        *,
        timeout: float = 30,
        logger: Callable[[str], None] | None = print,
    ) -> None:
        self.root = Path(root).resolve()
        self.input_dir = self.root / "input"
        self.output_dir = self.root / "output"
        self.sources_file = self.input_dir / "urls.json"
        self.local_rules_file = self.input_dir / "local-rules.txt"
        if timeout <= 0:
            raise ValueError("timeout 必须大于 0")
        self.timeout = timeout
        self.logger = logger

    def run(self, *, download: bool = True) -> ProcessingResult:
        """Execute the complete pipeline and return structured statistics."""
        rules = self._collect_rules(self._load_sources(download))
        browser_black, browser_white = self._clean_browser_lists(rules)
        black, white, discarded = self._clean_lists(rules)
        output_files = (
            self.output_dir / "BlackList_Raw.txt",
            self.output_dir / "WhiteList_Raw.txt",
            self.output_dir / "BlackList.txt",
            self.output_dir / "WhiteList.txt",
        )
        self._write_browser(output_files[0], browser_black, is_white=False)
        self._write_browser(output_files[1], browser_white, is_white=True)
        self._write_final(output_files[2], black, is_white=False)
        self._write_final(output_files[3], white, is_white=True)
        result = ProcessingResult(
            merged_rules=len(rules),
            blacklist_rules=len(black),
            whitelist_rules=len(white),
            discarded_non_public_hosts=discarded,
            output_files=output_files,
        )
        self._log(
            f"完成：合并规则 {result.merged_rules} 条，最终黑名单 "
            f"{result.blacklist_rules} 条，白名单 {result.whitelist_rules} 条，"
            f"丢弃非公网 hosts {result.discarded_non_public_hosts} 条"
        )
        return result

    def _log(self, message: str) -> None:
        if self.logger is not None:
            self.logger(message)

    @staticmethod
    def _read_lines(path: Path) -> list[str]:
        if not path.exists():
            return []
        return path.read_text(encoding="utf-8-sig", errors="replace").splitlines()

    def _read_source_config(self) -> list[dict[str, Any]]:
        try:
            config = json.loads(self.sources_file.read_text(encoding="utf-8-sig"))
        except FileNotFoundError as exc:
            raise ValueError(f"规则源配置不存在: {self.sources_file}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"规则源配置不是有效 JSON: {exc}") from exc
        if not isinstance(config, dict) or not isinstance(config.get("sources"), list):
            raise ValueError("urls.json 顶层必须是包含 sources 数组的对象")
        sources: list[dict[str, Any]] = []
        for index, source in enumerate(config["sources"], 1):
            if not isinstance(source, dict):
                raise ValueError(f"urls.json sources[{index}] 必须是对象")
            name, url = source.get("name"), source.get("url")
            enabled = source.get("enabled", True)
            if not isinstance(name, str) or not name.strip():
                raise ValueError(f"urls.json sources[{index}].name 必须是非空字符串")
            if not isinstance(url, str) or urlparse(url).scheme not in {"http", "https"}:
                raise ValueError(f"urls.json sources[{index}].url 必须是 HTTP(S) URL")
            if not isinstance(enabled, bool):
                raise ValueError(f"urls.json sources[{index}].enabled 必须是布尔值")
            if enabled:
                sources.append({"name": name.strip(), "url": url})
        return sources

    def _load_sources(self, download: bool) -> list[tuple[str, list[str]]]:
        sources = [(self.local_rules_file.name, self._read_lines(self.local_rules_file))]
        if not download:
            return sources
        for source in self._read_source_config():
            name, url = source["name"], source["url"]
            try:
                request = Request(url, headers={"User-Agent": "AdGuardHome-rules/1.0"})
                with urlopen(request, timeout=self.timeout) as response:
                    charset = response.headers.get_content_charset() or "utf-8"
                    content = response.read().decode(charset, errors="replace")
                sources.append((name, content.splitlines()))
                self._log(f"[成功] 已下载 {name}")
            except (HTTPError, URLError, TimeoutError) as exc:
                self._log(f"[警告] 下载失败 {name}: {exc}")
        return sources

    @staticmethod
    def _uncomment(raw: str) -> str:
        line = raw.strip()
        if not line or line.startswith(("!", "#", "[")):
            return ""
        return re.split(r"\s+[#!]", line, maxsplit=1)[0].strip()

    @staticmethod
    def _normalize_domain(value: str) -> str | None:
        domain = value.strip().lower().rstrip(".").lstrip(".")
        if domain in {"localhost", "localhost.localdomain"}:
            return None
        try:
            ipaddress.ip_address(domain)
            return None
        except ValueError:
            return domain if DOMAIN_RE.fullmatch(domain) else None

    @staticmethod
    def _is_blacklist_host_ip(
        host_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> bool:
        return isinstance(host_ip, ipaddress.IPv4Address) and (
            host_ip == UNSPECIFIED_BLACKLIST or host_ip in LOOPBACK_BLACKLIST
        )

    @classmethod
    def _parse_rule(cls, line: str) -> Rule | None:
        parts = line.split()
        if len(parts) == 2:
            try:
                host_ip = ipaddress.ip_address(parts[0])
            except ValueError:
                pass
            else:
                domain = cls._normalize_domain(parts[1])
                if domain:
                    return Rule(
                        line,
                        domain,
                        not cls._is_blacklist_host_ip(host_ip),
                        1,
                        host_ip,
                    )
                return None
        is_white = line.startswith("@@")
        adguard = line[2:] if is_white else line
        if adguard.startswith("||"):
            domain = cls._normalize_domain(adguard[2:].split("^", 1)[0])
            return Rule(line, domain, is_white, 2) if domain else None
        domain = cls._normalize_domain(line.rstrip("^"))
        return Rule(line, domain, False, 0) if domain else None

    @classmethod
    def _collect_rules(cls, sources: list[tuple[str, list[str]]]) -> list[Rule]:
        unique = {
            line
            for _, lines in sources
            for raw in lines
            if (line := cls._uncomment(raw))
        }
        rules = [rule for line in unique if (rule := cls._parse_rule(line))]
        return sorted(rules, key=lambda rule: (
            rule.is_white, rule.format_rank, rule.domain, rule.original
        ))

    @staticmethod
    def _is_valid_final_host(rule: Rule) -> bool:
        if rule.host_ip is None:
            return True
        if RuleProcessor._is_blacklist_host_ip(rule.host_ip):
            return True
        return rule.host_ip.is_global

    @staticmethod
    def _remove_redundant_subdomains(domains: set[str]) -> list[str]:
        ordinary = {domain for domain in domains if not domain.startswith("*.")}
        kept = []
        for domain in sorted(ordinary, key=lambda item: (item.count("."), item)):
            labels = domain.split(".")
            if not any(".".join(labels[index:]) in ordinary for index in range(1, len(labels))):
                kept.append(domain)
        return sorted(kept + list(domains - ordinary))

    @classmethod
    def _clean_browser_lists(cls, rules: list[Rule]) -> tuple[list[str], list[str]]:
        valid_rules = [rule for rule in rules if cls._is_valid_final_host(rule)]
        black = {rule.domain for rule in valid_rules if not rule.is_white}
        white = {rule.domain for rule in valid_rules if rule.is_white}
        black -= white
        return sorted(black), sorted(white)

    @classmethod
    def _clean_lists(cls, rules: list[Rule]) -> tuple[list[str], list[str], int]:
        black, white = cls._clean_browser_lists(rules)
        discarded = sum(not cls._is_valid_final_host(rule) for rule in rules)
        return (
            cls._remove_redundant_subdomains(set(black)),
            cls._remove_redundant_subdomains(set(white)),
            discarded,
        )

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", newline="\n", dir=path.parent, delete=False
        ) as temporary:
            temporary.write(content.rstrip() + "\n")
            temporary_path = Path(temporary.name)
        temporary_path.replace(path)

    def _write_browser(self, path: Path, domains: list[str], is_white: bool) -> None:
        updated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
        kind, prefix = ("浏览器兼容白名单", "@@||") if is_white else ("浏览器兼容黑名单", "||")
        header = [f"! 更新时间: {updated}", f"! 类型: {kind}", f"! 规则数量: {len(domains)}", ""]
        self._atomic_write(path, "\n".join(header + [f"{prefix}{domain}^" for domain in domains]))

    def _write_final(self, path: Path, domains: list[str], is_white: bool) -> None:
        updated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
        kind, prefix = ("白名单", "@@||") if is_white else ("黑名单", "||")
        suffix = "^$important" if is_white else "^"
        header = [f"! 更新时间: {updated}", f"! 类型: {kind}", f"! 规则数量: {len(domains)}", ""]
        self._atomic_write(path, "\n".join(header + [f"{prefix}{d}{suffix}" for d in domains]))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="合并并生成 AdGuard Home 黑白名单")
    parser.add_argument("--no-download", action="store_true", help="仅处理本地规则")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    RuleProcessor().run(download=not args.no_download)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
