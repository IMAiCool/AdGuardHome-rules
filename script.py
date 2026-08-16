"""Build extension-specific and AdGuard Home filtering rules."""

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

BROWSER_OUTPUT_NAMES = {
    "adguard": "AdGuard.txt",
    "adblock_plus": "AdblockPlus.txt",
    "ublock_origin": "uBlockOrigin.txt",
}
BROWSER_SPLIT_OUTPUT_NAMES = {
    "adguard": ("AdGuard_BlackList.txt", "AdGuard_WhiteList.txt"),
    "adblock_plus": ("AdblockPlus_BlackList.txt", "AdblockPlus_WhiteList.txt"),
    "ublock_origin": ("uBlockOrigin_BlackList.txt", "uBlockOrigin_WhiteList.txt"),
}
EXTENDED_RULE_MARKERS = (
    "##", "#@#", "#$#", "#@$#", "#%#", "#@%#", "#?#", "#@?#",
)
UBLOCK_ONLY_MARKERS = (
    "##+js(", "#@#+js(", "##^", "#@#^", ":remove()",
    ":remove-attr(", ":remove-class(", ":matches-path(", ":upward(",
)
ADGUARD_ONLY_MARKERS = ("#$#", "#@$#", "#%#", "#@%#", "#?#", "#@?#")
ADGUARD_ONLY_OPTIONS = {
    "app", "cookie", "extension", "hls", "inline-font", "inline-script",
    "jsonprune", "method", "network", "permissions", "referrerpolicy",
    "removeheader", "replace", "stealth", "urltransform", "xmlprune",
}
UBLOCK_ONLY_OPTIONS = {
    "denyallow", "header", "redirect", "redirect-rule", "removeparam",
    "uritransform", "urlskip",
}
ABP_COMMON_OPTIONS = {
    "1p", "3p", "collapse", "css", "document", "domain", "elemhide",
    "font", "frame", "genericblock", "generichide", "image", "match-case",
    "media", "object", "other", "ping", "popup", "script", "stylesheet",
    "subdocument", "third-party", "webrtc", "websocket", "xmlhttprequest",
    "xhr",
}
CANONICAL_OPTION_NAMES = {
    "adguard": {
        "1p": "~third-party", "3p": "third-party", "css": "stylesheet",
        "frame": "subdocument", "xhr": "xmlhttprequest",
    },
    "adblock_plus": {
        "1p": "~third-party", "3p": "third-party", "css": "stylesheet",
        "frame": "subdocument", "xhr": "xmlhttprequest",
    },
    "ublock_origin": {
        "~third-party": "1p", "third-party": "3p", "stylesheet": "css",
        "subdocument": "frame", "xmlhttprequest": "xhr",
    },
}


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
    output_files: tuple[Path, ...]
    browser_rules: tuple[tuple[str, int], ...] = ()


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
        lines = self._collect_source_lines(self._load_sources(download))
        rules = self._collect_rules(lines)
        browser_black, browser_white = self._clean_browser_lists(rules)
        black, white, discarded = self._clean_lists(rules)
        output_files = (
            self.output_dir / "BlackList_Raw.txt",
            self.output_dir / "WhiteList_Raw.txt",
            self.output_dir / "BlackList.txt",
            self.output_dir / "WhiteList.txt",
        )
        extension_files = tuple(
            self.output_dir / filename for filename in BROWSER_OUTPUT_NAMES.values()
        )
        extension_split_files = tuple(
            self.output_dir / filename
            for filenames in BROWSER_SPLIT_OUTPUT_NAMES.values()
            for filename in filenames
        )
        adguard_home_file = self.output_dir / "AdGuardHome.txt"
        self._write_browser(output_files[0], browser_black, is_white=False)
        self._write_browser(output_files[1], browser_white, is_white=True)
        self._write_final(output_files[2], black, is_white=False)
        self._write_final(output_files[3], white, is_white=True)
        self._write_adguard_home(adguard_home_file, black, white)
        browser_counts = []
        for profile, path in zip(BROWSER_OUTPUT_NAMES, extension_files):
            extension_rules = self._build_extension_rules(lines, profile)
            self._write_extension(path, extension_rules, profile)
            extension_black, extension_white = self._split_extension_rules(
                extension_rules
            )
            black_name, white_name = BROWSER_SPLIT_OUTPUT_NAMES[profile]
            self._write_extension(
                self.output_dir / black_name,
                extension_black,
                profile,
                list_kind="blacklist",
            )
            self._write_extension(
                self.output_dir / white_name,
                extension_white,
                profile,
                list_kind="whitelist",
            )
            browser_counts.extend((
                (f"{profile}_blacklist", len(extension_black)),
                (f"{profile}_whitelist", len(extension_white)),
            ))
        result = ProcessingResult(
            merged_rules=len(rules),
            blacklist_rules=len(black),
            whitelist_rules=len(white),
            discarded_non_public_hosts=discarded,
            output_files=(
                output_files
                + (adguard_home_file,)
                + extension_files
                + extension_split_files
            ),
            browser_rules=tuple(browser_counts),
        )
        self._log(
            f"完成：合并规则 {result.merged_rules} 条，最终黑名单 "
            f"{result.blacklist_rules} 条，白名单 {result.whitelist_rules} 条，"
            f"丢弃非公网 hosts {result.discarded_non_public_hosts} 条"
        )
        self._log("浏览器订阅：" + "，".join(f"{name} {count} 条" for name, count in browser_counts))
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
        if not line or line.startswith(("!", "[")):
            return ""
        if re.match(r"^#{2,}\s", line):
            return ""
        if line.startswith("#") and not line.startswith(EXTENDED_RULE_MARKERS):
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
    def _collect_source_lines(cls, sources: list[tuple[str, list[str]]]) -> list[str]:
        return sorted({
            line
            for _, lines in sources
            for raw in lines
            if (line := cls._uncomment(raw))
        })

    @classmethod
    def _collect_rules(cls, lines: list[str]) -> list[Rule]:
        rules = [rule for line in lines if (rule := cls._parse_rule(line))]
        return sorted(rules, key=lambda rule: (
            rule.is_white, rule.format_rank, rule.domain, rule.original
        ))

    @classmethod
    def _normalize_extension_input(cls, line: str) -> str | None:
        parts = line.split()
        if len(parts) == 2:
            try:
                host_ip = ipaddress.ip_address(parts[0])
            except ValueError:
                pass
            else:
                domain = cls._normalize_domain(parts[1])
                if not domain or not cls._is_valid_final_host(
                    Rule(line, domain, not cls._is_blacklist_host_ip(host_ip), 1, host_ip)
                ):
                    return None
                prefix = "@@||" if not cls._is_blacklist_host_ip(host_ip) else "||"
                return f"{prefix}{domain}^"

        domain = cls._normalize_domain(line.rstrip("^"))
        if domain:
            return f"||{domain}^"
        if any(ord(char) < 32 for char in line):
            return None
        if line.startswith(("address=/", "server=/", "local=/", "host-record=")):
            return None
        if line.startswith(EXTENDED_RULE_MARKERS) or any(
            marker in line for marker in EXTENDED_RULE_MARKERS
        ):
            if not line.strip("#"):
                return None
            return line
        if any(char.isspace() for char in line):
            return None
        if any(char in line for char in ("^", "*", "|", "/", "$")):
            return line
        return None

    @staticmethod
    def _option_names(line: str) -> set[str]:
        if "$" not in line or (line.startswith("/") and line.endswith("/")):
            return set()
        option_text = line.rsplit("$", 1)[1]
        return {
            option.lstrip("~").split("=", 1)[0].lower()
            for option in option_text.split(",")
            if option
        }

    @classmethod
    def _is_profile_compatible(cls, line: str, profile: str) -> bool:
        lowered = line.lower()
        options = cls._option_names(line)
        if profile == "adguard":
            return not any(marker in lowered for marker in UBLOCK_ONLY_MARKERS)
        if profile == "ublock_origin":
            if any(marker in lowered for marker in ADGUARD_ONLY_MARKERS):
                return False
            return not bool(options & ADGUARD_ONLY_OPTIONS)
        if profile == "adblock_plus":
            if any(marker in lowered for marker in ADGUARD_ONLY_MARKERS + UBLOCK_ONLY_MARKERS):
                return False
            return all(option in ABP_COMMON_OPTIONS for option in options)
        raise ValueError(f"未知浏览器配置: {profile}")

    @classmethod
    def _format_profile_rule(cls, line: str, profile: str) -> str:
        if not any(marker in line for marker in EXTENDED_RULE_MARKERS):
            exception = line.startswith("@@")
            pattern = line[2:] if exception else line
            if not pattern.startswith(("||", "|", "/", "*")):
                domain_match = re.match(
                    r"^(?:\*\.)?(?:[a-z0-9-]+\.)+[a-z0-9-]+(?=[\^/*])",
                    pattern,
                    re.IGNORECASE,
                )
                if domain_match:
                    pattern = "||" + pattern
            line = ("@@" if exception else "") + pattern

        if "$" not in line or (line.startswith("/") and line.endswith("/")):
            return line
        pattern, option_text = line.rsplit("$", 1)
        aliases = CANONICAL_OPTION_NAMES[profile]
        formatted_options = []
        for option in option_text.split(","):
            if not option:
                continue
            name, separator, value = option.partition("=")
            canonical_name = aliases.get(name.lower(), name.lower())
            formatted_options.append(
                canonical_name + (separator + value if separator else "")
            )
        return pattern + ("$" + ",".join(formatted_options) if formatted_options else "")

    @classmethod
    def _build_extension_rules(cls, lines: list[str], profile: str) -> list[str]:
        selected = set()
        for line in lines:
            normalized = cls._normalize_extension_input(line)
            if not normalized:
                continue
            if profile == "adblock_plus":
                normalized = normalized.replace("$important", "").rstrip("$")
            formatted = cls._format_profile_rule(normalized, profile)
            if cls._is_profile_compatible(formatted, profile):
                selected.add(formatted)
        return sorted(selected)

    @staticmethod
    def _split_extension_rules(rules: list[str]) -> tuple[list[str], list[str]]:
        cosmetic_exception_markers = ("#@#", "#@$#", "#@%#", "#@?#")
        white = [
            rule for rule in rules
            if rule.startswith("@@")
            or any(marker in rule for marker in cosmetic_exception_markers)
        ]
        white_set = set(white)
        black = [rule for rule in rules if rule not in white_set]
        return black, white

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

    def _write_adguard_home(
        self, path: Path, black: list[str], white: list[str]
    ) -> None:
        updated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
        rules = [f"||{domain}^" for domain in black]
        rules.extend(f"@@||{domain}^$important" for domain in white)
        header = [
            f"! 更新时间: {updated}",
            "! 类型: AdGuard Home 合并规则",
            f"! 黑名单规则: {len(black)}",
            f"! 白名单规则: {len(white)}",
            f"! 规则总数: {len(rules)}",
            "",
        ]
        self._atomic_write(path, "\n".join(header + rules))

    def _write_extension(
        self,
        path: Path,
        rules: list[str],
        profile: str,
        *,
        list_kind: str = "combined",
    ) -> None:
        updated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
        titles = {
            "adguard": "AdGuard browser filter",
            "adblock_plus": "Adblock Plus browser filter",
            "ublock_origin": "uBlock Origin browser filter",
        }
        kind_titles = {
            "combined": "combined filter",
            "blacklist": "blacklist",
            "whitelist": "whitelist",
        }
        header = (["[Adblock Plus 2.0]"] if profile == "adblock_plus" else []) + [
            f"! Title: AdGuardHome-rules - {titles[profile]} {kind_titles[list_kind]}",
            f"! Syntax: {titles[profile]}",
            f"! List type: {list_kind}",
            f"! Last modified: {updated}",
            "! Expires: 8 hours",
            f"! Rules: {len(rules)}",
            "",
        ]
        self._atomic_write(path, "\n".join(header + rules))


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
