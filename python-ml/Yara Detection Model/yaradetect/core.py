from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import re


# Data model
@dataclass
class HexPattern:
    """Hex pattern tokens. None means wildcard byte (??)."""
    tokens: List[Optional[int]]


@dataclass
class YaraString:
    ident: str
    kind: str
    value: Union[str, HexPattern, re.Pattern]
    nocase: bool = False
    modifiers: Tuple[str, ...] = ()


@dataclass
class YaraRule:
    name: str
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, str] = field(default_factory=dict)
    strings: List[YaraString] = field(default_factory=list)
    condition: str = ""

    def label(self) -> str:
        for k in ("category", "type", "family", "malware_type"):
            if k in self.meta and self.meta[k]:
                return self.meta[k].strip()
        if self.tags:
            return self.tags[0].strip()
        return self.name.strip()


_RULE_HEADER_RE = re.compile(
    r"rule\s+(?P<name>[A-Za-z0-9_]+)\s*(?::\s*(?P<tags>[A-Za-z0-9_\s]+))?\s*\{",
    re.IGNORECASE,
)
_META_LINE_RE = re.compile(r'(?P<key>[A-Za-z0-9_]+)\s*=\s*"(?P<val>[^"]*)"\s*$')
_STR_TEXT_RE = re.compile(r'(?P<id>\$[A-Za-z0-9_]+)\s*=\s*"(?P<txt>[^"]*)"\s*(?P<mods>.*)$')
_STR_HEX_RE = re.compile(r"(?P<id>\$[A-Za-z0-9_]+)\s*=\s*\{\s*(?P<hex>[0-9A-Fa-f?\s]+)\s*\}\s*(?P<mods>.*)$")
_STR_REGEX_RE = re.compile(r"(?P<id>\$[A-Za-z0-9_]+)\s*=\s*/(?P<rx>.*)/\s*(?P<mods>.*)$")


def _strip_comments(line: str) -> str:
    return line.split("//", 1)[0] if "//" in line else line


def _parse_modifiers(mods: str) -> Tuple[bool, Tuple[str, ...]]:
    mods = (mods or "").strip()
    if not mods:
        return False, ()
    parts = [p for p in re.split(r"\s+", mods) if p]
    nocase = any(p.lower() == "nocase" for p in parts)
    return nocase, tuple(parts)


def _parse_hex_pattern(hex_body: str) -> HexPattern:
    tokens: List[Optional[int]] = []
    for part in re.split(r"\s+", hex_body.strip()):
        if not part:
            continue
        if part == "??" or "?" in part:
            tokens.append(None)
        else:
            tokens.append(int(part, 16))
    return HexPattern(tokens=tokens)


def parse_rules(text: str) -> List[YaraRule]:
    lines = [_strip_comments(l).rstrip("\n") for l in text.splitlines()]

    rules: List[YaraRule] = []
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        if not s:
            i += 1
            continue

        m = _RULE_HEADER_RE.search(s)
        if not m:
            i += 1
            continue

        name = m.group("name")
        tags_raw = (m.group("tags") or "").strip()
        tags = [t for t in re.split(r"\s+", tags_raw) if t] if tags_raw else []

        rule = YaraRule(name=name, tags=tags)
        i += 1

        section: Optional[str] = None
        condition_lines: List[str] = []

        while i < len(lines):
            s = lines[i].strip()
            i += 1

            if not s:
                continue
            if s.startswith("}"):
                break

            if s.lower().startswith("meta:"):
                section = "meta"
                continue
            if s.lower().startswith("strings:"):
                section = "strings"
                continue
            if s.lower().startswith("condition:"):
                section = "condition"
                continue

            if section == "meta":
                mm = _META_LINE_RE.match(s)
                if mm:
                    rule.meta[mm.group("key").strip()] = mm.group("val")
                continue

            if section == "strings":
                mt = _STR_TEXT_RE.match(s)
                mh = _STR_HEX_RE.match(s)
                mr = _STR_REGEX_RE.match(s)

                if mt:
                    nocase, modifiers = _parse_modifiers(mt.group("mods"))
                    rule.strings.append(
                        YaraString(
                            ident=mt.group("id"),
                            kind="text",
                            value=mt.group("txt"),
                            nocase=nocase,
                            modifiers=modifiers,
                        )
                    )
                    continue

                if mh:
                    nocase, modifiers = _parse_modifiers(mh.group("mods"))
                    rule.strings.append(
                        YaraString(
                            ident=mh.group("id"),
                            kind="hex",
                            value=_parse_hex_pattern(mh.group("hex")),
                            nocase=nocase,
                            modifiers=modifiers,
                        )
                    )
                    continue

                if mr:
                    nocase, modifiers = _parse_modifiers(mr.group("mods"))
                    flags = re.IGNORECASE if nocase else 0
                    try:
                        rx = re.compile(mr.group("rx"), flags=flags)
                    except re.error:
                        rx = re.compile(r"a\A")
                    rule.strings.append(
                        YaraString(
                            ident=mr.group("id"),
                            kind="regex",
                            value=rx,
                            nocase=nocase,
                            modifiers=modifiers,
                        )
                    )
                    continue

                continue

            if section == "condition":
                condition_lines.append(s)

        rule.condition = " ".join(condition_lines).strip()
        rules.append(rule)

    return rules


def load_rules_from_file(path: str | Path) -> List[YaraRule]:
    p = Path(path)
    return parse_rules(p.read_text(encoding="utf-8", errors="ignore"))


def load_rules_from_dir(directory: str | Path) -> List[YaraRule]:
    d = Path(directory)
    rules: List[YaraRule] = []
    for p in sorted(d.rglob("*")):
        if p.is_file() and p.suffix.lower() in {".yar", ".yara", ".rule"}:
            rules.extend(load_rules_from_file(p))
    return rules


def _to_wide_bytes(s: str) -> bytes:
    return s.encode("utf-16le", errors="ignore")


def _find_hex(data: bytes, pat: HexPattern) -> bool:
    toks = pat.tokens
    if not toks:
        return False
    m = len(toks)
    n = len(data)
    if m > n:
        return False

    for i in range(0, n - m + 1):
        ok = True
        for j, b in enumerate(toks):
            if b is None:
                continue
            if data[i + j] != b:
                ok = False
                break
        if ok:
            return True
    return False


def match_rule(rule: YaraRule, data: bytes) -> Tuple[bool, List[str]]:
    """
    Returns (rule_fires, matched_string_ids).
    Rule fires if ANY string matches (approx mode).
    """
    matched: List[str] = []
    for ys in rule.strings:
        if ys.kind == "text":
            assert isinstance(ys.value, str)
            needle = ys.value
            needle_bytes = needle.encode("utf-8", errors="ignore")
            mods_lower = {m.lower() for m in ys.modifiers}

            if ys.nocase:
                hay = data.lower()
                if needle_bytes and needle_bytes.lower() in hay:
                    matched.append(ys.ident)
                    continue
                if "wide" in mods_lower:
                    w = _to_wide_bytes(needle).lower()
                    if w and w in hay:
                        matched.append(ys.ident)
            else:
                if needle_bytes and needle_bytes in data:
                    matched.append(ys.ident)
                    continue
                if "wide" in mods_lower:
                    w = _to_wide_bytes(needle)
                    if w and w in data:
                        matched.append(ys.ident)

        elif ys.kind == "hex":
            assert isinstance(ys.value, HexPattern)
            if _find_hex(data, ys.value):
                matched.append(ys.ident)

        elif ys.kind == "regex":
            assert isinstance(ys.value, re.Pattern)
            txt = data.decode("latin-1", errors="ignore")
            if ys.value.search(txt) is not None:
                matched.append(ys.ident)

    return (len(matched) > 0), matched


def match_rules(rules: List[YaraRule], data: bytes) -> Dict[str, Dict[str, object]]:
    out: Dict[str, Dict[str, object]] = {}
    for r in rules:
        fires, matched = match_rule(r, data)
        out[r.name] = {
            "match": fires,
            "matched_strings": matched,
            "label": r.label(),
            "tags": list(r.tags),
            "meta": dict(r.meta),
        }
    return out


def scan_file(rules: List[YaraRule], file_path: str | Path, max_bytes: int = 25_000_000) -> Dict[str, object]:
    p = Path(file_path)
    data = p.read_bytes()[:max_bytes]
    m = match_rules(rules, data)
    matched_rules = [name for name, info in m.items() if info.get("match")]
    return {
        "path": str(p),
        "matched_rules": matched_rules,
        "matches": {k: v for k, v in m.items() if v.get("match")},
    }


def scan_dir(rules: List[YaraRule], directory: str | Path, max_bytes: int = 25_000_000) -> List[Dict[str, object]]:
    d = Path(directory)
    results: List[Dict[str, object]] = []
    for p in sorted(d.rglob("*")):
        if p.is_file():
            results.append(scan_file(rules, p, max_bytes=max_bytes))
    return results
