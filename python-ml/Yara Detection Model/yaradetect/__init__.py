try:
    from .core import (
        YaraRule,
        YaraString,
        HexPattern,
        load_rules_from_file,
        load_rules_from_dir,
        parse_rules,
        match_rule,
        match_rules,
        scan_file,
        scan_dir,
    )
except ImportError:
    from core import (
        YaraRule,
        YaraString,
        HexPattern,
        load_rules_from_file,
        load_rules_from_dir,
        parse_rules,
        match_rule,
        match_rules,
        scan_file,
        scan_dir,
    )

__all__ = [
    "YaraRule",
    "YaraString",
    "HexPattern",
    "load_rules_from_file",
    "load_rules_from_dir",
    "parse_rules",
    "match_rule",
    "match_rules",
    "scan_file",
    "scan_dir",
]
