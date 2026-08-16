import tempfile
import unittest
from pathlib import Path

from script import RuleProcessor


class BrowserProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lines = RuleProcessor._collect_source_lines([
            ("test", [
                "example.com",
                "0.0.0.0 ads.example.com",
                "192.168.1.1 private.example.com",
                "csdnimg.cn^*#/preview/",
                "example.com##.advert",
                "example.com##+js(set, test, true)",
                "example.com#$#.advert { remove: true; }",
                "||tracker.example^$removeparam=utm_source",
                "### Version: V1.0",
                "##### Version Information",
            ]),
        ])

    def test_url_pattern_is_preserved_for_all_profiles(self) -> None:
        for profile in ("adguard", "adblock_plus", "ublock_origin"):
            rules = RuleProcessor._build_extension_rules(self.lines, profile)
            self.assertIn("||csdnimg.cn^*#/preview/", rules)

    def test_profile_specific_rules_are_separated(self) -> None:
        adguard = RuleProcessor._build_extension_rules(self.lines, "adguard")
        adblock_plus = RuleProcessor._build_extension_rules(self.lines, "adblock_plus")
        ublock = RuleProcessor._build_extension_rules(self.lines, "ublock_origin")

        self.assertNotIn("example.com#$#.advert { remove: true; }", adguard)
        self.assertNotIn("example.com##+js(set, test, true)", adguard)
        self.assertNotIn("example.com##+js(set, test, true)", ublock)
        self.assertIn("||tracker.example^$removeparam=utm_source", ublock)
        self.assertNotIn("||tracker.example^$removeparam=utm_source", adblock_plus)
        self.assertNotIn("example.com##.advert", adblock_plus)

    def test_hosts_are_converted_and_private_hosts_are_removed(self) -> None:
        rules = RuleProcessor._build_extension_rules(self.lines, "adblock_plus")
        self.assertIn("||ads.example.com^", rules)
        self.assertNotIn("@@||private.example.com^", rules)

    def test_markdown_headings_are_not_treated_as_cosmetic_rules(self) -> None:
        for profile in ("adguard", "adblock_plus", "ublock_origin"):
            rules = RuleProcessor._build_extension_rules(self.lines, profile)
            self.assertNotIn("### Version: V1.0", rules)
            self.assertNotIn("##### Version Information", rules)

    def test_extension_file_has_subscription_header(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "AdblockPlus.txt"
            processor = RuleProcessor(directory, logger=None)
            processor._write_extension(path, ["||example.com^"], "adblock_plus")
            content = path.read_text(encoding="utf-8")
            self.assertTrue(content.startswith("[Adblock Plus 2.0]\n"))
            self.assertIn("! Rules: 1\n", content)

    def test_each_profile_uses_canonical_option_names(self) -> None:
        line = "||example.com^$3p,xhr,css,frame"
        self.assertEqual(
            RuleProcessor._format_profile_rule(line, "adguard"),
            "||example.com^$third-party,xmlhttprequest,stylesheet,subdocument",
        )
        self.assertEqual(
            RuleProcessor._format_profile_rule(line, "adblock_plus"),
            "||example.com^$third-party,xmlhttprequest,stylesheet,subdocument",
        )
        self.assertEqual(
            RuleProcessor._format_profile_rule(
                "||example.com^$third-party,xmlhttprequest,stylesheet,subdocument",
                "ublock_origin",
            ),
            "||example.com^$3p,xhr,css,frame",
        )

    def test_only_adblock_plus_uses_abp_subscription_preamble(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            processor = RuleProcessor(directory, logger=None)
            for profile in ("adguard", "ublock_origin"):
                path = Path(directory) / f"{profile}.txt"
                processor._write_extension(path, [], profile)
                content = path.read_text(encoding="utf-8")
                self.assertFalse(content.startswith("[Adblock Plus 2.0]"))

    def test_separate_adguard_home_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            processor = RuleProcessor(directory, logger=None)
            black_path = Path(directory) / "AdGuardHome_BlackList.txt"
            white_path = Path(directory) / "AdGuardHome_WhiteList.txt"
            processor._write_final(black_path, ["blocked.example.com"], False)
            processor._write_final(white_path, ["allowed.example.com"], True)
            self.assertIn(
                "||blocked.example.com^\n",
                black_path.read_text(encoding="utf-8"),
            )
            self.assertIn(
                "@@||allowed.example.com^$important\n",
                white_path.read_text(encoding="utf-8"),
            )

    def test_extension_rules_are_split_into_black_and_white_lists(self) -> None:
        rules = [
            "||blocked.example.com^",
            "@@||allowed.example.com^",
            "||blocked.example.com/path/*",
            "@@||allowed.example.com/path/*",
        ]
        black, white = RuleProcessor._split_extension_rules(rules)
        self.assertEqual(
            black,
            [
                "||blocked.example.com^",
                "||blocked.example.com/path/*",
            ],
        )
        self.assertEqual(
            white,
            [
                "@@||allowed.example.com^",
                "@@||allowed.example.com/path/*",
            ],
        )

    def test_element_and_scriptlet_rules_are_collected_separately(self) -> None:
        rules = RuleProcessor._collect_element_rules(self.lines)
        self.assertIn("example.com##.advert", rules)
        self.assertIn("example.com##+js(set, test, true)", rules)
        self.assertIn("example.com#$#.advert { remove: true; }", rules)
        self.assertNotIn("||tracker.example^$removeparam=utm_source", rules)
        self.assertNotIn("### Version: V1.0", rules)

    def test_lite_rules_remove_covered_subdomains_and_respect_limit(self) -> None:
        rules = [
            "||example.com^",
            "||sub.example.com^",
            "||deep.sub.example.com^",
            "||other.example.net^",
            "||sub.example.com^$script",
        ]
        reduced = RuleProcessor._reduce_lite_rules(rules, limit=3)
        self.assertIn("||example.com^", reduced)
        self.assertNotIn("||sub.example.com^", reduced)
        self.assertNotIn("||deep.sub.example.com^", reduced)
        self.assertIn("||sub.example.com^$script", reduced)
        self.assertLessEqual(len(reduced), 3)


if __name__ == "__main__":
    unittest.main()
