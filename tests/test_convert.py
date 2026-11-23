import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import convert  # noqa: E402


class TestCandidateUrls(unittest.TestCase):
    def test_jsdelivr_mrs_expands_to_list_and_github_mirrors(self) -> None:
        url = "https://testingcf.jsdelivr.net/gh/DustinWin/ruleset_geodata@mihomo-ruleset/ads.mrs"
        cands = convert.build_candidate_urls(url, "mrs")
        self.assertEqual(
            cands[:3],
            [
                "https://testingcf.jsdelivr.net/gh/DustinWin/ruleset_geodata@mihomo-ruleset/ads.list",
                "https://raw.githubusercontent.com/DustinWin/ruleset_geodata/mihomo-ruleset/ads.list",
                "https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/ads.list",
            ],
        )

    def test_plain_yaml_url_adds_raw_fallback(self) -> None:
        url = "https://testingcf.jsdelivr.net/gh/foo/bar@main/rules/test.yaml"
        cands = convert.build_candidate_urls(url, "yaml")
        self.assertEqual(
            cands,
            [
                url,
                "https://raw.githubusercontent.com/foo/bar/main/rules/test.yaml",
            ],
        )


class TestRuleConversions(unittest.TestCase):
    def test_domain_text_and_yaml_conversion(self) -> None:
        content = """
        # comment line
        payload:
          - '+.Google.com'
          - '.youtube.com'
          - '*.netflix.com'
          - 'exact.example.org'
          - 'invalid.*.wildcard.com'
          - '+.google.com' # duplicate
          - '_dmarc.example.com'
        """
        rules, skipped = convert.convert_provider_content(content, "domain")
        self.assertEqual(
            rules,
            [
                "DOMAIN-SUFFIX,google.com",
                "DOMAIN-SUFFIX,youtube.com",
                "DOMAIN-SUFFIX,netflix.com",
                "DOMAIN,exact.example.org",
                "DOMAIN,_dmarc.example.com",
            ],
        )
        self.assertEqual(skipped, 1)

    def test_ipcidr_v4_and_v6_with_and_without_no_resolve(self) -> None:
        content = """
        # IP ranges
        192.168.0.0/16
        10.0.0.1/8
        2400:3200::/32
        not-an-ip
        """
        rules_nr, skipped_nr = convert.convert_provider_content(content, "ipcidr", add_no_resolve=True)
        self.assertEqual(
            rules_nr,
            [
                "IP-CIDR,192.168.0.0/16,no-resolve",
                "IP-CIDR,10.0.0.0/8,no-resolve",
                "IP-CIDR6,2400:3200::/32,no-resolve",
            ],
        )
        self.assertEqual(skipped_nr, 1)

        rules_plain, _ = convert.convert_provider_content(content, "ipcidr", add_no_resolve=False)
        self.assertEqual(
            rules_plain,
            [
                "IP-CIDR,192.168.0.0/16",
                "IP-CIDR,10.0.0.0/8",
                "IP-CIDR6,2400:3200::/32",
            ],
        )

    def test_classical_filters_unsupported_types(self) -> None:
        content = """
        DOMAIN-SUFFIX,openai.com
        DOMAIN-KEYWORD,chatgpt
        PROCESS-NAME,clash
        GEOSITE,cn
        SRC-IP-CIDR,192.168.1.0/24
        IP-CIDR,1.1.1.1/32,no-resolve
        """
        rules, skipped = convert.convert_provider_content(content, "classical")
        self.assertEqual(
            rules,
            [
                "DOMAIN-SUFFIX,openai.com",
                "DOMAIN-KEYWORD,chatgpt",
                "SRC-IP,192.168.1.0/24",
                "IP-CIDR,1.1.1.1/32,no-resolve",
            ],
        )
        self.assertEqual(skipped, 2)


class TestProxyGroupsAndEndToEnd(unittest.TestCase):
    def test_end_to_end_real_config_yaml(self) -> None:
        config_path = PROJECT_ROOT / "config" / "config.yaml"
        general_path = PROJECT_ROOT / "templates" / "general.ini"
        cfg = convert.load_yaml_file(config_path)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fixtures_dir = tmp_path / "fixtures"
            out_dir = tmp_path / "dist"
            summary_file = tmp_path / "summary.md"
            fixtures_dir.mkdir()

            for name, spec in cfg["rule-providers"].items():
                if spec["behavior"] == "domain":
                    (fixtures_dir / f"{name}.list").write_text(
                        f"+.{name}.example.com\nexact-{name}.example.com\n",
                        encoding="utf-8",
                    )
                else:
                    (fixtures_dir / f"{name}.list").write_text(
                        "192.0.2.0/24\n2001:db8::/32\n",
                        encoding="utf-8",
                    )

            rc = convert.main(
                [
                    "--config",
                    str(config_path),
                    "--general",
                    str(general_path),
                    "--output-dir",
                    str(out_dir),
                    "--repo",
                    "demo/my-rules",
                    "--branch",
                    "main",
                    "--offline-fixtures",
                    str(fixtures_dir),
                    "--summary-file",
                    str(summary_file),
                ]
            )
            self.assertEqual(rc, 0)

            # Verify all 19 rule lists generated
            list_files = sorted(p.name for p in (out_dir / "rules").glob("*.list"))
            self.assertEqual(len(list_files), 19)

            # Verify no-resolve semantics preserved per provider
            privateip_text = (out_dir / "rules" / "privateip.list").read_text(encoding="utf-8")
            self.assertIn("IP-CIDR,192.0.2.0/24,no-resolve", privateip_text)
            self.assertIn("IP-CIDR6,2001:db8::/32,no-resolve", privateip_text)

            cnip_text = (out_dir / "rules" / "cnip.list").read_text(encoding="utf-8")
            self.assertIn("IP-CIDR,192.0.2.0/24\n", cnip_text)
            self.assertNotIn("no-resolve", cnip_text)

            # Verify modular raw config
            raw_conf = (out_dir / "shadowrocket.conf").read_text(encoding="utf-8")
            self.assertTrue(
                raw_conf.startswith(
                    "#!MANAGED-CONFIG https://raw.githubusercontent.com/demo/my-rules/main/dist/shadowrocket.conf"
                )
            )
            # PASS must be mapped to DIRECT
            self.assertIn("🟢 全球绕过 = select, DIRECT, hidden=1", raw_conf)
            self.assertNotIn(", PASS", raw_conf)
            # include-all groups converted cleanly
            self.assertIn("👉 手动选择 = select, policy-regex-filter=.*", raw_conf)
            self.assertIn(
                "♻️ 自动选择 = url-test, policy-regex-filter=.*, url=http://www.gstatic.com/generate_204, interval=600, timeout=5, tolerance=100",
                raw_conf,
            )
            self.assertIn(
                "🇭🇰 香港节点 = url-test, policy-regex-filter=(?i)(🇭🇰|港|hk|hongkong|hong kong), url=http://www.gstatic.com/generate_204, interval=600, timeout=5, tolerance=50",
                raw_conf,
            )
            # Rule-sets and FINAL rule
            self.assertIn(
                "RULE-SET,https://raw.githubusercontent.com/demo/my-rules/main/dist/rules/ads.list,🛑 广告域名",
                raw_conf,
            )
            self.assertIn(
                "RULE-SET,https://raw.githubusercontent.com/demo/my-rules/main/dist/rules/telegramip.list,📲 电报消息,no-resolve",
                raw_conf,
            )
            self.assertIn("FINAL,🐟 漏网之鱼", raw_conf)

            # Verify CDN config
            cdn_conf = (out_dir / "shadowrocket-cdn.conf").read_text(encoding="utf-8")
            self.assertIn(
                "RULE-SET,https://testingcf.jsdelivr.net/gh/demo/my-rules@main/dist/rules/ai.list,🤖 AI 平台",
                cdn_conf,
            )

            # Verify inline config
            inline_conf = (out_dir / "shadowrocket-inline.conf").read_text(encoding="utf-8")
            self.assertIn("DOMAIN-SUFFIX,ai.example.com,🤖 AI 平台", inline_conf)
            self.assertIn("IP-CIDR,192.0.2.0/24,📲 电报消息,no-resolve", inline_conf)
            self.assertIn("IP-CIDR,192.0.2.0/24,🀄️ 国内 IP\n", inline_conf)
            self.assertIn("FINAL,🐟 漏网之鱼", inline_conf)

            # Verify summary report
            summary_text = summary_file.read_text(encoding="utf-8")
            self.assertIn("## ShellCrash -> Shadowrocket Sync Summary", summary_text)
            self.assertIn("| `ads` |", summary_text)


if __name__ == "__main__":
    unittest.main()
