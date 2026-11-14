import unittest
from unittest.mock import patch

from app import app as flask_app
import app as app_module
from app import (
    _sanitize_malware_evidence,
    _sanitize_network_record,
    _sanitize_sarvam_report_data,
)


class SarvamDataSanitizationTests(unittest.TestCase):
    def test_network_records_only_include_allowlisted_fields(self):
        sanitized = _sanitize_network_record(
            {
                "protocol": " tcp ",
                "sourcePort": 443,
                "destinationPort": 8443,
                "packetSize": 1280,
                "sourceIp": "192.0.2.10",
                "destinationIp": "198.51.100.5",
                "hostname": "internal.example",
            }
        )

        self.assertEqual(
            {
                "protocol": "TCP",
                "sourcePort": 443,
                "destinationPort": 8443,
                "packetSize": 1280,
            },
            sanitized,
        )

    def test_malware_evidence_excludes_file_identifiers_and_features(self):
        sanitized = _sanitize_malware_evidence(
            {
                "file": {
                    "extension": ".EXE",
                    "sizeBytes": 2048,
                    "filePath": "C:\\Users\\alice\\secret.exe",
                    "fileName": "secret.exe",
                    "sha256": "deadbeef",
                },
                "derivedFeatures": {"path_depth": 4},
                "model": {"label": "suspicious", "confidence": 92, "classId": 1},
            }
        )

        self.assertEqual(
            {
                "file": {"extension": ".exe", "sizeBytes": 2048},
                "model": {"label": "suspicious", "confidence": 92, "classId": 1},
            },
            sanitized,
        )

    def test_database_report_discards_unapproved_fields(self):
        sanitized = _sanitize_sarvam_report_data(
            {
                "generatedAt": "2026-03-10T12:00:00Z",
                "source": "attacker-controlled",
                "summary": {"alerts": 2, "windowsEvents": 1, "extra": "discard"},
                "recentAlerts": [
                    {
                        "severity": "high",
                        "type": "BRUTE_FORCE",
                        "status": "new",
                        "timestamp": "2026-03-10T11:00:00Z",
                        "sourceIp": "192.0.2.10",
                        "alertMessage": "private text",
                    }
                ],
                "recentIncidents": [],
                "recentMalware": [],
                "recentVulnerabilities": [],
                "windowsEventLevels": {"Warning": 1},
                "rawEventMessages": ["private text"],
            }
        )

        self.assertEqual("database", sanitized["source"])
        self.assertEqual({"alerts": 2, "windowsEvents": 1}, sanitized["summary"])
        self.assertEqual(
            {
                "severity": "high",
                "type": "BRUTE_FORCE",
                "status": "new",
                "timestamp": "2026-03-10T11:00:00Z",
            },
            sanitized["recentAlerts"][0],
        )
        self.assertNotIn("rawEventMessages", sanitized)

    def test_network_enrichment_sends_only_sanitized_records(self):
        captured = {}
        assessment = {
            "index": 0,
            "assessment": "benign",
            "confidence": 90,
            "summary": "No anomaly found",
            "evidence": [],
            "recommendations": [],
        }

        def fake_request(_prompt, payload, **_kwargs):
            captured.update(payload)
            return {"results": [assessment]}

        with patch("app._request_sarvam_json", side_effect=fake_request):
            _results, status = app_module._enrich_anomaly_results(
                [
                    {
                        "protocol": "TCP",
                        "sourcePort": 443,
                        "destinationPort": 8443,
                        "packetSize": 1280,
                        "sourceIp": "192.0.2.10",
                    }
                ],
                [{"anomaly": False, "anomaly_score": 0.1}],
            )

        self.assertEqual("ok", status)
        self.assertEqual(
            {
                "protocol": "TCP",
                "sourcePort": 443,
                "destinationPort": 8443,
                "packetSize": 1280,
            },
            captured["items"][0]["record"],
        )

    def test_malware_endpoint_omits_legacy_file_identifiers(self):
        captured = {}

        def fake_assess(_kind, evidence):
            captured.update(evidence)
            return {
                "assessment": "benign",
                "confidence": 90,
                "summary": "No threat found",
                "evidence": [],
                "recommendations": [],
            }

        with patch("app._sarvam_assess", side_effect=fake_assess):
            response = flask_app.test_client().post(
                "/api/malware/analyze",
                json={
                    "fileName": "secret.exe",
                    "fileHash": "deadbeef",
                    "fileExtension": ".EXE",
                    "fileSize": 2048,
                    "scanResult": "clean",
                    "scanEngine": "YARA",
                    "virustotalPositives": 0,
                    "virustotalTotal": 70,
                },
            )

        self.assertEqual(200, response.status_code)
        self.assertEqual(
            {"file": {"extension": ".exe", "sizeBytes": 2048},
             "deterministicScanResult": "clean",
             "scanEngine": "YARA",
             "virustotalPositives": 0,
             "virustotalTotal": 70},
            captured,
        )

    def test_report_endpoint_sends_only_sanitized_database_snapshot(self):
        captured = {}
        report_result = {
            "executive_summary": "Assessment complete",
            "risk_level": "low",
            "findings": [],
            "recommendations": [],
            "limitations": "",
        }

        def fake_request(_prompt, payload, **_kwargs):
            captured.update(payload)
            return report_result

        with (
            patch("app._request_sarvam_json", side_effect=fake_request),
            patch("app._build_report_pdf", return_value=b"%PDF test"),
        ):
            response = flask_app.test_client().post(
                "/api/sarvam/report",
                json={
                    "title": "Test",
                    "data": {
                        "summary": {"alerts": 1, "extra": "discard"},
                        "recentAlerts": [
                            {
                                "severity": "high",
                                "type": "BRUTE_FORCE",
                                "status": "new",
                                "sourceIp": "192.0.2.10",
                                "alertMessage": "private text",
                            }
                        ],
                        "recentIncidents": [],
                        "recentMalware": [],
                        "recentVulnerabilities": [],
                        "windowsEventLevels": {},
                        "rawEventMessages": ["private text"],
                    },
                },
            )

        self.assertEqual(200, response.status_code)
        safe_data = captured["analysisData"]
        self.assertEqual({"alerts": 1}, safe_data["summary"])
        self.assertEqual(
            {"severity": "high", "type": "BRUTE_FORCE", "status": "new"},
            safe_data["recentAlerts"][0],
        )
        self.assertNotIn("rawEventMessages", safe_data)


if __name__ == "__main__":
    unittest.main()
