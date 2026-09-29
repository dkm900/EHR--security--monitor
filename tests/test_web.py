"""Tests for the HTTP layer, using Flask's in-process test client.

No server is started; these exercise routing, JSON shape and status codes.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as web  # noqa: E402


class WebTestCase(unittest.TestCase):
    def setUp(self):
        web.monitor.reset()
        self.c = web.app.test_client()

    def tearDown(self):
        web.monitor.reset()

    # -- pages ----------------------------------------------------------
    def test_index_renders(self):
        res = self.c.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        for needle in ("EHR Security Monitor", "Patient records",
                       "Scenario launcher", "Alerts"):
            self.assertIn(needle, html)

    def test_static_assets_are_served(self):
        self.assertEqual(self.c.get("/static/style.css").status_code, 200)
        self.assertEqual(self.c.get("/static/app.js").status_code, 200)

    # -- reference ------------------------------------------------------
    def test_bootstrap_shape(self):
        data = self.c.get("/api/bootstrap").get_json()
        self.assertEqual(len(data["staff"]), 7)
        self.assertEqual(len(data["scenarios"]), 7)
        self.assertEqual([r["id"] for r in data["rules"]],
                         ["EHR-001", "EHR-002", "EHR-003"])
        self.assertIn("max_batch", data["heuristic"])

    def test_records_listing(self):
        data = self.c.get("/api/records?limit=5").get_json()
        self.assertEqual(len(data["records"]), 5)
        self.assertGreater(data["in_catalog"], 100)
        first = data["records"][0]
        for key in ("record_id", "patient_name", "age", "department",
                    "categories"):
            self.assertIn(key, first)

    def test_records_search_by_name(self):
        allrec = self.c.get("/api/records?limit=1").get_json()["records"][0]
        name = allrec["patient_name"].split()[0]
        data = self.c.get(f"/api/records?q={name}").get_json()
        self.assertGreater(data["total"], 0)

    def test_records_filter_by_department(self):
        data = self.c.get("/api/records?department=Psychiatry").get_json()
        self.assertTrue(data["records"])
        for r in data["records"]:
            self.assertEqual(r["department"], "Psychiatry")

    def test_records_filter_by_category(self):
        data = self.c.get("/api/records?category=psych").get_json()
        self.assertTrue(data["records"])
        for r in data["records"]:
            self.assertIn("psych", r["categories"])

    def test_single_record(self):
        rid = self.c.get("/api/records?limit=1").get_json()["records"][0]["record_id"]
        self.assertEqual(self.c.get(f"/api/records/{rid}").status_code, 200)

    def test_missing_record_is_404(self):
        self.assertEqual(self.c.get("/api/records/NOPE").status_code, 404)

    # -- access ---------------------------------------------------------
    def test_login_failure_and_alert(self):
        for _ in range(3):
            self.c.post("/api/login", json={"user_id": "dr.ivanov",
                                            "password": "bad"})
        alerts = self.c.get("/api/alerts").get_json()["open"]
        self.assertTrue(any(a["rule_id"] == "EHR-001" for a in alerts))

    def test_login_success(self):
        res = self.c.post("/api/login", json={"user_id": "dr.ivanov",
                                              "password": "correct-horse"})
        self.assertTrue(res.get_json()["allowed"])

    def test_access_denied_returns_200_with_verdict(self):
        """A denial is a *successful* API call describing a refused action."""
        rid = self.c.get("/api/records?category=psych&limit=1") \
                  .get_json()["records"][0]["record_id"]
        res = self.c.post("/api/access", json={
            "user_id": "clerk.bianchi", "record_ids": [rid],
            "sections": ["psych"],
        })
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertFalse(body["allowed"])
        self.assertEqual(body["event"]["outcome"], "denied")

    def test_access_with_sections(self):
        rid = self.c.get("/api/records?category=billing&limit=1") \
                  .get_json()["records"][0]["record_id"]
        res = self.c.post("/api/access", json={
            "user_id": "clerk.bianchi", "record_ids": [rid],
            "sections": ["billing"], "action": "view",
        })
        self.assertTrue(res.get_json()["allowed"])

    def test_bad_action_is_400(self):
        res = self.c.post("/api/access", json={
            "user_id": "dr.okafor", "record_ids": ["MRN-1001"],
            "action": "obliterate",
        })
        self.assertEqual(res.status_code, 400)

    def test_bad_section_is_400(self):
        res = self.c.post("/api/access", json={
            "user_id": "dr.okafor", "record_ids": ["MRN-1001"],
            "sections": ["not_a_section"],
        })
        self.assertEqual(res.status_code, 400)

    # -- monitoring -----------------------------------------------------
    def test_alerts_acknowledge(self):
        for _ in range(3):
            self.c.post("/api/login", json={"user_id": "dr.ivanov",
                                            "password": "bad"})
        alert = self.c.get("/api/alerts").get_json()["open"][0]
        res = self.c.post(f"/api/alerts/{alert['alert_id']}/ack")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(self.c.get("/api/alerts").get_json()["open"], [])

    def test_ack_unknown_alert_is_404(self):
        self.assertEqual(
            self.c.post("/api/alerts/zzz/ack").status_code, 404
        )

    def test_ack_all(self):
        for _ in range(3):
            self.c.post("/api/login", json={"user_id": "dr.ivanov",
                                            "password": "bad"})
        res = self.c.post("/api/alerts/ack-all").get_json()
        self.assertGreaterEqual(res["acknowledged"], 1)

    def test_audit_endpoint_reports_integrity(self):
        self.c.post("/api/login", json={"user_id": "dr.ivanov",
                                        "password": "correct-horse"})
        data = self.c.get("/api/audit").get_json()
        self.assertTrue(data["integrity"]["chain_ok"])
        self.assertGreaterEqual(data["total"], 1)
        self.assertIn("entry_hash", data["events"][0])

    def test_audit_limit_is_capped(self):
        for i in range(5):
            self.c.post("/api/login", json={"user_id": "dr.ivanov",
                                            "password": "correct-horse"})
        data = self.c.get("/api/audit?limit=99999").get_json()
        self.assertLessEqual(len(data["events"]), 500)

    def test_stats_endpoint(self):
        stats = self.c.get("/api/stats").get_json()
        for key in ("total_events", "outcomes", "by_severity", "chain_ok"):
            self.assertIn(key, stats)

    # -- scenarios ------------------------------------------------------
    def test_every_scenario_endpoint_runs(self):
        for entry in self.c.get("/api/bootstrap").get_json()["scenarios"]:
            with self.subTest(scenario=entry["key"]):
                web.monitor.reset()
                res = self.c.post(f"/api/scenarios/{entry['key']}")
                self.assertEqual(res.status_code, 200)
                body = res.get_json()
                self.assertTrue(body["behaved_as_expected"])
                self.assertEqual(body["key"], entry["key"])

    def test_unknown_scenario_is_404(self):
        self.assertEqual(
            self.c.post("/api/scenarios/nope").status_code, 404
        )

    def test_reset_clears_state(self):
        for _ in range(3):
            self.c.post("/api/login", json={"user_id": "dr.ivanov",
                                            "password": "bad"})
        self.assertTrue(self.c.get("/api/alerts").get_json()["open"])
        self.c.post("/api/reset")
        self.assertEqual(self.c.get("/api/alerts").get_json()["open"], [])
        self.assertEqual(self.c.get("/api/audit").get_json()["total"], 0)

    def test_unknown_route_returns_json_404(self):
        res = self.c.get("/api/nope")
        self.assertEqual(res.status_code, 404)
        self.assertIn("error", res.get_json())


if __name__ == "__main__":
    unittest.main(verbosity=2)
