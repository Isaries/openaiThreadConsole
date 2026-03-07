"""
Tests for database.py — DB operations for groups, IP bans, settings, logs.
"""
import pytest


class TestLoadGroups:

    def test_empty_initially(self, app, db):
        with app.app_context():
            import database
            groups = database.load_groups()
            # Only the admin user created by create_app exists, no projects
            assert isinstance(groups, list)

    def test_returns_project_data(self, app, db, sample_project):
        with app.app_context():
            import database
            groups = database.load_groups()
            assert len(groups) >= 1
            found = [g for g in groups if g['group_id'] == sample_project.id]
            assert len(found) == 1
            assert found[0]['name'] == 'Test Project'
            assert isinstance(found[0]['threads'], list)
            assert isinstance(found[0]['owners'], list)


class TestGetGroupById:

    def test_existing(self, app, db, sample_project):
        with app.app_context():
            import database
            group = database.get_group_by_id(sample_project.id)
            assert group is not None
            assert group['name'] == 'Test Project'

    def test_not_found(self, app, db):
        with app.app_context():
            import database
            assert database.get_group_by_id('nonexistent') is None


class TestIPBans:

    def test_add_and_load(self, app, db):
        with app.app_context():
            import database
            database.add_ip_ban("11.22.33.44", "Spam", 9999999999.0)
            bans = database.load_ip_bans()
            assert "11.22.33.44" in bans
            assert bans["11.22.33.44"]["reason"] == "Spam"

    def test_remove(self, app, db):
        with app.app_context():
            import database
            database.add_ip_ban("55.66.77.88", "Test", 0)
            database.remove_ip_ban("55.66.77.88")
            bans = database.load_ip_bans()
            assert "55.66.77.88" not in bans

    def test_update_existing(self, app, db):
        with app.app_context():
            import database
            database.add_ip_ban("1.1.1.1", "Reason1", 100)
            database.add_ip_ban("1.1.1.1", "Reason2", 200)
            bans = database.load_ip_bans()
            assert bans["1.1.1.1"]["reason"] == "Reason2"


class TestSettings:

    def test_update_and_load(self, app, db):
        with app.app_context():
            import database
            database.update_setting("theme", "dark")
            settings = database.load_settings()
            assert settings.get("theme") == "dark"

    def test_update_complex_value(self, app, db):
        with app.app_context():
            import database
            database.update_setting("config", {"a": 1, "b": [2, 3]})
            settings = database.load_settings()
            assert settings["config"]["a"] == 1
            assert settings["config"]["b"] == [2, 3]

    def test_save_settings_bulk(self, app, db):
        with app.app_context():
            import database
            result = database.save_settings({"k1": "v1", "k2": 42})
            assert result is True
            s = database.load_settings()
            assert s.get("k1") == "v1"
            assert s.get("k2") == 42


class TestLogs:

    def test_save_and_load(self, app, db):
        with app.app_context():
            import database
            import time
            database.save_log({
                'timestamp': int(time.time()),
                'group': 'TestGroup',
                'target': 'QueryX',
                'date_range': '2024-01-01 ~ 2024-12-31',
                'matches': 5,
                'total': 100,
                'api_results': [],
            })
            logs = database.load_logs()
            assert len(logs) >= 1
            assert logs[0]['group'] == 'TestGroup'
