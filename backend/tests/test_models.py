"""
Tests for ORM models — creation, relationships, and cascade behavior.
"""
import pytest
from datetime import datetime


class TestUserModel:

    def test_create_user(self, app, db):
        with app.app_context():
            from app.models import User
            from werkzeug.security import generate_password_hash

            user = User(
                id='u-test',
                username='john',
                email='john@example.com',
                password_hash=generate_password_hash('SomePass123'),
                is_admin=False,
            )
            db.session.add(user)
            db.session.commit()

            found = db.session.get(User, 'u-test')
            assert found is not None
            assert found.username == 'john'
            assert found.is_admin is False


class TestProjectModel:

    def test_create_project(self, app, db):
        with app.app_context():
            from app.models import Project
            p = Project(id='proj-test', name='My Project', is_visible=True, version=1)
            db.session.add(p)
            db.session.commit()

            found = db.session.get(Project, 'proj-test')
            assert found.name == 'My Project'


class TestProjectOwnerRelation:

    def test_add_owner(self, app, db, sample_user, sample_project):
        with app.app_context():
            from app.models import Project, User
            project = db.session.get(Project, sample_project.id)
            user = db.session.get(User, sample_user.id)
            project.owners.append(user)
            db.session.commit()

            assert user in project.owners
            assert project in user.owned_projects


class TestThreadModel:

    def test_create_thread(self, app, db, sample_project):
        with app.app_context():
            from app.models import Thread
            t = Thread(thread_id='thread_t1', project_id=sample_project.id, remark='R1')
            db.session.add(t)
            db.session.commit()

            assert t.id is not None
            assert t.project.id == sample_project.id


class TestMessageModel:

    def test_create_message(self, app, db, sample_thread):
        with app.app_context():
            from app.models import Message
            import time

            msg = Message(
                thread_id=sample_thread.id,
                role='user',
                content='Hello, assistant!',
                created_at=int(time.time()),
            )
            db.session.add(msg)
            db.session.commit()

            assert msg.id is not None
            assert msg.thread.thread_id == 'thread_abc123'


class TestCascadeDelete:

    def test_delete_project_cascades_threads(self, app, db, sample_project, sample_thread):
        with app.app_context():
            from app.models import Thread, Project

            # Re-fetch within the current session to avoid cross-session issues
            project = db.session.get(Project, sample_project.id)
            assert project is not None

            db.session.delete(project)
            db.session.commit()

            remaining = Thread.query.filter_by(thread_id='thread_abc123').first()
            assert remaining is None

    def test_delete_thread_cascades_messages(self, app, db, sample_thread):
        with app.app_context():
            from app.models import Message, Thread
            import time

            # Re-fetch thread in current session
            thread = db.session.get(Thread, sample_thread.id)

            msg = Message(
                thread_id=thread.id,
                role='assistant',
                content='Reply',
                created_at=int(time.time()),
            )
            db.session.add(msg)
            db.session.commit()
            msg_id = msg.id

            db.session.delete(thread)
            db.session.commit()

            assert db.session.get(Message, msg_id) is None


class TestIPBanModel:

    def test_create(self, app, db):
        with app.app_context():
            from app.models import IPBan
            ban = IPBan(ip='99.99.99.99', reason='Bad actor', expires_at=-1)
            db.session.add(ban)
            db.session.commit()

            found = db.session.get(IPBan, '99.99.99.99')
            assert found is not None
            assert found.reason == 'Bad actor'


class TestSystemSettingModel:

    def test_upsert(self, app, db):
        with app.app_context():
            from app.models import SystemSetting

            s = SystemSetting(key='max_retries', value='5')
            db.session.add(s)
            db.session.commit()

            found = db.session.get(SystemSetting, 'max_retries')
            assert found.value == '5'

            found.value = '10'
            db.session.commit()

            updated = db.session.get(SystemSetting, 'max_retries')
            assert updated.value == '10'


class TestAuditLogModel:

    def test_create(self, app, db):
        with app.app_context():
            from app.models import AuditLog
            log = AuditLog(
                user_name='admin',
                action='Login',
                target='auth',
                status='Success',
                ip_address='127.0.0.1',
            )
            db.session.add(log)
            db.session.commit()

            assert log.id is not None
