from .extensions import db
from datetime import datetime


# removed db = SQLAlchemy() as it is in extensions

# Association Table for Project Owners
project_owners = db.Table('project_owners',
    db.Column('project_id', db.String(50), db.ForeignKey('projects.id'), primary_key=True),
    db.Column('user_id', db.String(36), db.ForeignKey('users.id'), primary_key=True)
)

# Association Table for Project Tags
project_tags = db.Table('project_tags',
    db.Column('project_id', db.String(50), db.ForeignKey('projects.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id'), primary_key=True)
)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    password_hint = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.Integer, nullable=False, default=lambda: int(datetime.now().timestamp()))
    is_admin = db.Column(db.Boolean, default=False)
    
    # Relationships
    owned_projects = db.relationship('Project', secondary=project_owners, back_populates='owners')

class Tag(db.Model):
    __tablename__ = 'tags'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class Project(db.Model):
    __tablename__ = 'projects'
    id = db.Column(db.String(50), primary_key=True) # e.g., group_123
    name = db.Column(db.String(100), nullable=False)
    api_key = db.Column(db.String(500), nullable=True)
    api_key_hash = db.Column(db.String(64), index=True, nullable=True)
    is_visible = db.Column(db.Boolean, default=True)
    version = db.Column(db.Integer, default=1)
    created_at = db.Column(db.Integer, nullable=True)  # Unix timestamp
    
    # Relationships
    threads = db.relationship('Thread', backref='project', lazy=True, cascade="all, delete-orphan")
    owners = db.relationship('User', secondary=project_owners, back_populates='owned_projects')
    tags = db.relationship('Tag', secondary=project_tags, backref=db.backref('projects', lazy=True))

class Thread(db.Model):
    __tablename__ = 'threads'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # The actual string ID used in external systems
    thread_id = db.Column(db.String(100), nullable=False, index=True) 
    project_id = db.Column(db.String(50), db.ForeignKey('projects.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    remark = db.Column(db.Text, nullable=True)
    
    # Cache fields
    last_synced_at = db.Column(db.Integer, nullable=True) # unix timestamp
    message_count = db.Column(db.Integer, default=0)
    total_tokens = db.Column(db.Integer, default=0)
    
    # Smart refresh fields
    last_message_timestamp = db.Column(db.Integer, nullable=True)  # Latest message timestamp
    stale_refresh_count = db.Column(db.Integer, default=0)         # Consecutive no-change refreshes
    refresh_priority = db.Column(db.String(20), default='normal')  # normal / low / frozen
    
    messages = db.relationship('Message', backref='thread', lazy=True, cascade="all, delete-orphan")

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    thread_id = db.Column(db.Integer, db.ForeignKey('threads.id'), nullable=False, index=True)
    role = db.Column(db.String(20), nullable=False) # user / assistant
    content = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.Integer, nullable=False) # unix timestamp
    
    # Optional: store full JSON just in case? No, waste of space.
    
class SearchHistory(db.Model):
    __tablename__ = 'search_history'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.Integer, nullable=False)
    project_name = db.Column(db.String(100))
    target_query = db.Column(db.String(200))
    date_range = db.Column(db.String(50))
    match_count = db.Column(db.Integer)
    total_scanned = db.Column(db.Integer)
    # Storing pure JSON string for debug details
    api_results_json = db.Column(db.Text)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    user_name = db.Column(db.String(80))
    action = db.Column(db.String(50))
    target = db.Column(db.String(100))
    status = db.Column(db.String(20))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))

class IPBan(db.Model):
    __tablename__ = 'ip_bans'
    ip = db.Column(db.String(45), primary_key=True)
    reason = db.Column(db.String(200))
    expires_at = db.Column(db.Float) # -1 for permanent, else unix timestamp

class SearchResultChunk(db.Model):
    __tablename__ = 'search_result_chunks'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    task_id = db.Column(db.String(100), index=True) 
    page_index = db.Column(db.Integer)
    data_json = db.Column(db.Text) # JSON list of 50 threads
    metadata = db.Column(db.Text) # JSON metadata for progress tracking
    created_at = db.Column(db.Integer, default=lambda: int(datetime.now().timestamp()))

class SystemMetric(db.Model):
    __tablename__ = 'sys_metrics'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.Integer, index=True, nullable=False)
    cpu_percent = db.Column(db.Float)
    memory_percent = db.Column(db.Float)
    memory_used = db.Column(db.Float) # GB
    memory_total = db.Column(db.Float) # GB
    total_managed_tokens = db.Column(db.Integer, default=0) # System-wide total

class RefreshHistory(db.Model):
    __tablename__ = 'refresh_history'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.Integer, nullable=False, index=True) # Start Time
    duration = db.Column(db.Float) # Seconds
    result_status = db.Column(db.String(20)) # Success / Partial / Failed
    
    total_scanned = db.Column(db.Integer, default=0)
    updated_count = db.Column(db.Integer, default=0)
    error_count = db.Column(db.Integer, default=0)
    
    log_json = db.Column(db.Text) # JSON string for error details (Limited size)

class SystemSetting(db.Model):
    __tablename__ = 'system_settings'
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.Text, nullable=True) # JSON content
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

