# backend/app/routes/admin/forms.py

"""Form definitions for admin thread operations.

These forms centralize validation logic for adding a new thread and can be
extended in the future for other admin actions.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, HiddenField
from wtforms.validators import DataRequired, Regexp, Length, Optional


class AddThreadForm(FlaskForm):
    """Validate the fields required to add a new thread.

    * ``thread_id`` – must start with ``thread_`` and contain only alphanumeric
      characters.
    * ``remark`` – optional free‑text, limited to 200 characters.
    * ``group_id`` – hidden field identifying the project (required).
    """

    class Meta:
        # CSRF is enabled by default in Flask-WTF if not explicitly disabled.
        # We want it enabled for security.
        pass

    thread_id = StringField(
        "Thread ID",
        validators=[
            DataRequired(message="Thread ID 為必填"),
            Regexp(r"^thread_[A-Za-z0-9]+$", message="Thread ID 格式錯誤 (必須以 thread_ 開頭，且僅包含英數字)"),
        ],
    )
    remark = StringField(
        "Remark",
        validators=[Optional(), Length(max=200, message="Remark 最多 200 字元")],
    )
    group_id = HiddenField(validators=[DataRequired(message="Group ID 為必填")])
