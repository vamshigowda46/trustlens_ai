"""
MySQL persistence for multi-turn chat (conversations + messages).
Safe to call repeatedly — uses CREATE TABLE IF NOT EXISTS once per process flag from caller.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SCHEMA_SQL = [
    """
    CREATE TABLE IF NOT EXISTS chat_conversations (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      title VARCHAR(200) NOT NULL DEFAULT 'New chat',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      KEY idx_chat_user_updated (user_id, updated_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS chat_messages (
      id INT AUTO_INCREMENT PRIMARY KEY,
      conversation_id INT NOT NULL,
      role ENUM('user','assistant','system') NOT NULL,
      content MEDIUMTEXT NOT NULL,
      meta TEXT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      KEY idx_chat_msg_conv (conversation_id, id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
]


def ensure_schema(cursor) -> None:
    for sql in _SCHEMA_SQL:
        cursor.execute(sql)


def create_conversation(cursor, user_id: int, title: str = "New chat") -> int:
    cursor.execute(
        "INSERT INTO chat_conversations (user_id, title) VALUES (%s, %s)",
        (user_id, title[:200]),
    )
    return int(cursor.lastrowid)


def list_conversations(cursor, user_id: int, limit: int = 40) -> List[Dict[str, Any]]:
    cursor.execute(
        """
        SELECT id, title, created_at, updated_at
        FROM chat_conversations
        WHERE user_id=%s
        ORDER BY updated_at DESC
        LIMIT %s
        """,
        (user_id, int(limit)),
    )
    rows = cursor.fetchall() or []
    out = []
    for r in rows:
        out.append(
            {
                "id": r["id"],
                "title": r["title"],
                "created_at": str(r["created_at"]) if r.get("created_at") else "",
                "updated_at": str(r["updated_at"]) if r.get("updated_at") else "",
            }
        )
    return out


def conversation_owned(cursor, conversation_id: int, user_id: int) -> bool:
    cursor.execute(
        "SELECT id FROM chat_conversations WHERE id=%s AND user_id=%s LIMIT 1",
        (conversation_id, user_id),
    )
    return bool(cursor.fetchone())


def delete_conversation(cursor, conversation_id: int, user_id: int) -> bool:
    if not conversation_owned(cursor, conversation_id, user_id):
        return False
    cursor.execute("DELETE FROM chat_conversations WHERE id=%s AND user_id=%s", (conversation_id, user_id))
    return True


def fetch_messages_for_model(cursor, conversation_id: int, user_id: int, limit_pairs: int = 10) -> List[Dict[str, str]]:
    """Return [{'user':..., 'bot':...}, ...] from DB for Grok context."""
    if not conversation_owned(cursor, conversation_id, user_id):
        return []
    n = int(limit_pairs) * 2 + 5
    cursor.execute(
        """
        SELECT role, content FROM chat_messages
        WHERE conversation_id=%s
        ORDER BY id DESC
        LIMIT %s
        """,
        (conversation_id, n),
    )
    rows = list(reversed(cursor.fetchall() or []))
    turns: List[Dict[str, str]] = []
    pending_user: Optional[str] = None
    for r in rows:
        role = (r.get("role") or "").strip()
        content = (r.get("content") or "").strip()
        if role == "user":
            pending_user = content
        elif role == "assistant" and pending_user is not None:
            turns.append({"user": pending_user, "bot": content})
            pending_user = None
    return turns


def append_message(cursor, conversation_id: int, role: str, content: str, meta: Optional[Dict[str, Any]] = None) -> None:
    meta_s = json.dumps(meta)[:8000] if meta is not None else None
    cursor.execute(
        """
        INSERT INTO chat_messages (conversation_id, role, content, meta)
        VALUES (%s, %s, %s, %s)
        """,
        (conversation_id, role, content, meta_s),
    )


def touch_conversation_title(cursor, conversation_id: int, user_id: int, first_user_text: str) -> None:
    title = (first_user_text or "").strip().replace("\n", " ")
    if len(title) > 80:
        title = title[:77] + "..."
    cursor.execute(
        """
        UPDATE chat_conversations
        SET title=IF(title='New chat' AND %s<>'', %s, title), updated_at=CURRENT_TIMESTAMP
        WHERE id=%s AND user_id=%s
        """,
        (title, title, conversation_id, user_id),
    )


def get_last_user_message(cursor, conversation_id: int, user_id: int) -> Optional[str]:
    if not conversation_owned(cursor, conversation_id, user_id):
        return None
    cursor.execute(
        """
        SELECT content FROM chat_messages
        WHERE conversation_id=%s AND role='user'
        ORDER BY id DESC LIMIT 1
        """,
        (conversation_id,),
    )
    row = cursor.fetchone()
    return (row.get("content") or "").strip() if row else None


def delete_last_assistant(cursor, conversation_id: int, user_id: int) -> bool:
    """Remove the most recent assistant message (for regenerate)."""
    if not conversation_owned(cursor, conversation_id, user_id):
        return False
    cursor.execute(
        """
        SELECT id FROM chat_messages
        WHERE conversation_id=%s AND role='assistant'
        ORDER BY id DESC LIMIT 1
        """,
        (conversation_id,),
    )
    row = cursor.fetchone()
    if not row:
        return False
    cursor.execute("DELETE FROM chat_messages WHERE id=%s", (row["id"],))
    return True


def fetch_messages_ui(cursor, conversation_id: int, user_id: int, limit: int = 200) -> List[Dict[str, Any]]:
    if not conversation_owned(cursor, conversation_id, user_id):
        return []
    cursor.execute(
        """
        SELECT id, role, content, created_at
        FROM chat_messages
        WHERE conversation_id=%s
        ORDER BY id ASC
        LIMIT %s
        """,
        (conversation_id, int(limit)),
    )
    rows = cursor.fetchall() or []
    return [
        {
            "id": r["id"],
            "role": r["role"],
            "content": r["content"],
            "created_at": str(r["created_at"]) if r.get("created_at") else "",
        }
        for r in rows
    ]

