"""Session Manager for Flow2API - Per-Account Browser Session Management"""
import os
import json
from typing import Optional, Dict, List
from datetime import datetime
from ..core.logger import debug_logger


class SessionManager:
    """Manages browser session files for each token/account."""
    
    SESSION_DIR = "browser_sessions"
    
    def __init__(self):
        """Initialize the session manager and ensure directory exists."""
        os.makedirs(self.SESSION_DIR, exist_ok=True)
    
    def get_session_path(self, token_id: int) -> str:
        """Get the session file path for a given token ID."""
        return os.path.join(self.SESSION_DIR, f"auth_{token_id}.json")
    
    def has_session(self, token_id: int) -> bool:
        """Check if a session file exists for the given token ID."""
        return os.path.exists(self.get_session_path(token_id))
    
    def get_session_status(self, token_id: int) -> Dict:
        """
        Get detailed session status for a token.
        
        Returns:
            {
                "has_session": bool,
                "session_file": str,
                "needs_login": bool,
                "last_modified": str or None,
                "message": str
            }
        """
        session_path = self.get_session_path(token_id)
        has_session = os.path.exists(session_path)
        
        last_modified = None
        if has_session:
            try:
                mtime = os.path.getmtime(session_path)
                last_modified = datetime.fromtimestamp(mtime).isoformat()
            except:
                pass
        
        return {
            "has_session": has_session,
            "session_file": session_path,
            "needs_login": not has_session,
            "last_modified": last_modified,
            "message": "已登录" if has_session else "需要浏览器登录"
        }
    
    def list_all_sessions(self, token_ids: List[int]) -> Dict[int, Dict]:
        """
        Get session status for multiple tokens.
        
        Args:
            token_ids: List of token IDs to check.
            
        Returns:
            Dict mapping token_id to session status.
        """
        return {tid: self.get_session_status(tid) for tid in token_ids}
    
    def delete_session(self, token_id: int) -> bool:
        """Delete a session file for a token."""
        session_path = self.get_session_path(token_id)
        if os.path.exists(session_path):
            try:
                os.remove(session_path)
                debug_logger.log_info(f"[SessionManager] Deleted session for token {token_id}")
                return True
            except Exception as e:
                debug_logger.log_error(f"[SessionManager] Failed to delete session: {e}")
                return False
        return True  # Already doesn't exist


# Singleton instance
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Get the singleton SessionManager instance."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager
