"""
Azure Storage Service - Clean Architecture Phase 1

Handles all Azure Table Storage operations for credentials and sessions.
Single responsibility: Data persistence layer.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from azure.data.tables import TableServiceClient


class AzureStorageService:
    """
    Azure Table Storage service for WebAuthn credential and session management.
    
    Production-grade service with error handling and logging.
    Supports both credentials and sessions tables.
    """
    
    def __init__(self, connection_string: str):
        """Initialize Azure Table Storage service."""
        self.connection_string = connection_string
        self.table_service_client = None
        self.credentials_table = "credentials"
        self.sessions_table = "sessions"
        
        self._initialize_storage()
    
    def _initialize_storage(self) -> None:
        """Initialize Azure Table Storage client and create tables."""
        if not self.connection_string:
            logging.error("Azure Storage connection string not provided")
            return
            
        try:
            self.table_service_client = TableServiceClient.from_connection_string(
                self.connection_string
            )
            
            # Create tables if they don't exist
            self.table_service_client.create_table_if_not_exists(self.credentials_table)
            self.table_service_client.create_table_if_not_exists(self.sessions_table)
            
            logging.info("Azure Table Storage initialized successfully")
        except Exception as e:
            logging.error(f"Failed to initialize Azure Table Storage: {str(e)}")
            self.table_service_client = None
    
    def is_available(self) -> bool:
        """Check if Azure Table Storage is available."""
        return self.table_service_client is not None
    
    # Credentials Management
    
    def load_credentials(self) -> Dict[str, Dict[str, str]]:
        """
        Load all credentials from Azure Table Storage.
        
        Returns:
            Dict mapping user_id to credential data
        """
        if not self.is_available():
            logging.error("Azure Table Storage not available - credentials unavailable")
            return {}
        
        try:
            table_client = self.table_service_client.get_table_client(self.credentials_table)
            entities = table_client.list_entities()
            
            data = {}
            for entity in entities:
                data[entity['RowKey']] = {
                    'credential_id': entity.get('credential_id', ''),
                    'public_key': entity.get('public_key', '')
                }
            
            logging.info(f"Loaded credentials for {len(data)} users")
            return data
            
        except Exception as e:
            logging.error(f"Error loading credentials from Azure Table Storage: {str(e)}")
            return {}
    
    def save_credentials(self, data: Dict[str, Dict[str, str]]) -> None:
        """
        Save credentials to Azure Table Storage.
        
        Args:
            data: Dict mapping user_id to credential data
        """
        if not self.is_available():
            logging.error("Azure Table Storage not available - cannot save credentials")
            raise Exception("Storage unavailable - Azure Table Storage required for production")
        
        try:
            table_client = self.table_service_client.get_table_client(self.credentials_table)
            
            for user_id, cred_data in data.items():
                entity = {
                    'PartitionKey': 'credentials',
                    'RowKey': user_id,
                    'credential_id': cred_data.get('credential_id', ''),
                    'public_key': cred_data.get('public_key', '')
                }
                table_client.upsert_entity(entity)
            
            logging.info(f"Credentials saved successfully for {len(data)} users")
            
        except Exception as e:
            logging.error(f"Error saving credentials to Azure Table Storage: {str(e)}")
            raise
    
    def save_user_credential(self, user_id: str, credential_id: str, public_key: str) -> None:
        """
        Save single user credential to Azure Table Storage.
        
        Args:
            user_id: User identifier
            credential_id: WebAuthn credential ID (base64)
            public_key: WebAuthn public key (base64)
        """
        if not self.is_available():
            raise Exception("Storage unavailable - Azure Table Storage required")
        
        try:
            table_client = self.table_service_client.get_table_client(self.credentials_table)
            
            entity = {
                'PartitionKey': 'credentials',
                'RowKey': user_id,
                'credential_id': credential_id,
                'public_key': public_key
            }
            
            table_client.upsert_entity(entity)
            logging.info(f"Credential saved for user: {user_id}")
            
        except Exception as e:
            logging.error(f"Error saving credential for user {user_id}: {str(e)}")
            raise
    
    def get_user_credentials(self, user_id: str) -> List[Tuple[str, str, int]]:
        """
        Get credentials for specific user in legacy tuple format.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of tuples: (credential_id, public_key, counter)
        """
        credentials_data = self.load_credentials()
        user_cred = credentials_data.get(user_id, {})
        
        if user_cred:
            # Convert new dict format to old tuple format for compatibility
            return [(
                user_cred.get('credential_id', ''), 
                user_cred.get('public_key', ''), 
                0  # Counter not used in current implementation
            )]
        return []
    
    # Sessions Management
    
    def load_sessions(self) -> Dict[str, Dict]:
        """
        Load all sessions from Azure Table Storage.
        
        Returns:
            Dict mapping token to session data
        """
        if not self.is_available():
            logging.error("Azure Table Storage not available - sessions unavailable")
            return {}
        
        try:
            table_client = self.table_service_client.get_table_client(self.sessions_table)
            entities = table_client.list_entities()
            
            data = {}
            for entity in entities:
                # Convert ISO string back to datetime object
                expires_at_str = entity.get('expires_at', '')
                try:
                    expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                except ValueError:
                    expires_at = datetime.now(timezone.utc)
                
                data[entity['RowKey']] = {
                    'user_id': entity.get('user_id', ''),
                    'challenge': entity.get('challenge', ''),
                    'verified': entity.get('verified', False),
                    'expires_at': expires_at,
                    'username': entity.get('username', '')
                }
            
            logging.info(f"Loaded {len(data)} sessions")
            return data
            
        except Exception as e:
            logging.error(f"Error loading sessions from Azure Table Storage: {str(e)}")
            return {}
    
    def save_sessions(self, data: Dict[str, Dict]) -> None:
        """
        Save sessions to Azure Table Storage.
        
        Args:
            data: Dict mapping token to session data
        """
        if not self.is_available():
            logging.error("Azure Table Storage not available - cannot save sessions")
            raise Exception("Storage unavailable - Azure Table Storage required for production")
        
        try:
            table_client = self.table_service_client.get_table_client(self.sessions_table)
            
            for token, session_data in data.items():
                # Convert datetime to ISO string for storage
                expires_at = session_data.get('expires_at')
                if isinstance(expires_at, datetime):
                    expires_at_str = expires_at.isoformat()
                else:
                    expires_at_str = str(expires_at)
                
                entity = {
                    'PartitionKey': 'sessions',
                    'RowKey': token,
                    'user_id': session_data.get('user_id', ''),
                    'challenge': session_data.get('challenge', ''),
                    'verified': session_data.get('verified', False),
                    'expires_at': expires_at_str
                }
                
                table_client.upsert_entity(entity)
            
            logging.info(f"Sessions saved successfully for {len(data)} tokens")
            
        except Exception as e:
            logging.error(f"Error saving sessions to Azure Table Storage: {str(e)}")
            raise
    
    def save_session(self, token: str, user_id: str, challenge: str, 
                     expires_at: datetime, verified: bool = False) -> None:
        """
        Save single session to Azure Table Storage.
        
        Args:
            token: JWT token
            user_id: User identifier
            challenge: WebAuthn challenge (base64)
            expires_at: Session expiration datetime
            verified: Whether session is verified
        """
        if not self.is_available():
            raise Exception("Storage unavailable - Azure Table Storage required")
        
        try:
            table_client = self.table_service_client.get_table_client(self.sessions_table)
            
            entity = {
                'PartitionKey': 'sessions',
                'RowKey': token,
                'user_id': user_id,
                'challenge': challenge,
                'verified': verified,
                'expires_at': expires_at.isoformat()
            }
            
            table_client.upsert_entity(entity)
            logging.info(f"Session saved for token: {token[:10]}...")
            
        except Exception as e:
            logging.error(f"Error saving session {token[:10]}...: {str(e)}")
            raise
    
    def get_session_data(self, token: str) -> Optional[Dict]:
        """
        Get specific session data.
        
        Args:
            token: JWT token
            
        Returns:
            Session data dict or None if not found/expired
        """
        sessions_data = self.load_sessions()
        session = sessions_data.get(token)
        
        if session and session['expires_at'] > datetime.now(timezone.utc):
            return session
        return None
    
    def mark_session_verified(self, token: str) -> None:
        """
        Mark session as verified.
        
        Args:
            token: JWT token to mark as verified
        """
        sessions_data = self.load_sessions()
        if token in sessions_data:
            sessions_data[token]["verified"] = True
            self.save_sessions(sessions_data)
            logging.info(f"Session marked as verified: {token[:10]}...")

    def update_session_challenge(self, token: str, new_challenge: str) -> bool:
        """
        Update session challenge for WebAuthn flow.
        
        Args:
            token: JWT token identifying the session
            new_challenge: New challenge from WebAuthn options
            
        Returns:
            True if update successful, False otherwise
        """
        try:
            sessions_data = self.load_sessions()
            if token in sessions_data:
                sessions_data[token]["challenge"] = new_challenge
                self.save_sessions(sessions_data)
                logging.info(f"Updated session challenge: {token[:10]}...")
                return True
            else:
                logging.warning(f"Session not found for challenge update: {token[:10]}...")
                return False
        except Exception as e:
            logging.error(f"Error updating session challenge: {str(e)}")
            return False
    
    def cleanup_expired_sessions(self) -> int:
        """
        Remove expired sessions from storage.
        
        Returns:
            Number of sessions cleaned up
        """
        if not self.is_available():
            return 0
        
        try:
            sessions_data = self.load_sessions()
            current_time = datetime.now(timezone.utc)
            
            # Find expired sessions
            expired_tokens = [
                token for token, session in sessions_data.items()
                if session['expires_at'] <= current_time
            ]
            
            if expired_tokens:
                # Remove expired sessions
                table_client = self.table_service_client.get_table_client(self.sessions_table)
                for token in expired_tokens:
                    table_client.delete_entity('sessions', token)
                
                logging.info(f"Cleaned up {len(expired_tokens)} expired sessions")
            
            return len(expired_tokens)
            
        except Exception as e:
            logging.error(f"Error during session cleanup: {str(e)}")
            return 0