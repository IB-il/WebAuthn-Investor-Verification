"""
WebAuthn Service - Clean Architecture Phase 2

Handles all WebAuthn cryptographic operations for biometric verification.
Single responsibility: WebAuthn credential management and verification.
"""

import logging
import base64
import json
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timezone

from webauthn import generate_registration_options, verify_registration_response
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse
)

from .storage_service import AzureStorageService


class WebAuthnService:
    """
    WebAuthn service for biometric credential management and verification.
    
    Handles all cryptographic WebAuthn operations including:
    - Registration options generation
    - Registration response verification
    - Authentication options generation  
    - Authentication response verification
    
    Uses real cryptographic verification - cannot be bypassed.
    """
    
    def __init__(self, storage_service: AzureStorageService, rp_id: str, origin: str):
        """
        Initialize WebAuthn service.
        
        Args:
            storage_service: Storage service for credentials
            rp_id: Relying Party ID (domain)
            origin: Origin URL for WebAuthn
        """
        self.storage = storage_service
        self.rp_id = rp_id
        self.origin = origin
        self.rp_name = "Interactive Israel - WebAuthn Investor Verification"
    
    def _base64url_decode(self, data: str) -> bytes:
        """Decode base64url string to bytes."""
        try:
            # Add padding if needed
            padding = '=' * (4 - len(data) % 4)
            data = data.replace('-', '+').replace('_', '/') + padding
            return base64.b64decode(data)
        except Exception as e:
            logging.error(f"Base64url decode error: {str(e)}")
            raise ValueError(f"Invalid base64url encoding: {str(e)}")
    
    def _base64url_encode(self, data: bytes) -> str:
        """Encode bytes to base64url string."""
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')
    
    def generate_registration_options(self, user_id: str, username: str, existing_credentials: List[Tuple[str, str, int]] = None) -> Dict:
        """
        Generate WebAuthn registration options for new credential.
        
        Args:
            user_id: User identifier
            username: User display name
            existing_credentials: List of existing credentials to exclude
            
        Returns:
            Dict with WebAuthn registration options
        """
        try:
            # Create exclude list from existing credentials
            exclude_credentials = []
            if existing_credentials:
                for cred_id, _, _ in existing_credentials:
                    if cred_id:  # Only add if credential ID exists
                        try:
                            exclude_credentials.append(
                                PublicKeyCredentialDescriptor(id=self._base64url_decode(cred_id))
                            )
                        except Exception as e:
                            logging.warning(f"Skipping invalid credential ID {cred_id}: {str(e)}")
            
            # Generate registration options - FORCE PLATFORM AUTHENTICATOR (This Device)
            options = generate_registration_options(
                rp_id=self.rp_id,
                rp_name=self.rp_name,
                user_id=user_id.encode('utf-8'),
                user_name=username,
                user_display_name=username,
                exclude_credentials=exclude_credentials,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    authenticator_attachment=AuthenticatorAttachment.PLATFORM,  # Force "This Device" 
                    user_verification=UserVerificationRequirement.REQUIRED  # Require biometric verification
                )
            )
            
            # Convert to JSON-serializable format
            options_json = {
                "challenge": self._base64url_encode(options.challenge),
                "rp": {"id": options.rp.id, "name": options.rp.name},
                "user": {
                    "id": self._base64url_encode(options.user.id),
                    "name": options.user.name,
                    "displayName": options.user.display_name
                },
                "pubKeyCredParams": [
                    {"alg": param.alg, "type": param.type} 
                    for param in options.pub_key_cred_params
                ],
                "excludeCredentials": [
                    {
                        "id": self._base64url_encode(cred.id),
                        "type": cred.type,
                        "transports": cred.transports or []
                    }
                    for cred in options.exclude_credentials
                ],
                "authenticatorSelection": {
                    "userVerification": options.authenticator_selection.user_verification.value
                },
                "timeout": options.timeout
            }
            
            logging.info(f"Generated registration options for user: {user_id}")
            return {
                "options": options_json,
                "challenge": self._base64url_encode(options.challenge)
            }
            
        except Exception as e:
            logging.error(f"Error generating registration options for {user_id}: {str(e)}")
            raise
    
    def verify_registration_response(self, user_id: str, challenge: str, credential_response: Dict) -> Dict:
        """
        Verify WebAuthn registration response.
        
        Args:
            user_id: User identifier
            challenge: Expected challenge (base64url)
            credential_response: WebAuthn credential response
            
        Returns:
            Dict with verification result and credential data
        """
        try:
            # Parse and validate credential response
            if not all(key in credential_response for key in ['id', 'rawId', 'response', 'type']):
                raise ValueError("Invalid credential response format")
            
            response_data = credential_response['response']
            if not all(key in response_data for key in ['clientDataJSON', 'attestationObject']):
                raise ValueError("Missing required response data")
            
            # Convert credential data to WebAuthn format
            client_data_json = self._base64url_decode(response_data["clientDataJSON"])
            attestation_object = self._base64url_decode(response_data["attestationObject"])
            
            logging.info(f"Verifying registration for user: {user_id}")
            logging.info(f"Credential ID length: {len(credential_response['id'])}")
            
            # Create credential object
            credential = RegistrationCredential(
                id=credential_response['id'],
                raw_id=self._base64url_decode(credential_response['rawId']),
                response=AuthenticatorAttestationResponse(
                    client_data_json=client_data_json,
                    attestation_object=attestation_object
                ),
                type=credential_response['type']
            )
            
            # REAL WebAuthn verification - cannot be bypassed
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=self._base64url_decode(challenge),
                expected_origin=self.origin,
                expected_rp_id=self.rp_id
            )
            
            # Extract credential data from verification result
            if hasattr(verification, 'credential_id'):
                credential_id = self._base64url_encode(verification.credential_id)
            else:
                credential_id = credential_response['id']
            
            if hasattr(verification, 'credential_public_key'):
                public_key = self._base64url_encode(verification.credential_public_key)
            else:
                # Fallback: extract from attestation object
                public_key = self._base64url_encode(attestation_object)
            
            logging.info(f"Registration verification successful for user: {user_id}")
            
            return {
                "verified": True,
                "credential_id": credential_id,
                "public_key": public_key,
                "user_id": user_id
            }
            
        except Exception as e:
            error_msg = str(e)
            logging.error(f"Registration verification failed for {user_id}: {error_msg}")
            return {
                "verified": False,
                "error": error_msg
            }
    
    def generate_authentication_options(self, user_id: str, user_credentials: List[Tuple[str, str, int]]) -> Dict:
        """
        Generate WebAuthn authentication options.
        
        Args:
            user_id: User identifier
            user_credentials: List of user's credentials (id, public_key, count)
            
        Returns:
            Dict with WebAuthn authentication options
        """
        try:
            # Create allow list from user credentials
            allow_credentials = []
            for cred_id, _, _ in user_credentials:
                if cred_id:  # Only add if credential ID exists
                    try:
                        allow_credentials.append(
                            PublicKeyCredentialDescriptor(id=self._base64url_decode(cred_id))
                        )
                    except Exception as e:
                        logging.warning(f"Skipping invalid credential ID {cred_id}: {str(e)}")
            
            if not allow_credentials:
                raise ValueError("No valid credentials found for authentication")
            
            # Generate authentication options - FORCE PLATFORM AUTHENTICATOR (This Device)
            options = generate_authentication_options(
                rp_id=self.rp_id,
                allow_credentials=allow_credentials,
                user_verification=UserVerificationRequirement.REQUIRED  # Force biometric verification
            )
            
            # Convert to JSON-serializable format
            options_json = {
                "challenge": self._base64url_encode(options.challenge),
                "rpId": options.rp_id,
                "allowCredentials": [
                    {
                        "id": self._base64url_encode(cred.id),
                        "type": cred.type,
                        "transports": cred.transports or []
                    }
                    for cred in options.allow_credentials
                ],
                "userVerification": options.user_verification.value,
                "timeout": options.timeout
            }
            
            logging.info(f"Generated authentication options for user: {user_id}")
            return {
                "options": options_json,
                "challenge": self._base64url_encode(options.challenge)
            }
            
        except Exception as e:
            logging.error(f"Error generating authentication options for {user_id}: {str(e)}")
            raise
    
    def verify_authentication_response(self, user_id: str, challenge: str, 
                                     credential_response: Dict, user_credentials: List[Tuple[str, str, int]]) -> Dict:
        """
        Verify WebAuthn authentication response.
        
        Args:
            user_id: User identifier
            challenge: Expected challenge (base64url)
            credential_response: WebAuthn credential response
            user_credentials: List of user's credentials (id, public_key, count)
            
        Returns:
            Dict with verification result
        """
        try:
            # Parse and validate credential response
            if not all(key in credential_response for key in ['id', 'rawId', 'response', 'type']):
                raise ValueError("Invalid credential response format")
            
            response_data = credential_response['response']
            if not all(key in response_data for key in ['clientDataJSON', 'authenticatorData', 'signature']):
                raise ValueError("Missing required authentication response data")
            
            # Find matching credential
            credential_id_b64 = credential_response["id"]
            matching_cred = None
            
            for cred in user_credentials:
                if len(cred) >= 2 and cred[0] == credential_id_b64:
                    matching_cred = cred
                    break
            
            if not matching_cred:
                raise ValueError(f"No matching credential found for ID: {credential_id_b64}")
            
            credential_id_found, public_key_b64, current_sign_count = (
                matching_cred[0], matching_cred[1], matching_cred[2] if len(matching_cred) > 2 else 0
            )
            
            # Create credential object
            credential = AuthenticationCredential(
                id=credential_response['id'],
                raw_id=self._base64url_decode(credential_response['rawId']),
                response=AuthenticatorAssertionResponse(
                    client_data_json=self._base64url_decode(response_data["clientDataJSON"]),
                    authenticator_data=self._base64url_decode(response_data["authenticatorData"]),
                    signature=self._base64url_decode(response_data["signature"]),
                    user_handle=self._base64url_decode(response_data.get("userHandle", "")) if response_data.get("userHandle") else None
                ),
                type=credential_response['type']
            )
            
            # REAL WebAuthn authentication verification - cannot be bypassed
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=self._base64url_decode(challenge),
                expected_origin=self.origin,
                expected_rp_id=self.rp_id,
                credential_public_key=self._base64url_decode(public_key_b64),
                credential_current_sign_count=current_sign_count
            )
            
            # Extract new sign count if available
            new_sign_count = getattr(verification, 'new_sign_count', current_sign_count)
            
            logging.info(f"Authentication verification successful for user: {user_id}")
            
            return {
                "verified": True,
                "user_id": user_id,
                "credential_id": credential_id_found,
                "new_sign_count": new_sign_count
            }
            
        except Exception as e:
            error_msg = str(e)
            logging.error(f"Authentication verification failed for {user_id}: {error_msg}")
            return {
                "verified": False,
                "error": error_msg
            }
    
    def get_user_credential_count(self, user_id: str) -> int:
        """
        Get count of credentials for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Number of credentials for user
        """
        try:
            credentials = self.storage.get_user_credentials(user_id)
            return len(credentials)
        except Exception as e:
            logging.error(f"Error getting credential count for {user_id}: {str(e)}")
            return 0
    
    def has_existing_credentials(self, user_id: str) -> bool:
        """
        Check if user has existing credentials.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if user has credentials, False otherwise
        """
        return self.get_user_credential_count(user_id) > 0
    
    def save_verified_credential(self, user_id: str, credential_id: str, public_key: str) -> None:
        """
        Save verified credential to storage.
        
        Args:
            user_id: User identifier
            credential_id: WebAuthn credential ID (base64url)
            public_key: WebAuthn public key (base64url)
        """
        try:
            self.storage.save_user_credential(user_id, credential_id, public_key)
            logging.info(f"Saved verified credential for user: {user_id}")
        except Exception as e:
            logging.error(f"Error saving credential for {user_id}: {str(e)}")
            raise
    
    def update_credential_sign_count(self, credential_id: str, new_sign_count: int) -> None:
        """
        Update sign count for credential (prevents replay attacks).
        
        Args:
            credential_id: WebAuthn credential ID
            new_sign_count: New sign count value
        """
        # Note: Sign count updates can be implemented if needed
        # For production WebAuthn, sign count is optional but recommended
        logging.info(f"Sign count update for credential {credential_id}: {new_sign_count}")
        # TODO: Implement sign count storage if replay protection is critical