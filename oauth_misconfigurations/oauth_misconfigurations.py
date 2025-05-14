import secrets
import hashlib
import base64
import time
import requests
from typing import Dict, Optional
from jose import jwt, JWTError  # Requires: pip install python-jose

# === Configuration ===
AUTH_SERVER = "https://auth-server.com"
CLIENT_ID = "client123"
CLIENT_SECRET = "supersecret"  # In production, store securely!
REDIRECT_URI = "https://example.com/callback"
JWKS_URL = f"{AUTH_SERVER}/.well-known/jwks.json"

class OAuthClient:
    """
    Implements OAuth 2.0 Authorization Code Flow with PKCE and secure token handling.
    """
    def __init__(self, redirect_uri: str):
        # Store redirect URI for validation
        self.redirect_uri = redirect_uri
        # Generate PKCE code verifier and challenge for this session
        self.code_verifier, self.code_challenge = self.generate_pkce()
        # Generate a cryptographically secure state parameter for CSRF protection
        self.state = self.generate_state()
        # Fetch JWKS (public keys) for JWT validation
        self.jwks = self._fetch_jwks()
        # Token storage
        self.access_token = None
        self.refresh_token = None
        self.expires_at = 0

    def generate_pkce(self) -> (str, str):
        """
        Generate PKCE code verifier and corresponding challenge.
        """
        code_verifier = secrets.token_urlsafe(64)  # High entropy string
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode('utf-8').rstrip('=')
        return code_verifier, code_challenge

    def generate_state(self) -> str:
        """
        Generate a random state parameter to prevent CSRF.
        """
        return secrets.token_urlsafe(32)

    def _fetch_jwks(self) -> Dict:
        """
        Fetch JWKS (JSON Web Key Set) for JWT signature validation.
        """
        try:
            response = requests.get(JWKS_URL, timeout=5)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception("Failed to fetch JWKS") from e

    def _store_tokens(self, token_response: Dict):
        """
        Securely store access and refresh tokens with expiration.
        In production, use encrypted, secure storage.
        """
        self.access_token = token_response.get('access_token')
        self.refresh_token = token_response.get('refresh_token')
        # Calculate expiration time (now + expires_in seconds)
        self.expires_at = time.time() + token_response.get('expires_in', 3600)

    def validate_token(self, token: str) -> bool:
        """
        Validate JWT locally and via token introspection endpoint.
        """
        # First, validate JWT signature and claims locally
        if not self._validate_jwt(token):
            return False

        # Then, check token status with the authorization server
        data = {
            'token': token,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
        }
        try:
            response = requests.post(
                f"{AUTH_SERVER}/introspect",
                data=data,
                timeout=5
            )
            response.raise_for_status()
            return response.json().get('active', False)
        except Exception as e:
            raise Exception("Token introspection failed") from e

    def _validate_jwt(self, token: str) -> bool:
        """
        Validate JWT signature, issuer, audience, and expiration.
        """
        try:
            # Extract the key id from the JWT header
            header = jwt.get_unverified_header(token)
            kid = header['kid']
            # Find the matching public key in JWKS
            key = next(k for k in self.jwks['keys'] if k['kid'] == kid)
            # Decode and validate the JWT
            claims = jwt.decode(
                token,
                key,
                algorithms=[key['alg']],
                audience=CLIENT_ID,
                issuer=AUTH_SERVER
            )
            # Check expiration
            return claims['exp'] > time.time()
        except (JWTError, KeyError, StopIteration):
            return False

    def refresh_access_token(self) -> Optional[str]:
        """
        Refresh the access token using the refresh token.
        """
        if not self.refresh_token:
            return None

        data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
        }

        try:
            response = requests.post(
                f"{AUTH_SERVER}/token",
                data=data,
                timeout=5
            )
            response.raise_for_status()
            self._store_tokens(response.json())
            return self.access_token
        except Exception as e:
            raise Exception("Token refresh failed") from e

    def make_authenticated_request(self, url: str) -> Optional[Dict]:
        """
        Make an API request using the access token, refreshing if needed.
        """
        # Refresh token if expired
        if time.time() > self.expires_at:
            if not self.refresh_access_token():
                print("Token refresh failed or not available.")
                return None

        # Validate token before making request
        if not self.validate_token(self.access_token):
            print("Token is invalid or inactive.")
            return None

        headers = {'Authorization': f'Bearer {self.access_token}'}
        try:
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print("API request failed:", str(e))
            return None

# === Example Usage ===

# Step 1: Initialize OAuth client with your redirect URI
client = OAuthClient(REDIRECT_URI)

# Step 2: Direct the user to the authorization URL (handled by your web frontend)
print("Go to the following URL to authorize:")
print(
    f"{AUTH_SERVER}/authorize?"
    f"client_id={CLIENT_ID}&"
    f"redirect_uri={REDIRECT_URI}&"
    f"response_type=code&"
    f"scope=profile email&"
    f"state={client.state}&"
    f"code_challenge={client.code_challenge}&"
    f"code_challenge_method=S256"
)

# Step 3: After user authorizes, they are redirected back to your redirect_uri with ?code=...&state=...
# You would extract 'code' and 'state' from the redirect parameters in your web backend.

# For demonstration, let's assume you have received the code and validated the state:
# (In a real web app, this would be handled by your web framework's route/controller.)
authorization_code = "RECEIVED_FROM_CALLBACK"
received_state = "RECEIVED_FROM_CALLBACK"

if received_state != client.state:
    print("State mismatch! Possible CSRF attack.")
else:
    # Step 4: Exchange the authorization code for tokens
    data = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'code_verifier': client.code_verifier,
        'client_secret': CLIENT_SECRET  # Only for confidential clients
    }
    try:
        response = requests.post(f"{AUTH_SERVER}/token", data=data, timeout=5)
        response.raise_for_status()
        client._store_tokens(response.json())
        print("Tokens obtained and stored securely.")
    except Exception as e:
        print("Token exchange failed:", str(e))

    # Step 5: Use the access token to call a protected API
    api_response = client.make_authenticated_request("https://api.example.com/user")
    if api_response:
        print("Protected data:", api_response)
    else:
        print("Failed to retrieve protected data.")

# === End of Example ===

# Notes:
# - In production, always use HTTPS for all endpoints.
# - Store CLIENT_SECRET and tokens in secure, encrypted storage.
# - Implement error logging and alerting for security events.
# - Regularly rotate secrets and monitor for suspicious activity.
