# engine/auth/session.py
import json
import urllib.request
import urllib.error

class AnvilAuthManager:
    """Manages stateful authentication sequences (JWT/Cookies) for DAST testing."""

    def __init__(self, login_url: str):
        self.login_url = login_url
        self.session_headers = {"Content-Type": "application/json"}

    def authenticate(self, username: str, password: str, token_key: str = "token") -> dict:
        """
        Executes a login request and extracts the authentication token.
        Returns the headers required to authenticate subsequent requests.
        """
        print(f"[ANVIL AUTH] Attempting stateful authentication at: {self.login_url}")
        
        payload = json.dumps({
            "username": username,
            "password": password,
            "email": username # Common fallback
        }).encode("utf-8")
        
        req = urllib.request.Request(self.login_url, data=payload, headers=self.session_headers, method="POST")
        
        try:
            with urllib.request.urlopen(req, timeout=5.0) as response:
                if response.status == 200:
                    body = json.loads(response.read().decode('utf-8'))
                    
                    # Look for JWT Token in JSON response
                    if token_key in body:
                        token = body[token_key]
                        self.session_headers["Authorization"] = f"Bearer {token}"
                        print("[ANVIL AUTH] [+] JWT Bearer Token extracted successfully.")
                        return self.session_headers
                    
                    # Look for Session Cookies
                    set_cookie = response.headers.get('Set-Cookie')
                    if set_cookie:
                        self.session_headers["Cookie"] = set_cookie.split(";")[0]
                        print("[ANVIL AUTH] [+] Session Cookie extracted successfully.")
                        return self.session_headers

                    print("[ANVIL AUTH] [-] Login succeeded, but no token or cookie found in response.")
                else:
                    print(f"[ANVIL AUTH] [-] Login failed with status code: {response.status}")
                    
        except urllib.error.HTTPError as e:
            print(f"[ANVIL AUTH] [-] Authentication rejected (HTTP {e.code}).")
        except Exception as e:
            print(f"[ANVIL AUTH] [-] Connection error during login: {e}")

        return self.session_headers