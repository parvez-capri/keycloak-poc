import random
import string
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakAuthenticationError

class KeycloakManager:
    def __init__(self, server_url, realm_name, client_id, client_secret, redirect_uri):
        self.keycloak_openid = KeycloakOpenID(
            server_url=server_url,
            client_id=client_id,
            realm_name=realm_name,
            client_secret_key=client_secret
        )
        self.redirect_uri = redirect_uri

    def authenticate_user(self, access_token=''):
        try:
            user_info = self.keycloak_openid.userinfo(token=access_token)
            user_info['app'] = 'CGCL_LOS'
            return user_info
        except KeycloakAuthenticationError:
            state = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(30))
            auth_url = self.keycloak_openid.auth_url(
                redirect_uri=f'{self.redirect_uri}?next=protected',
                scope='openid',
                state=state
            )
            return RedirectResponse(auth_url)

    def get_access_token(self, code, state, next_page):
        try:
            redirect_url = f'{self.redirect_uri}?next={next_page}'
            token = self.keycloak_openid.token(
                code=code,
                grant_type='authorization_code',
                redirect_uri=redirect_url,
                state=state
            )
            access_token = token['access_token']
            redirect_url = f'http://localhost:5000/{next_page}?access_token={access_token}'
            return RedirectResponse(redirect_url)
        except Exception as err:
            return {'error_msg': str(err)}

app = FastAPI()

# Keycloak configuration
keycloak_manager = KeycloakManager(
    server_url="http://localhost:8080/auth",
    realm_name="capri_loans",
    client_id="cgcl_los",
    client_secret="QwFWPABdUgxlMledRFcOP2hRTDKRD7kj",
    redirect_uri="http://localhost:5000/callback"
)

@app.get("/public")
def public_api(request: Request):
    return {"message": "This is a public CGCL API"}

@app.get("/protected")
def protected_api(request: Request, access_token=''):
    return keycloak_manager.authenticate_user(access_token=access_token)

@app.get("/callback")
def callback(
    request: Request,
    state: str = None,
    session_state: str = None,
    code: str = None,
    next: str = None
):
    query_params = request.query_params
    if 'next' in query_params:
        next_page = query_params['next']
        return keycloak_manager.get_access_token(code, state, next_page)
    return {'error_msg': 'Invalid request'}
