"""Study OAuth scopes, non-premium grants and authenticated introspection."""
import hashlib
import secrets
import time
from urllib.parse import parse_qs,urlsplit
import pytest
from jose import jwt
from test_ai_mcp import env
import oauth_routes as oauth
from jwt_utils import encode_token, JWT_SECRET_KEY
from api_v1 import _resolve_token_with_scope

@pytest.mark.asyncio
@pytest.mark.parametrize('scope',['study:read study:summary:write','study:read study:summary:write study:notes:write'])
async def test_study_grant_introspection_refresh_revoke(env,scope):
    client=env
    registered=await client.post('/oauth/register',json={'redirect_uris':['http://127.0.0.1/callback'],'client_name':'Study test'})
    cid=registered.json()['client_id'];verifier=secrets.token_urlsafe(32)
    challenge=oauth._b64url(hashlib.sha256(verifier.encode()).digest())
    args={'client_id':cid,'redirect_uri':'http://127.0.0.1:45678/callback','scope':scope,'state':'test','code_challenge':challenge,'code_challenge_method':'S256','resource':oauth.STUDY_RESOURCE,'token':encode_token({'id':3})}
    r=await client.post('/oauth/authorize',json=args);assert r.status_code==200,r.text
    code=parse_qs(urlsplit(r.json()['redirect_url']).query)['code'][0]
    exchange={'grant_type':'authorization_code','client_id':cid,'code':code,'redirect_uri':args['redirect_uri'],'code_verifier':verifier,'resource':oauth.STUDY_RESOURCE}
    token=(await client.post('/oauth/token',data=exchange)).json();assert 'access_token' in token,token
    raw=token['access_token']
    # Loopback credential plus matching token hash required.
    assert (await client.post('/oauth/introspect-study',json={'token':raw})).status_code==401
    now=int(time.time());proof=jwt.encode({'aud':'study-introspection','iat':now,'exp':now+30,'token_hash':hashlib.sha256(raw.encode()).hexdigest()},JWT_SECRET_KEY,algorithm='HS256')
    # ASGI test peer is 127.0.0.1.
    headers={'Authorization':'Bearer '+proof}
    r=await client.post('/oauth/introspect-study',headers=headers,json={'token':raw});assert r.status_code==200,r.text
    assert r.json()['active'] and r.json()['sub']=='3'
    assert set(r.json()['scope'].split())==set(scope.split())
    assert (await client.post('/oauth/introspect-study',headers=headers,json={'token':'other'})).status_code==401
    with pytest.raises(Exception) as error:await _resolve_token_with_scope('Bearer '+raw,'alarm:read')
    assert error.value.status_code==401
    refresh={'grant_type':'refresh_token','client_id':cid,'refresh_token':token['refresh_token'],'resource':oauth.STUDY_RESOURCE}
    rotated=await client.post('/oauth/token',data=refresh);assert rotated.status_code==200
    assert set(rotated.json()['scope'].split())==set(scope.split())
    assert not (await client.post('/oauth/introspect-study',headers=headers,json={'token':raw})).json()['active']
    assert (await client.post('/oauth/token',data=refresh)).status_code==400
    await client.post('/oauth/revoke',data={'token':rotated.json()['refresh_token']})
    assert (await client.post('/oauth/authorize',json={**args,'scope':'alarm:read'})).status_code==400
    assert (await client.post('/oauth/authorize',json={**args,'resource':'','scope':'study:read'})).status_code==400
    page=await client.get('/oauth/authorize',params={k:v for k,v in args.items() if k!='token'})
    assert 'Study 授權請求' in page.text and '學習資料' in page.text
