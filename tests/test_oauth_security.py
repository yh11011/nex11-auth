"""Focused validation checks without production accounts or side effects."""
import pytest
from oauth_routes import validate_authorization, redirect_matches, RESOURCE, _verify_pkce_s256

def test_resource_pkce_scope_validation():
    for scope,challenge,method,resource in [('admin','a'*43,'S256',RESOURCE),('alarm:read','','S256',RESOURCE),('alarm:read','a'*43,'plain',RESOURCE),('alarm:read','a'*43,'S256','https://other.example/mcp')]:
        with pytest.raises(Exception) as e: validate_authorization(scope,challenge,method,resource)
        assert e.value.status_code==400
    assert not _verify_pkce_s256('非 ASCII', 'a'*43)

def test_redirect_matching_only_relaxes_native_loopback_ports():
    allowed=['http://127.0.0.1/callback','https://chatgpt.com/callback']
    assert redirect_matches('http://127.0.0.1:49255/callback',allowed)
    assert not redirect_matches('http://127.0.0.1:49255/evil',allowed)
    assert not redirect_matches('https://chatgpt.com:444/callback',allowed)
    assert not redirect_matches('https://evil.example/callback',allowed)
