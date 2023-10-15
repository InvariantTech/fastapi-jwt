from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

from fastapi_jwt import JwtAccessCookie, JwtRefreshCookie
from tests.utils import compare_schema

app = FastAPI()

access_security = JwtAccessCookie(secret_key="secret_key")
refresh_security = JwtRefreshCookie(secret_key="secret_key")


@app.post("/auth")
def auth(response: Response):
    subject = {"username": "username", "role": "user"}

    access_token = access_security.create_access_token(subject=subject)
    refresh_token = access_security.create_refresh_token(subject=subject)

    access_security.set_access_cookie(
        response,
        access_token,
        cookie_name="custom_access_cookie",
        cookie_domain="testserver",
        path="/docs",
        samesite="strict",
    )
    refresh_security.set_refresh_cookie(
        response,
        refresh_token,
        cookie_name="custom_refresh_cookie",
        cookie_domain="testserver",
        path="/docs",
        samesite="strict",
    )

    return {"access_token": access_token, "refresh_token": refresh_token}


@app.delete("/auth")
def logout(response: Response):
    access_security.unset_access_cookie(response, cookie_name="custom_access_cookie")
    refresh_security.unset_refresh_cookie(response, cookie_name="custom_refresh_cookie")

    return {"msg": "Successful logout"}


client = TestClient(app)

openapi_schema = {
    "openapi": "3.0.2",
    "info": {"title": "FastAPI", "version": "0.1.0"},
    "paths": {
        "/auth": {
            "post": {
                "responses": {
                    "200": {
                        "description": "Successful Response",
                        "content": {"application/json": {"schema": {}}},
                    }
                },
                "summary": "Auth",
                "operationId": "auth_auth_post",
            },
            "delete": {
                "responses": {
                    "200": {
                        "description": "Successful Response",
                        "content": {"application/json": {"schema": {}}},
                    }
                },
                "summary": "Logout",
                "operationId": "logout_auth_delete",
            },
        }
    },
}


def test_openapi_schema():
    response = client.get("/openapi.json")
    assert response.status_code == 200, response.text
    compare_schema(response.json(), openapi_schema)


def test_security_jwt_auth():
    response = client.post("/auth")
    assert response.status_code == 200, response.text

    assert "custom_access_cookie" in response.cookies
    assert "access_token_cookie" not in response.cookies
    assert response.cookies["custom_access_cookie"] == response.json()["access_token"]
    cookie = next(cookie for cookie in response.cookies.jar if cookie.name == "custom_access_cookie")
    assert cookie.path == "/docs"
    assert cookie.domain == ".testserver"
    assert "custom_refresh_cookie" in response.cookies
    assert "refresh_token_cookie" not in response.cookies
    assert response.cookies["custom_refresh_cookie"] == response.json()["refresh_token"]
    cookie = next(cookie for cookie in response.cookies.jar if cookie.name == "custom_refresh_cookie")
    assert cookie.path == "/docs"
    assert cookie.domain == ".testserver"
    print(response.headers["set-cookie"])
    cookie_headers = response.headers["set-cookie"].split(',')
    assert "HttpOnly" not in cookie_headers[0]
    assert "HttpOnly" in cookie_headers[1]
    assert "SameSite=strict" in cookie_headers[0]
    assert "SameSite=strict" in cookie_headers[1]


def test_security_jwt_logout():
    response = client.delete("/auth")
    assert response.status_code == 200, response.text

    assert "custom_access_cookie" in response.headers["set-cookie"]
    assert 'custom_access_cookie=""; Max-Age=-1;' in response.headers["set-cookie"]
    assert "custom_refresh_cookie" in response.headers["set-cookie"]
    assert (
        'custom_refresh_cookie=""; HttpOnly; Max-Age=-1'
        in response.headers["set-cookie"]
    )
