# Administrator-owned adapter. The real access and refresh tokens stay in the
# binding's state file. Secret bytes never enter Starlark.
def acquire(request):
    return oauth_refresh("token", parameter("client_id"), secret("client_secret"))
