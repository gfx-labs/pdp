def acquire(request):
    return oauth_client_credentials("token", parameter("client_id"), secret("client_secret"))
