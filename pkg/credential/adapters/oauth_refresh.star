# The native helper locks and durably replaces the configured private state file.
def acquire(request):
    return oauth_refresh("token", parameter("client_id"), secret("client_secret"))
