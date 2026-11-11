# Exact installation endpoint, repositories and permissions come from admin config.
def acquire(request):
    return github_installation("token", secret("private_key"))
