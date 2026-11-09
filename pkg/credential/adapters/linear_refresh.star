# For an existing authorization-code installation with admin-attested app/user actor.
def acquire(request):
    return linear_refresh("token", parameter("client_id"), secret("client_secret"))
