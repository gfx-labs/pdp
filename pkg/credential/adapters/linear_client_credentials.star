# Requires Linear's client credentials toggle. The grant always uses the app actor.
def acquire(request):
    return linear_client_credentials("token", parameter("client_id"), secret("client_secret"))
