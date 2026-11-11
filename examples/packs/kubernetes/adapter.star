# Administrator-owned adapter. The mounted file is reread on acquisition.
def acquire(request):
    return static(secret("token"))
