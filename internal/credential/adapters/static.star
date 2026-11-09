# Administrator-owned adapter. Secret bytes never enter Starlark.
def acquire(request):
    return static(secret("token"))
