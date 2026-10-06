def handler(event, context):
    """Toy authorizer: only a request with the right token gets through."""
    token = (event.get("headers") or {}).get("authorization", "")
    return {"isAuthorized": token == "Bearer demo-token"}