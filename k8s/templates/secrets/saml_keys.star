load("@ytt:assert", "assert")

def saml_keys(login):
    if not login or not login.saml or not hasattr(login.saml, "activeKeyId") or not login.saml.activeKeyId:
        assert.fail("login.saml.activeKeyId is required")
    end

    if type(login.saml.keys) != "struct":
        assert.fail("login.saml.keys must be an object")
    end

    if not login.saml.keys or not getattr(login.saml.keys, login.saml.activeKeyId, None):
        assert.fail("login.saml.activeKeyId must reference key in login.saml.keys")
    end

    return login
end
