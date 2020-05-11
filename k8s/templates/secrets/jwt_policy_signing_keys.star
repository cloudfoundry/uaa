load("@ytt:assert", "assert")

def signing_keys(jwt_policy):
  if not jwt_policy or not jwt_policy.activeKeyId:
    assert.fail("jwt.policy.activeKeyId is required")
  end

  found_active_key = False

  if type(jwt_policy.keys) != "list":
    assert.fail("jwt.policy.keys must be a list")
  end

  keys = {}
  for k in jwt_policy.keys:
    keys[k.keyId] = {
      "signingKey": k.signingKey
    }
    if k.keyId == jwt_policy.activeKeyId:
      found_active_key = True
    end
  end

  if not found_active_key:
    assert.fail("jwt.policy.keys must contain keyId matching jwt.policy.signingKey")
  end

  return {
    "activeKeyId": jwt_policy.activeKeyId,
    "keys": keys,
  }
end
