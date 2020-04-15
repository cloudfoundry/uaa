load("@ytt:assert", "assert")

def signing_keys(jwt_policy):
  if not jwt_policy or not jwt_policy.activeKeyId:
    assert.fail("jwt.policy.activeKeyId is required")
  end

  keys = {}
  for k in jwt_policy.keys:
    keys[k.keyId] = {
      "signingKey": k.signingKey
    }
  end

  return {
    "activeKeyId": jwt_policy.activeKeyId,
    "keys": keys,
  }
end
