load("@ytt:assert", "assert")

def signing_keys(jwt_policy):
  if not jwt_policy or not jwt_policy.activeKeyId:
    assert.fail("jwt.policy.activeKeyId is required")
  end

  if type(jwt_policy.keys) != "struct":
    assert.fail("jwt.policy.keys must be an object")
  end

  if not hasattr(jwt_policy.keys, jwt_policy.activeKeyId):
    assert.fail("jwt.policy.keys must contain keyId matching jwt.policy.activeKeyId")
  end

  return jwt_policy
end
