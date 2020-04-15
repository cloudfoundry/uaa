def signing_keys(jwt_policy):
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
