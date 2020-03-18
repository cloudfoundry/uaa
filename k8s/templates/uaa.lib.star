load("@ytt:assert", "assert")

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

def database_connection_string(database):
    if not database or not database.scheme:
        assert.fail("database.scheme is required")
    end
    if database.scheme == "hsqldb":
        return "jdbc:hsqldb:mem:uaa"
    end
    return "jdbc:{}://{}:{}/{}{}".format(
        database.scheme,
        database.address,
        database.port,
        database.name,
        database_query_params(database.scheme))
end

def database_query_params(scheme):
    if scheme == "postgresql":
        return "?sslmode=disable"
    elif scheme == "mysql":
        return "?useSSL=false"
    end
    return ""
end