def spring_profiles(database_scheme):
  if database_scheme == "postgresql":
    return "postgresql"
  else:
    return "default,hsqldb"
  end
end
