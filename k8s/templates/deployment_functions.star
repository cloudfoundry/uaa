def spring_profiles(database_scheme):
  if database_scheme in ["postgresql","mysql"]:
    return database_scheme
  else:
    return "default,hsqldb"
  end
end
