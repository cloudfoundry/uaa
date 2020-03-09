def spring_profiles(database_scheme):
  if database_scheme in ["postgresql","mysql"]:
    return database_scheme
  else:
    return "default,hsqldb"
  end
end

java_opts_list = [
  "-Djava.security.egd=file:/dev/./urandom",
  "-Dlogging.config=/etc/config/log4j2.properties",
  "-Dlog4j.configurationFile=/etc/config/log4j2.properties",
]

def java_opts():
  ret = java_opts_list[0]
  for i in range(1, len(java_opts_list)):
    ret += " "
    ret += java_opts_list[i]
  end
  return ret
end