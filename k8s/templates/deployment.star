config_dir = "/etc/config"

java_opts_list = [
  "-Djava.security.egd=file:/dev/./urandom",
  "-Dlogging.config={}/log4j2.properties".format(config_dir),
  "-Dlog4j.configurationFile={}/log4j2.properties".format(config_dir),
]

def java_opts():
  ret = java_opts_list[0]
  for i in range(1, len(java_opts_list)):
    ret += " "
    ret += java_opts_list[i]
  end
  return ret
end