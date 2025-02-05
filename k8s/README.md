## Database connection strings

Don't specify username and password in the url. Use `ytt` values `database.username` and `database.password`.

#### HSQLDB
The UAA uses the driver provided by hsqldb (`org.hsqldb:hsqldb`). To use an in-memory database, it's possible to have a database url as simple as `database.url=jdbc:hsqldb:mem:uaa`.

HSQLDB connection strings are documented at http://www.hsqldb.org/doc/2.0/apidocs/index.html
#### Postgres
The UAA uses the driver provided by postgres (`org.postgresql:postgresql`). The connection string format is documented at https://jdbc.postgresql.org/documentation/head/connect.html

The typical structure will look like `database.url=jdbc:postgres://<HOST>:<PORT>/<DB-NAME>?sslmode=disable|allow|prefer|require|verify-ca|verify-full`, with whatever other params you may need to use.

#### Mysql / MariaDB
The UAA uses the driver provided by mariadb (`org.mariadb.jdbc:mariadb-java-client`) for both MySQL and MariaDB servers. The connection string format is documented at https://mariadb.com/kb/en/about-mariadb-connector-j/#connection-strings.

The typical structure will look like `database.url=jdbc:mysql://<HOST>:<PORT>/<DB-NAME>?useSSL=false|true`, with whatever other params you may need to use.

## Testing image `cloudfoundry/uaa` 

To switch between the minikube docker daemon and the local docker daemon, use these commands:

For minikube's docker daemon: `eval "$(minikube docker-env)"`

For the local docker daemon: `eval "$(minikube docker-env --unset=true)"`

To test image `cloudfoundry/uaa`, you can make use of these sample docker commands:

### Docker Run

```shell script
docker pull cloudfoundry/uaa:latest \
	&& docker run \
		--detach \
		--publish 8080:8080 \
		--mount type=bind,source=${PWD}/../scripts/cargo/uaa.yml,target=/uaa.yml \
		--env CLOUDFOUNDRY_CONFIG_PATH= \
		--env spring_profiles=hsqldb \
		cloudfoundry/uaa:latest
```

### Docker Debug

```shell script
docker pull cloudfoundry/uaa:latest \
   	&& docker run \
		--detach \
		--publish 8080:8080 \
		--publish 5005:5005 \
		--mount type=bind,source=${PWD}/../scripts/cargo/uaa.yml,target=/uaa.yml \
		--env CLOUDFOUNDRY_CONFIG_PATH= \
		--env spring_profiles=hsqldb \
		--env JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -Djava.security.egd=file:/dev/./urandom" \
		cloudfoundry/uaa:latest
```
