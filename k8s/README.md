## Testing image `cfidentity/uaa` 

To test image `cfidentity/uaa`, you can make use of these sample docker commands:

### Docker Run

```shell script
docker pull cfidentity/uaa:latest \
	&& docker run \
		--detach \
		--publish 8080:8080 \
		--mount type=bind,source=${PWD}/../scripts/cargo/uaa.yml,target=/uaa.yml \
		--env CLOUDFOUNDRY_CONFIG_PATH= \
		--env spring_profiles=default,hsqldb \
		cfidentity/uaa:latest
```

### Docker Debug

```shell script
docker pull cfidentity/uaa:latest \
   	&& docker run \
		--detach \
		--publish 8080:8080 \
		--publish 5005:5005 \
		--mount type=bind,source=${PWD}/../scripts/cargo/uaa.yml,target=/uaa.yml \
		--env CLOUDFOUNDRY_CONFIG_PATH= \
		--env spring_profiles=default,hsqldb \
		--env JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -Djava.security.egd=file:/dev/./urandom" \
		cfidentity/uaa:latest
```
