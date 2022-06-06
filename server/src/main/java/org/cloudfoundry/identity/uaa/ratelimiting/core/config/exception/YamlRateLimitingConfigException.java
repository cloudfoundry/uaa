package org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception;

public class YamlRateLimitingConfigException extends RateLimitingConfigException {
    private final String yaml;

    public YamlRateLimitingConfigException( String yaml, String message ) {
        super( "Yaml " + message );
        this.yaml = yaml;
    }

    public YamlRateLimitingConfigException( String yaml, String message, Throwable cause ) {
        super( "Yaml " + message, cause );
        this.yaml = yaml;
    }

    public String getYaml() {
        return yaml;
    }
}
