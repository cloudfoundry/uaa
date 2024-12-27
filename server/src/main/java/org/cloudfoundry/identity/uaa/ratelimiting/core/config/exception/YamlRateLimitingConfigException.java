package org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception;

public class YamlRateLimitingConfigException extends RateLimitingConfigException {
    public static final String MESSAGE_PREFIX = "Yaml ";
    private final String yaml;

    public YamlRateLimitingConfigException(String yaml, String message) {
        super(MESSAGE_PREFIX + message);
        this.yaml = yaml;
    }

    public YamlRateLimitingConfigException(String yaml, String message, Throwable cause) {
        super(MESSAGE_PREFIX + message, cause);
        this.yaml = yaml;
    }

    public String getYaml() {
        return yaml;
    }
}
