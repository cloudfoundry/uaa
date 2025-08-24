package org.cloudfoundry.identity.uaa.login;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "notifications")
public record NotificationsProperties(
        String url,
        @DefaultValue("true") boolean sendInDefaultZone,
        @DefaultValue("false") boolean verify_ssl
) {
}
