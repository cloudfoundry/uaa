package org.cloudfoundry.identity.uaa.impl.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "smtp")
public record SmtpProperties(
        @DefaultValue("localhost") String host,
        @DefaultValue("25") int port,
        @DefaultValue("") String user,
        @DefaultValue("") String password,
        @DefaultValue("false") boolean auth,
        @DefaultValue("false") boolean starttls,
        @DefaultValue("TLSv1.2") String sslprotocols,
        @DefaultValue("") String fromAddress
) {
}
