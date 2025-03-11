package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.lang.Nullable;

/**
 * Future replacement of {@link org.cloudfoundry.identity.uaa.impl.config.UaaConfiguration}
 * for binding properties and validating them.
 */
public class UaaProperties {

    @ConfigurationProperties
    public record RootLevel(
            @DefaultValue("false") boolean require_https,
            @DefaultValue("loginsecret") String LOGIN_SECRET
    ) {

    }

    @ConfigurationProperties(prefix = "uaa")
    public record Uaa(String url) {
        public Uaa {
            if (url == null) {
                url = UaaStringUtils.DEFAULT_UAA_URL;
            }
        }
    }

    @ConfigurationProperties(prefix = "servlet")
    public record Servlet(SessionCookie sessionCookie, @DefaultValue("1800") int idleTimeout) {
        public Servlet {
            if (sessionCookie == null) {
                sessionCookie = new SessionCookie(true, null);
            }
        }
    }

    public record SessionCookie(@DefaultValue("true") boolean encodeBase64, @Nullable Integer maxAge) {
    }

}

