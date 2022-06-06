package org.cloudfoundry.identity.uaa.ratelimiting.core;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;

import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtils;

public interface RateLimiter {
    static String configUrl() {
        return StringUtils.normalizeToNull( System.getenv( "RateLimiterConfigUrl" ) );
    }

    static boolean isEnabled() {
        Boolean enabled = value[0];
        if ( enabled == null ) {
            enabled = false;
            String url = configUrl();
            if ( url != null ) {
                for ( UrlPrefix up : UrlPrefix.values() ) {
                    if ( url.startsWith( up.asPrefix() ) ) {
                        enabled = true;
                        break;
                    }
                }
            }
            value[0] = enabled;
        }
        return enabled;
    }

    @NotNull Limiter checkRequest( HttpServletRequest request );

    enum UrlPrefix {
        https, http, file;

        public String asPrefix() {
            return name() + "://";
        }
    }

    Boolean[] value = new Boolean[1];
}
