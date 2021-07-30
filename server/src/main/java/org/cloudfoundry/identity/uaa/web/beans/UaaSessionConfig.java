package org.cloudfoundry.identity.uaa.web.beans;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

public class UaaSessionConfig {
    private static final String SERVLET_SESSION_STORE = "servlet.session-store";
    static final String DATABASE_SESSION_STORE_TYPE = "database";
    static final String MEMORY_SESSION_STORE_TYPE = "memory";

    static String getSessionStore(final Environment environment) {
        return environment.getProperty(SERVLET_SESSION_STORE, MEMORY_SESSION_STORE_TYPE);
    }

    static void validateSessionStore(String sessionStore) {
        if (DATABASE_SESSION_STORE_TYPE.equals(sessionStore) || MEMORY_SESSION_STORE_TYPE.equals(sessionStore)) {
            return;
        }
        throw new IllegalArgumentException(String.format(
                "%s is not a valid argument for %s. Please choose %s or %s.",
                sessionStore,
                SERVLET_SESSION_STORE,
                MEMORY_SESSION_STORE_TYPE,
                DATABASE_SESSION_STORE_TYPE));
    }

    @Bean
    public CookieSerializer uaaCookieSerializer(
            final @Value("${servlet.session-cookie.max-age:-1}") int cookieMaxAge
    ) {
        DefaultCookieSerializer cookieSerializer = new DefaultCookieSerializer();
        cookieSerializer.setSameSite("None");
        cookieSerializer.setUseSecureCookie(true);
        cookieSerializer.setCookieMaxAge(cookieMaxAge);
        cookieSerializer.setCookieName("JSESSIONID");

        return cookieSerializer;
    }
}
