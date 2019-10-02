package org.cloudfoundry.identity.uaa.web.beans;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;
import org.springframework.session.jdbc.config.annotation.web.http.JdbcHttpSessionConfiguration;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

import java.util.concurrent.ConcurrentHashMap;

public class UaaSessionConfig {
    private static final String DATABASE_SESSION_STORE_TYPE = "database";

    @Configuration
    @Conditional(DatabaseConfigured.class)
    @EnableJdbcHttpSession
    public static class UaaJdbcSessionConfig extends UaaSessionConfig {
        @Autowired
        public void customizeIdleTimeout(
                final JdbcHttpSessionConfiguration jdbcHttpSessionConfiguration,
                final @Value("${servlet.idle-timeout:1800}") int idleTimeout) {
            jdbcHttpSessionConfiguration.setMaxInactiveIntervalInSeconds(idleTimeout);
        }
    }

    @Configuration
    @Conditional(MemoryConfigured.class)
    @EnableSpringHttpSession
    public static class UaaMemorySessionConfig extends UaaSessionConfig {
        @Bean
        public MapSessionRepository sessionRepository(final @Value("${servlet.idle-timeout:1800}") int idleTimeout) {
            MapSessionRepository sessionRepository = new MapSessionRepository(new ConcurrentHashMap<>());
            sessionRepository.setDefaultMaxInactiveInterval(idleTimeout);
            return sessionRepository;
        }
    }

    public static class MemoryConfigured implements Condition {
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            String sessionStore = context.getEnvironment().getProperty("servlet.session-store");
            return !DATABASE_SESSION_STORE_TYPE.equals(sessionStore);
        }
    }

    public static class DatabaseConfigured implements Condition {
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            String sessionStore = context.getEnvironment().getProperty("servlet.session-store");
            return DATABASE_SESSION_STORE_TYPE.equals(sessionStore);
        }
    }

    @Bean
    public CookieSerializer uaaCookieSerializer(
            final @Value("${servlet.session-cookie.max-age:-1}") int cookieMaxAge
    ) {
        DefaultCookieSerializer cookieSerializer = new DefaultCookieSerializer();
        cookieSerializer.setSameSite(null);
        cookieSerializer.setCookieMaxAge(cookieMaxAge);
        cookieSerializer.setCookieName("JSESSIONID");

        return cookieSerializer;
    }
}
