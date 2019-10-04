package org.cloudfoundry.identity.uaa.web.beans;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.lang.NonNull;
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;
import org.springframework.session.jdbc.config.annotation.web.http.JdbcHttpSessionConfiguration;

@Configuration
@Conditional(UaaJdbcSessionConfig.DatabaseConfigured.class)
@EnableJdbcHttpSession
public class UaaJdbcSessionConfig extends UaaSessionConfig {

    private final static Logger logger = LoggerFactory.getLogger(UaaJdbcSessionConfig.class);

    public static class DatabaseConfigured implements Condition {
        @Override
        public boolean matches(@NonNull ConditionContext context, @NonNull AnnotatedTypeMetadata metadata) {
            String sessionStore = getSessionStore(context.getEnvironment());
            validateSessionStore(sessionStore);
            return DATABASE_SESSION_STORE_TYPE.equals(sessionStore);
        }
    }

    @Autowired
    public void customizeIdleTimeout(
            final JdbcHttpSessionConfiguration jdbcHttpSessionConfiguration,
            final @Value("${servlet.idle-timeout:1800}") int idleTimeout) {
        jdbcHttpSessionConfiguration.setMaxInactiveIntervalInSeconds(idleTimeout);
    }

    @Autowired
    void log() {
        logger.info("Using JDBC session configuration");
    }
}
