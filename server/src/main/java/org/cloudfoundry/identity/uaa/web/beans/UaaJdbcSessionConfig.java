package org.cloudfoundry.identity.uaa.web.beans;

import org.cloudfoundry.identity.uaa.UaaProperties;
import org.cloudfoundry.identity.uaa.db.DatabasePlatform;
import org.cloudfoundry.identity.uaa.db.beans.DatabaseProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.lang.NonNull;
import org.springframework.session.config.SessionRepositoryCustomizer;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.session.jdbc.MySqlJdbcIndexedSessionRepositoryCustomizer;
import org.springframework.session.jdbc.PostgreSqlJdbcIndexedSessionRepositoryCustomizer;
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;
import org.springframework.session.jdbc.config.annotation.web.http.JdbcHttpSessionConfiguration;

@Configuration
@Conditional(UaaJdbcSessionConfig.DatabaseConfigured.class)
@EnableJdbcHttpSession
public class UaaJdbcSessionConfig extends UaaSessionConfig {

    private static final Logger logger = LoggerFactory.getLogger(UaaJdbcSessionConfig.class);

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
            UaaProperties.Servlet servlet) {
        jdbcHttpSessionConfiguration.setMaxInactiveIntervalInSeconds(servlet.idleTimeout());
    }

    /**
     * Makes the {@code SPRING_SESSION_ATTRIBUTES} insert idempotent (upsert) per DB vendor.
     * <p>
     * Without this, two concurrent requests sharing a JSESSIONID both see an attribute as
     * new (each {@code JdbcSession} loaded the row before either committed), both mark their
     * delta as {@code ADDED}, and the second {@code INSERT} fails with {@code DuplicateKeyException}.
     * Spring Session ships ready-made customizers for Postgres and MySQL; HSQLDB needs a MERGE.
     */
    @Bean
    public static SessionRepositoryCustomizer<JdbcIndexedSessionRepository> sessionAttributeUpsertCustomizer(
            DatabaseProperties databaseProperties) {
        DatabasePlatform platform = databaseProperties.getDatabasePlatform();
        return switch (platform) {
            case POSTGRESQL -> new PostgreSqlJdbcIndexedSessionRepositoryCustomizer();
            case MYSQL -> new MySqlJdbcIndexedSessionRepositoryCustomizer();
            case HSQLDB -> new HsqldbJdbcIndexedSessionRepositoryCustomizer();
        };
    }

    @Autowired
    void log() {
        logger.info("Using JDBC session configuration");
    }
}
