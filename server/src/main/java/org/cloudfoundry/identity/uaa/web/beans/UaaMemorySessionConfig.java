package org.cloudfoundry.identity.uaa.web.beans;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.lang.NonNull;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Configuration
@Conditional(UaaMemorySessionConfig.MemoryConfigured.class)
@EnableSpringHttpSession
@EnableScheduling
public class UaaMemorySessionConfig extends UaaSessionConfig {

    private final static Logger logger = LoggerFactory.getLogger(UaaMemorySessionConfig.class);

    public static class MemoryConfigured implements Condition {
        @Override
        public boolean matches(@NonNull ConditionContext context, @NonNull AnnotatedTypeMetadata metadata) {
            String sessionStore = getSessionStore(context.getEnvironment());
            validateSessionStore(sessionStore);
            return MEMORY_SESSION_STORE_TYPE.equals(sessionStore);
        }
    }

    @Bean
    public static Map<String, Session> sessionMap() {
        return new ConcurrentHashMap<>();
    }

    @Bean
    public MapSessionRepository sessionRepository(
            final @Value("${servlet.idle-timeout:1800}") int idleTimeout,
            final Map<String, Session> sessionMap) {
        MapSessionRepository sessionRepository = new MapSessionRepository(sessionMap);
        sessionRepository.setDefaultMaxInactiveInterval(idleTimeout);
        return sessionRepository;
    }

    @Autowired
    private Map<String, Session> sessionMap;

    private static final String SERVLET_SESSION_MEMORY_CLEANUP_CRON_VALUE = "${servlet.session.memory.cleanup.cron:0 * * * * *}";

    @Value(SERVLET_SESSION_MEMORY_CLEANUP_CRON_VALUE)
    private String memoryCleanupCron;

    @Scheduled(cron = SERVLET_SESSION_MEMORY_CLEANUP_CRON_VALUE)
    public void expireSessions() {
        logger.info("Purging Expired Memory Sessions using cron [{}]", memoryCleanupCron);
        try {
            final int numExpiredSessions = expireSessionsThrowing(sessionMap);
            logger.info("Purged {} Expired Memory Sessions", numExpiredSessions);
        } catch (Throwable t) {
            logger.error("Error Purging Expired Memory Sessions", t);
        }
    }

    private static int expireSessionsThrowing(
            final Map<String, Session> sessionMap
    ) {
        return sessionMap
                .entrySet()
                .parallelStream()
                .filter(entry -> entry.getValue().isExpired())
                .map(Map.Entry::getKey)
                .map(sessionId -> {
                    try {
                        sessionMap.remove(sessionId);
                        logger.info("Purging Expired Session ID {}", sessionId);
                        return 1;
                    } catch (Throwable t) {
                        logger.error(String.format("Error purging Expired Session ID %s", sessionId), t);
                        return 0;
                    }
                })
                .mapToInt(Integer::valueOf)
                .sum();
    }

    @Autowired
    void log() {
        logger.info("Using memory session configuration");
    }
}