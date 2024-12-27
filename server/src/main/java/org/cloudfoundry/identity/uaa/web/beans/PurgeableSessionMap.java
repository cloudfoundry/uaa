package org.cloudfoundry.identity.uaa.web.beans;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.session.Session;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

@Component
class PurgeableSessionMap extends ConcurrentHashMap<String, Session> {
    private static final Logger logger = LoggerFactory.getLogger(PurgeableSessionMap.class);

    @Scheduled(fixedDelayString = "${servlet-session-purge-delay:900000}")
    public void purge() {
        List<Session> expired = expired();
        expired.forEach(s -> remove(s.getId()));
        logger.debug("Purged %s sessions".formatted(expired.size()));
    }

    public List<Session> expired() {
        return values().stream().filter(Session::isExpired).toList();
    }
}
