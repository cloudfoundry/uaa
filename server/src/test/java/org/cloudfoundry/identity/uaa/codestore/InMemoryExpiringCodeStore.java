package org.cloudfoundry.identity.uaa.codestore;

import org.cloudfoundry.identity.uaa.util.TimeService;
import org.springframework.dao.DataIntegrityViolationException;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.springframework.util.Assert;

import java.sql.Timestamp;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class InMemoryExpiringCodeStore implements ExpiringCodeStore {

    private RandomValueStringGenerator generator = new RandomValueStringGenerator(6);

    private final ConcurrentMap<String, ExpiringCode> store = new ConcurrentHashMap<>();

    private final TimeService timeService;

    public InMemoryExpiringCodeStore(final TimeService timeService) {
        this.timeService = timeService;
    }

    @Override
    public ExpiringCode generateCode(String data, Timestamp expiresAt, String intent, String zoneId) {
        if (data == null || expiresAt == null) {
            throw new NullPointerException();
        }

        if (expiresAt.getTime() < timeService.getCurrentTimeMillis()) {
            throw new IllegalArgumentException();
        }

        String code = generator.generate();

        ExpiringCode expiringCode = new ExpiringCode(code, expiresAt, data, intent);

        ExpiringCode duplicate = store.putIfAbsent(code + zoneId, expiringCode);
        if (duplicate != null) {
            throw new DataIntegrityViolationException("Duplicate code: " + code);
        }

        return expiringCode;
    }

    @Override
    public ExpiringCode peekCode(String code, String zoneId) {
        if (code == null) {
            throw new NullPointerException();
        }

        ExpiringCode expiringCode = store.get(code + zoneId);

        if (expiringCode == null || isExpired(expiringCode)) {
            expiringCode = null;
        }

        return expiringCode;
    }

    @Override
    public ExpiringCode retrieveCode(String code, String zoneId) {
        if (code == null) {
            throw new NullPointerException();
        }

        ExpiringCode expiringCode = store.remove(code + zoneId);

        if (expiringCode == null || isExpired(expiringCode)) {
            expiringCode = null;
        }

        return expiringCode;
    }

    private boolean isExpired(ExpiringCode expiringCode) {
        return expiringCode.getExpiresAt().getTime() < timeService.getCurrentTimeMillis();
    }

    @Override
    public void setGenerator(RandomValueStringGenerator generator) {
        this.generator = generator;
    }

    @Override
    public void expireByIntent(String intent, String zoneId) {
        Assert.hasText(intent, "must have text");

        store.values().stream().filter(c -> intent.equals(c.getIntent())).forEach(c -> store.remove(c.getCode() + zoneId));
    }

}
