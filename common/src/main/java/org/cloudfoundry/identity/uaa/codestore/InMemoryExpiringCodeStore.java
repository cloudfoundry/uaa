package org.cloudfoundry.identity.uaa.codestore;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.Timestamp;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class InMemoryExpiringCodeStore implements ExpiringCodeStore {

    private RandomValueStringGenerator generator = new RandomValueStringGenerator(6);

    private ConcurrentMap<String, ExpiringCode> store = new ConcurrentHashMap<String, ExpiringCode>();

    @Override
    public ExpiringCode generateCode(String data, Timestamp expiresAt) {
        if (data == null || expiresAt == null) {
            throw new NullPointerException();
        }

        if (expiresAt.getTime() < System.currentTimeMillis()) {
            throw new IllegalArgumentException();
        }

        String code = generator.generate();

        ExpiringCode expiringCode = new ExpiringCode(code, expiresAt, data);

        ExpiringCode duplicate = store.putIfAbsent(code, expiringCode);
        if (duplicate != null) {
            throw new DataIntegrityViolationException("Duplicate code: " + code);
        }

        return expiringCode;
    }

    @Override
    public ExpiringCode retrieveCode(String code) {
        if (code == null) {
            throw new NullPointerException();
        }

        ExpiringCode expiringCode = store.remove(code);
       
        if (expiringCode==null || expiringCode.getExpiresAt().getTime()<System.currentTimeMillis()) {
            expiringCode = null;
        }
        
        return expiringCode;
    }

    @Override
    public void setGenerator(RandomValueStringGenerator generator) {
        this.generator = generator;
    }
}
