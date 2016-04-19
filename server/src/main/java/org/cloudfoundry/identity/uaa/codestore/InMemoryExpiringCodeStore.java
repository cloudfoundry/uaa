/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.codestore;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.Assert;

import java.sql.Timestamp;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class InMemoryExpiringCodeStore implements ExpiringCodeStore {

    private RandomValueStringGenerator generator = new RandomValueStringGenerator(6);

    private ConcurrentMap<String, ExpiringCode> store = new ConcurrentHashMap<String, ExpiringCode>();

    @Override
    public ExpiringCode generateCode(String data, Timestamp expiresAt, String intent) {
        if (data == null || expiresAt == null) {
            throw new NullPointerException();
        }

        if (expiresAt.getTime() < System.currentTimeMillis()) {
            throw new IllegalArgumentException();
        }

        String code = generator.generate();

        ExpiringCode expiringCode = new ExpiringCode(code, expiresAt, data, intent);

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

        if (expiringCode == null || expiringCode.getExpiresAt().getTime() < System.currentTimeMillis()) {
            expiringCode = null;
        }

        return expiringCode;
    }

    @Override
    public void setGenerator(RandomValueStringGenerator generator) {
        this.generator = generator;
    }

    @Override
    public void expireByIntent(String intent) {
        Assert.hasText(intent);

        store.values().stream().filter(c -> intent.equals(c.getIntent())).forEach(c -> store.remove(c.getCode()));
    }
}
