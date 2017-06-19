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

import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.Assert;

import java.sql.Timestamp;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class InMemoryExpiringCodeStore implements ExpiringCodeStore {

    private RandomValueStringGenerator generator = new RandomValueStringGenerator(6);

    private ConcurrentMap<String, ExpiringCode> store = new ConcurrentHashMap<String, ExpiringCode>();

    private TimeService timeService = new TimeServiceImpl();

    @Override
    public ExpiringCode generateCode(String data, Timestamp expiresAt, String intent) {
        if (data == null || expiresAt == null) {
            throw new NullPointerException();
        }

        if (expiresAt.getTime() < timeService.getCurrentTimeMillis()) {
            throw new IllegalArgumentException();
        }

        String code = generator.generate();

        ExpiringCode expiringCode = new ExpiringCode(code, expiresAt, data, intent);

        ExpiringCode duplicate = store.putIfAbsent(code + IdentityZoneHolder.get().getId(), expiringCode);

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

        ExpiringCode expiringCode = store.remove(code + IdentityZoneHolder.get().getId());

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
    public void expireByIntent(String intent) {
        Assert.hasText(intent);

        store.values().stream().filter(c -> intent.equals(c.getIntent())).forEach(c -> store.remove(c.getCode() + IdentityZoneHolder.get().getId()));
    }

    public InMemoryExpiringCodeStore setTimeService(TimeService timeService) {
        this.timeService = timeService;
        return this;
    }
}
