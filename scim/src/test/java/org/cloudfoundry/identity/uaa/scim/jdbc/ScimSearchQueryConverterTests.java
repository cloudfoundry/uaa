/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.cloudfoundry.identity.uaa.rest.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.rest.jdbc.SearchQueryConverter.ProcessedFilter;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class ScimSearchQueryConverterTests {

    private ScimSearchQueryConverter filterProcessor;

    @Before
    public void setUp() {
        Map<String, String> replaceWith = new HashMap<>();
        replaceWith.put("emails\\.value", "email");
        replaceWith.put("groups\\.display", "authorities");
        replaceWith.put("phoneNumbers\\.value", "phoneNumber");
        filterProcessor = new ScimSearchQueryConverter();
        filterProcessor.setAttributeNameMapper(new SimpleAttributeNameMapper(replaceWith));
    }

    @Test
    public void canConvertValidFilters() throws Exception {
        validate(filterProcessor.convert("username pr", null, false), "username IS NOT NULL", 0);
        validate(filterProcessor.convert("username eq \"joe\"", null, false), "LOWER(username) = LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("username eq \"'bar\"", null, false), "LOWER(username) = LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("displayName eq \"openid\"", null, false), "LOWER(displayName) = LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("USERNAME eq \"joe\"", null, false), "LOWER(USERNAME) = LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("username EQ \"joe\"", null, false), "LOWER(username) = LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("username eq \"Joe\"", null, false), "LOWER(username) = LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("username eq \"Joe\"", null, false), "LOWER(username) = LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("displayName co \"write\"", null, false), "LOWER(displayName) LIKE LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("displayName sw \"scim.\"", null, false), "LOWER(displayName) LIKE LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("username gt \"joe\"", null, false), "LOWER(username) > LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("userName eq \"joe\" and meta.version eq 0", null, false),"(LOWER(userName) = LOWER(:__value_0) AND version = :__value_1)", 2);
        validate(filterProcessor.convert("meta.created gt \"1970-01-01T00:00:00.000Z\"", null, false),"created > :__value_0", 1);
        validate(filterProcessor.convert("username pr and active eq true", null, false),"(username IS NOT NULL AND active = :__value_0)", 1);
        validate(filterProcessor.convert("username pr", "username", true),"username IS NOT NULL ORDER BY username ASC", 0);
        validate(filterProcessor.convert("displayName pr", "displayName", false),"displayName IS NOT NULL ORDER BY displayName DESC", 0);
        validate(filterProcessor.convert("username pr and emails.value co \".com\"", null, false),"(username IS NOT NULL AND LOWER(email) LIKE LOWER(:__value_0))", 1);
        validate(filterProcessor.convert("username eq \"joe\" or emails.value co \".com\"", null, false),"(LOWER(username) = LOWER(:__value_0) OR LOWER(email) LIKE LOWER(:__value_1))", 2);
        validate(filterProcessor.convert("active eq true", null, false),"active = :__value_0", 1, Boolean.class);
        validate(filterProcessor.convert("test eq 1000000.45", null, false),"test = :__value_0", 1, Double.class);
        validate(filterProcessor.convert("test eq 1000000", null, false),"test = :__value_0", 1, Double.class);
    }

    @Test
    public void caseInsensitiveDbDoesNotInjectLower() throws Exception {
        filterProcessor.setDbCaseInsensitive(true);
        validate(filterProcessor.convert("username pr", null, false), "username IS NOT NULL", 0);
        validate(filterProcessor.convert("username eq \"joe\"", null, false), "username = :__value_0", 1);
        validate(filterProcessor.convert("username eq \"'bar\"", null, false), "username = :__value_0", 1);
        validate(filterProcessor.convert("displayName eq \"openid\"", null, false), "displayName = :__value_0", 1);
        validate(filterProcessor.convert("USERNAME eq \"joe\"", null, false), "USERNAME = :__value_0", 1);
        validate(filterProcessor.convert("username EQ \"joe\"", null, false), "username = :__value_0", 1);
        validate(filterProcessor.convert("username eq \"Joe\"", null, false), "username = :__value_0", 1);
        validate(filterProcessor.convert("username eq \"Joe\"", null, false), "username = :__value_0", 1);
        validate(filterProcessor.convert("displayName co \"write\"", null, false), "displayName LIKE :__value_0", 1);
        validate(filterProcessor.convert("displayName sw \"scim.\"", null, false), "displayName LIKE :__value_0", 1);
        validate(filterProcessor.convert("username gt \"joe\"", null, false), "username > :__value_0", 1);
        validate(filterProcessor.convert("userName eq \"joe\" and meta.version eq 0", null, false),"(userName = :__value_0 AND version = :__value_1)", 2);
        validate(filterProcessor.convert("meta.created gt \"1970-01-01T00:00:00.000Z\"", null, false),"created > :__value_0", 1);
        validate(filterProcessor.convert("username pr and active eq true", null, false),"(username IS NOT NULL AND active = :__value_0)", 1);
        validate(filterProcessor.convert("username pr", "username", true),"username IS NOT NULL ORDER BY username ASC", 0);
        validate(filterProcessor.convert("displayName pr", "displayName", false),"displayName IS NOT NULL ORDER BY displayName DESC", 0);
        validate(filterProcessor.convert("username pr and emails.value co \".com\"", null, false),"(username IS NOT NULL AND email LIKE :__value_0)", 1);
        validate(filterProcessor.convert("username eq \"joe\" or emails.value co \".com\"", null, false),"(username = :__value_0 OR email LIKE :__value_1)", 2);
        validate(filterProcessor.convert("active eq true", null, false),"active = :__value_0", 1, Boolean.class);
        validate(filterProcessor.convert("test eq 1000000.45", null, false),"test = :__value_0", 1, Double.class);
        validate(filterProcessor.convert("test eq 1000000", null, false),"test = :__value_0", 1, Double.class);
    }

    @Test
    public void canConvertWithReplacePatterns() {
        validate(filterProcessor.convert("emails.value sw \"joe\"", null, false), "LOWER(email) LIKE LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("groups.display co \"org.foo\"", null, false),"LOWER(authorities) LIKE LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("phoneNumbers.value sw \"+1-222\"", null, false),"LOWER(phoneNumber) LIKE LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("username pr", "emails.value", true),"username IS NOT NULL ORDER BY email ASC", 0);
    }

    @Test
    public void testFilterWithApostrophe() throws Exception {
        validate(filterProcessor.convert("username eq \"marissa'@test.org\"", null, false),
                "LOWER(username) = LOWER(:__value_0)", 1);
    }

    @Test
    public void canConvertLegacyValidFilters() throws Exception {
        validate(filterProcessor.convert("username pr", null, false), "username IS NOT NULL", 0);
        validate(filterProcessor.convert("username eq 'joe'", null, false), "LOWER(username) = LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("displayName eq \"openid\"", null, false), "LOWER(displayName) = LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("USERNAME eq 'joe'", null, false), "LOWER(USERNAME) = LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("username EQ 'joe'", null, false), "LOWER(username) = LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("username eq 'Joe'", null, false), "LOWER(username) = LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("displayName co 'write'", null, false), "LOWER(displayName) LIKE LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("displayName sw 'scim.'", null, false), "LOWER(displayName) LIKE LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("username gt 'joe'", null, false), "LOWER(username) > LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("userName eq 'joe' and meta.version eq 0", null, false), "(LOWER(userName) = LOWER(:__value_0) AND version = :__value_1)", 2);
        validate(filterProcessor.convert("meta.created gt '1970-01-01T00:00:00.000Z'", null, false), "created > :__value_0", 1);
        validate(filterProcessor.convert("username pr and active eq true", null, false), "(username IS NOT NULL AND active = :__value_0)", 1);
        validate(filterProcessor.convert("username pr", "username", true), "username IS NOT NULL ORDER BY username ASC", 0);
        validate(filterProcessor.convert("displayName pr", "displayName", false), "displayName IS NOT NULL ORDER BY displayName DESC", 0);
        validate(filterProcessor.convert("username pr and emails.value co '.com'", null, false), "(username IS NOT NULL AND LOWER(email) LIKE LOWER(:__value_0))", 1);
        validate(filterProcessor.convert("username eq 'joe' or emails.value co '.com'", null, false), "(LOWER(username) = LOWER(:__value_0) OR LOWER(email) LIKE LOWER(:__value_1))", 2);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIllegalUnquotedValueInFilter() throws Exception {
        filterProcessor.convert("username eq joe", null, false);
    }

    @Test
    public void canConvertLegacyWithReplacePatterns() {
        Map<String, String> replaceWith = new HashMap<>();
        replaceWith.put("emails\\.value", "email");
        replaceWith.put("groups\\.display", "authorities");
        replaceWith.put("phoneNumbers\\.value", "phoneNumber");
        filterProcessor.setAttributeNameMapper(new SimpleAttributeNameMapper(replaceWith));

        validate(filterProcessor.convert("emails.value sw 'joe'", null, false), "LOWER(email) LIKE LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("groups.display co 'org.foo'", null, false), "LOWER(authorities) LIKE LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("phoneNumbers.value sw '+1-222'", null, false), "LOWER(phoneNumber) LIKE LOWER(:__value_0)", 1);
        validate(filterProcessor.convert("username pr", "emails.value", true), "username IS NOT NULL ORDER BY email ASC", 0);
    }

    private void validate(ProcessedFilter filter, String expectedSql, int expectedParamCount, Class... types) {
        assertNotNull(filter);
        expectedSql = expectedSql.replaceAll("__value_", filter.getParamPrefix());
        assertEquals(expectedSql, filter.getSql());
        assertEquals(expectedParamCount, filter.getParams().size());

        int count = 0;
        for (Class type : types) {
            String param = filter.getParamPrefix()+String.valueOf(count++);
            Object value = filter.getParams().get(param);
            assertEquals(type, value.getClass());
        }
    }
}
