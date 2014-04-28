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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.rest.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.rest.jdbc.SearchQueryConverter.ProcessedFilter;
import org.cloudfoundry.identity.uaa.scim.dao.common.ScimSearchQueryConverter;
import org.junit.Test;

public class ScimSearchQueryConverterTests {

    private ScimSearchQueryConverter filterProcessor = new ScimSearchQueryConverter();

    @Test
    public void canConvertValidFilters() throws Exception {
        validate(filterProcessor.convert("username pr", null, false), "username is not null", 0);
        validate(filterProcessor.convert("username eq 'joe'", null, false), "lower(username) = :value0", 1);
        validate(filterProcessor.convert("username eq 'bar", null, false), "username = 'bar", 0);
        validate(filterProcessor.convert("displayName eq \"openid\"", null, false), "lower(displayName) = :value0", 1);
        validate(filterProcessor.convert("USERNAME eq 'joe'", null, false), "lower(USERNAME) = :value0", 1);
        validate(filterProcessor.convert("username EQ 'joe'", null, false), "lower(username) = :value0", 1);
        validate(filterProcessor.convert("username eq 'Joe'", null, false), "lower(username) = :value0", 1);
        validate(filterProcessor.convert("displayName co 'write'", null, false), "lower(displayName) like :value0", 1);
        validate(filterProcessor.convert("displayName sw 'scim.'", null, false), "lower(displayName) like :value0", 1);
        validate(filterProcessor.convert("username gt 'joe'", null, false), "username > 'joe'", 0);
        validate(filterProcessor.convert("userName eq 'joe' and meta.version eq 0", null, false),
                        "lower(userName) = :value0 and version = 0", 1);
        validate(filterProcessor.convert("meta.created gt '1970-01-01T00:00:00.000Z'", null, false),
                        "created > :value0", 1);
        validate(filterProcessor.convert("username pr and active eq true", null, false),
                        "username is not null and active = :value0", 1);
        validate(filterProcessor.convert("username pr", "username", true),
                        "username is not null order by username asc", 0);
        validate(filterProcessor.convert("displayName pr", "displayName", false),
                        "displayName is not null order by displayName desc", 0);
        validate(filterProcessor.convert("username pr and emails.value co '.com'", null, false),
                        "username is not null and emails.lower(value) like :value0", 1);
        validate(filterProcessor.convert("username eq 'joe' or emails.value co '.com'", null, false),
                        "lower(username) = :value1 or emails.lower(value) like :value0", 2);
    }

    @Test
    public void canConvertWithReplacePatterns() {
        Map<String, String> replaceWith = new HashMap<String, String>();
        replaceWith.put("emails\\.value", "email");
        replaceWith.put("groups\\.display", "authorities");
        replaceWith.put("phoneNumbers\\.value", "phoneNumber");
        filterProcessor.setAttributeNameMapper(new SimpleAttributeNameMapper(replaceWith));

        validate(filterProcessor.convert("emails.value sw 'joe'", null, false), "lower(email) like :value0", 1);
        validate(filterProcessor.convert("groups.display co 'org.foo'", null, false),
                        "lower(authorities) like :value0", 1);
        validate(filterProcessor.convert("phoneNumbers.value sw '+1-222'", null, false),
                        "lower(phoneNumber) like :value0", 1);
        validate(filterProcessor.convert("username pr", "emails.value", true),
                        "username is not null order by email asc", 0);
        validate(filterProcessor.convert("emails.type eq 'bar'", "emails.type", false),
                        "emails.lower(type) = :value0 order by emails.type desc", 1);

    }

    private void validate(ProcessedFilter filter, String expectedSql, int expectedParamCount) {
        assertNotNull(filter);
        assertEquals(expectedSql, filter.getSql());
        assertEquals(expectedParamCount, filter.getParams().size());
    }

}
