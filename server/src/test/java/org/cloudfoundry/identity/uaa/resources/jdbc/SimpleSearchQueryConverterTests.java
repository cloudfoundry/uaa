/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.resources.jdbc;

import com.unboundid.scim.sdk.InvalidResourceException;
import com.unboundid.scim.sdk.SCIMFilter;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

public class SimpleSearchQueryConverterTests {

    SimpleSearchQueryConverter converter;

    String query = "user_id eq \"7e2345e8-8bbf-4eaa-9bc3-ae1ba610f890\"" +
        "and " +
        "client_id eq \"app\"" +
        "and " +
        "meta.lastmodified gt \"some-value\"" +
        "and " +
        "(an/**/invalid/**/attribute/**/and/**/1" + //invalid attribute name
        " pr " + //operator (present)
        "and "
        + "1 eq 1)" + //invalid attribute name 1
        " and " +
        "\"1\" eq \"1\"";

    String validQuery = "user_id eq \"7e2345e8-8bbf-4eaa-9bc3-ae1ba610f890\"" +
        "and " +
        "client_id eq \"app\"" +
        "and " +
        "meta.lastmodified gt \"some-value\"" +
        "and " +
        "meta.created pr";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setup() {
        converter = new SimpleSearchQueryConverter();
    }

    @Test
    public void test_query() throws Exception {
        exception.expect(InvalidResourceException.class);
        exception.expectMessage(startsWith("Invalid filter attributes"));
        exception.expectMessage(containsString("an/**/invalid/**/attribute/**/and/**/1"));
        exception.expectMessage(containsString("1"));
        exception.expectMessage(containsString("\"1\""));
        converter.scimFilter(query);
    }

    @Test
    public void print_query() throws Exception {
        SCIMFilter filter = converter.scimFilter(validQuery);
        printFilterAttributes(filter, new AtomicInteger(0));
    }

    @Test
    public void simple_value_extract() throws Exception {
        for (String query : Arrays.asList(
            "origin eq \"origin-value\" and externalGroup eq \"group-value\"",
            "externalGroup eq \"group-value\" and origin eq \"origin-value\""
        )) {
            MultiValueMap<String, Object> result = converter.getFilterValues(query, Arrays.asList("origin", "externalGroup".toLowerCase()));
            assertNotNull(result);
            assertEquals(2, result.size());

            assertNotNull(result.get("origin"));
            assertEquals(1, result.get("origin").size());
            assertEquals("origin-value", result.get("origin").get(0));

            assertNotNull(result.get("externalGroup"));
            assertEquals(1, result.get("externalGroup").size());
            assertEquals("group-value", result.get("externalGroup").get(0));
        }
    }

    @Test
    public void invalid_filter_attribute() throws Exception {
        String query = "origin eq \"origin-value\" and externalGroup eq \"group-value\"";
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Invalid filter attributes:externalGroup");
        converter.getFilterValues(query, Arrays.asList("origin","externalGroup"));
    }

    @Test
    public void invalid_conditional_or() throws Exception {
        String query = "origin eq \"origin-value\" or externalGroup eq \"group-value\"";
        try {
            converter.getFilterValues(query, Arrays.asList("origin", "externalGroup".toLowerCase()));
            fail("[or] is not supported");
        } catch (IllegalArgumentException e) {
            assertEquals("[or] operator is not supported.", e.getMessage());
        }
    }

    @Test
    public void invalid_conditional_pr() throws Exception {
        String query = "origin eq \"origin-value\" and externalGroup pr";
        try {
            converter.getFilterValues(query, Arrays.asList("origin", "externalGroup".toLowerCase()));
            fail("[pr] is not supported");
        } catch (IllegalArgumentException e) {
            assertEquals("[pr] operator is not supported.", e.getMessage());
        }
    }

    @Test
    public void invalid_operator() throws Exception {
        for (String operator : Arrays.asList("co","sw","ge","gt","lt","le")) {
            String query = "origin eq \"origin-value\" and externalGroup "+operator+" \"group-value\"";
            try {
                converter.getFilterValues(query, Arrays.asList("origin", "externalGroup".toLowerCase()));
                fail(operator);
            } catch (IllegalArgumentException e) {
                assertEquals("["+operator+"] operator is not supported.", e.getMessage());
            }
        }
    }

    public void printFilterAttributes(SCIMFilter filter, AtomicInteger pos) {
        if (filter.getFilterAttribute() != null) {
            String name = filter.getFilterAttribute().getAttributeName();
            if (filter.getFilterAttribute().getSubAttributeName() != null) {
                name = name + "." + filter.getFilterAttribute().getSubAttributeName();
            }
            System.out.println((pos.incrementAndGet()) + ". Attribute name:" + name);
        }
        for (SCIMFilter subfilter : ofNullable(filter.getFilterComponents()).orElse(emptyList())) {
            printFilterAttributes(subfilter, pos);
        }
    }

}