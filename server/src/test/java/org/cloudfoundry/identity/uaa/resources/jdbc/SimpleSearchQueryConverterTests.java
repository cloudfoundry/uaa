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
import org.cloudfoundry.identity.uaa.scim.jdbc.ScimSearchQueryConverter;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.concurrent.atomic.AtomicInteger;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;

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
        converter = new ScimSearchQueryConverter();
    }

    @Test
    public void test_query() throws Exception {
        exception.expect(InvalidResourceException.class);
        exception.expectMessage(startsWith("Invalid filter attributes"));
        exception.expectMessage(containsString("an/**/invalid/**/attribute/**/and/**/1"));
        exception.expectMessage(containsString("1"));
        exception.expectMessage(containsString("\"1\""));
        SCIMFilter filter = converter.scimFilter(query);
    }

    @Test
    public void print_query() throws Exception {
        SCIMFilter filter = converter.scimFilter(validQuery);
        printFilterAttributes(filter, new AtomicInteger(0));
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