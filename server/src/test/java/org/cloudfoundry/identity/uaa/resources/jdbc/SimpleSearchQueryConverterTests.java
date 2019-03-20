package org.cloudfoundry.identity.uaa.resources.jdbc;

import com.unboundid.scim.sdk.InvalidResourceException;
import org.cloudfoundry.identity.uaa.test.ModelTestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SimpleSearchQueryConverterTests {

    private SimpleSearchQueryConverter converter;

    @BeforeEach
    void setup() {
        converter = new SimpleSearchQueryConverter();
    }

    @Test
    void testQuery() {
        String query = ModelTestUtils.getResourceAsString(this.getClass(), "testQuery.scimFilter");

        String message =
                assertThrows(InvalidResourceException.class, () -> converter.scimFilter(query))
                        .getMessage();

        assertThat(message, startsWith("Invalid filter attributes"));
        assertThat(message, containsString("an/**/invalid/**/attribute/**/and/**/1"));
        assertThat(message, containsString("1"));
        assertThat(message, containsString("\"1\""));
    }

    @Test
    void simpleValueExtract() {
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
    void invalidFilterAttribute() {
        String query = "origin eq \"origin-value\" and externalGroup eq \"group-value\"";

        String message = assertThrows(IllegalArgumentException.class,
                () -> converter.getFilterValues(query, Arrays.asList("origin", "externalGroup"))).getMessage();

        assertThat(message, is("Invalid filter attributes:externalGroup"));
    }

    @Test
    void invalidConditionalOr() {
        String query = "origin eq \"origin-value\" or externalGroup eq \"group-value\"";
        try {
            converter.getFilterValues(query, Arrays.asList("origin", "externalGroup".toLowerCase()));
            fail("[or] is not supported");
        } catch (IllegalArgumentException e) {
            assertEquals("[or] operator is not supported.", e.getMessage());
        }
    }

    @Test
    void invalidConditionalPr() {
        String query = "origin eq \"origin-value\" and externalGroup pr";
        try {
            converter.getFilterValues(query, Arrays.asList("origin", "externalGroup".toLowerCase()));
            fail("[pr] is not supported");
        } catch (IllegalArgumentException e) {
            assertEquals("[pr] operator is not supported.", e.getMessage());
        }
    }

    @Test
    void invalidOperator() {
        for (String operator : Arrays.asList("co", "sw", "ge", "gt", "lt", "le")) {
            String query = "origin eq \"origin-value\" and externalGroup " + operator + " \"group-value\"";
            try {
                converter.getFilterValues(query, Arrays.asList("origin", "externalGroup".toLowerCase()));
                fail(operator);
            } catch (IllegalArgumentException e) {
                assertEquals("[" + operator + "] operator is not supported.", e.getMessage());
            }
        }
    }
}