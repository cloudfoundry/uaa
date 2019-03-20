package org.cloudfoundry.identity.uaa.resources.jdbc;

import com.unboundid.scim.sdk.InvalidResourceException;
import org.cloudfoundry.identity.uaa.test.ModelTestUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.*;

public class SimpleSearchQueryConverterTests {

    private SimpleSearchQueryConverter converter;

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setup() {
        converter = new SimpleSearchQueryConverter();
    }

    @Test
    public void testQuery() throws Exception {
        exception.expect(InvalidResourceException.class);
        exception.expectMessage(startsWith("Invalid filter attributes"));
        exception.expectMessage(containsString("an/**/invalid/**/attribute/**/and/**/1"));
        exception.expectMessage(containsString("1"));
        exception.expectMessage(containsString("\"1\""));
        String query = ModelTestUtils.getResourceAsString(this.getClass(), "testQuery.scimFilter");

        converter.scimFilter(query);
    }

    @Test
    public void simpleValueExtract() {
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
    public void invalidFilterAttribute() {
        String query = "origin eq \"origin-value\" and externalGroup eq \"group-value\"";
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Invalid filter attributes:externalGroup");
        converter.getFilterValues(query, Arrays.asList("origin", "externalGroup"));
    }

    @Test
    public void invalidConditionalOr() {
        String query = "origin eq \"origin-value\" or externalGroup eq \"group-value\"";
        try {
            converter.getFilterValues(query, Arrays.asList("origin", "externalGroup".toLowerCase()));
            fail("[or] is not supported");
        } catch (IllegalArgumentException e) {
            assertEquals("[or] operator is not supported.", e.getMessage());
        }
    }

    @Test
    public void invalidConditionalPr() {
        String query = "origin eq \"origin-value\" and externalGroup pr";
        try {
            converter.getFilterValues(query, Arrays.asList("origin", "externalGroup".toLowerCase()));
            fail("[pr] is not supported");
        } catch (IllegalArgumentException e) {
            assertEquals("[pr] operator is not supported.", e.getMessage());
        }
    }

    @Test
    public void invalidOperator() {
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