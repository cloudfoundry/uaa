package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.cloudfoundry.identity.uaa.resources.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.resources.jdbc.SearchQueryConverter.ProcessedFilter;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

class ScimSearchQueryConverterTests {

    private SimpleSearchQueryConverter filterProcessor;
    private final String zoneId = "fake-zone-id";
    private boolean expectCaseInsensitiveDbBehavior;

    @BeforeEach
    void setUp() {
        expectCaseInsensitiveDbBehavior = false;
        Map<String, String> replaceWith = new HashMap<>();
        replaceWith.put("emails\\.value", "email");
        replaceWith.put("groups\\.display", "authorities");
        replaceWith.put("phoneNumbers\\.value", "phoneNumber");
        filterProcessor = new SimpleSearchQueryConverter();
        filterProcessor.setAttributeNameMapper(new SimpleAttributeNameMapper(replaceWith));
    }

    @Test
    void canConvertValidFilters() {
        validate(filterProcessor.convert("username pr", null, false, zoneId), "username IS NOT NULL", null, 0);
        validate(filterProcessor.convert("username eq \"joe\"", null, false, zoneId), "LOWER(username) = LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("username eq \"'bar\"", null, false, zoneId), "LOWER(username) = LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("displayName eq \"openid\"", null, false, zoneId), "LOWER(displayName) = LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("USERNAME eq \"joe\"", null, false, zoneId), "LOWER(USERNAME) = LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("username EQ \"joe\"", null, false, zoneId), "LOWER(username) = LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("username eq \"Joe\"", null, false, zoneId), "LOWER(username) = LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("username eq \"Joe\"", null, false, zoneId), "LOWER(username) = LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("displayName co \"write\"", null, false, zoneId), "LOWER(displayName) LIKE LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("displayName sw \"scim.\"", null, false, zoneId), "LOWER(displayName) LIKE LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("username gt \"joe\"", null, false, zoneId), "LOWER(username) > LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("userName eq \"joe\" and meta.version eq 0", null, false, zoneId), "(LOWER(userName) = LOWER(:__value_0) AND version = :__value_1)", null, 2);
        validate(filterProcessor.convert("meta.created gt \"1970-01-01T00:00:00.000Z\"", null, false, zoneId), "created > :__value_0", null, 1);
        validate(filterProcessor.convert("username pr and active eq true", null, false, zoneId), "(username IS NOT NULL AND active = :__value_0)", null, 1);
        validate(filterProcessor.convert("username pr", "username", true, zoneId), "username IS NOT NULL", "ORDER BY username ASC", 0);
        validate(filterProcessor.convert("displayName pr", "displayName", false, zoneId), "displayName IS NOT NULL", "ORDER BY displayName DESC", 0);
        validate(filterProcessor.convert("username pr and emails.value co \".com\"", null, false, zoneId), "(username IS NOT NULL AND LOWER(email) LIKE LOWER(:__value_0))", null, 1);
        validate(filterProcessor.convert("username eq \"joe\" or emails.value co \".com\"", null, false, zoneId), "(LOWER(username) = LOWER(:__value_0) OR LOWER(email) LIKE LOWER(:__value_1))", null, 2);
        validate(filterProcessor.convert("active eq true", null, false, zoneId), "active = :__value_0", null, 1, Boolean.class);
        validate(filterProcessor.convert("Version eq 1000000.45", null, false, zoneId), "Version = :__value_0", null, 1, Double.class);
        validate(filterProcessor.convert("meta.VerSion eq 1000000", null, false, zoneId), "VerSion = :__value_0", null, 1, Double.class);
    }

    @Test
    void caseInsensitiveDbDoesNotInjectLower() {
        expectCaseInsensitiveDbBehavior = true;
        filterProcessor.setDbCaseInsensitive(expectCaseInsensitiveDbBehavior);
        validate(filterProcessor.convert("username pr", null, false, zoneId), "username IS NOT NULL", null, 0);
        validate(filterProcessor.convert("username eq \"joe\"", null, false, zoneId), "username = :__value_0", null, 1);
        validate(filterProcessor.convert("username eq \"'bar\"", null, false, zoneId), "username = :__value_0", null, 1);
        validate(filterProcessor.convert("displayName eq \"openid\"", null, false, zoneId), "displayName = :__value_0", null, 1);
        validate(filterProcessor.convert("USERNAME eq \"joe\"", null, false, zoneId), "USERNAME = :__value_0", null, 1);
        validate(filterProcessor.convert("username EQ \"joe\"", null, false, zoneId), "username = :__value_0", null, 1);
        validate(filterProcessor.convert("username eq \"Joe\"", null, false, zoneId), "username = :__value_0", null, 1);
        validate(filterProcessor.convert("username eq \"Joe\"", null, false, zoneId), "username = :__value_0", null, 1);
        validate(filterProcessor.convert("displayName co \"write\"", null, false, zoneId), "displayName LIKE :__value_0", null, 1);
        validate(filterProcessor.convert("displayName sw \"scim.\"", null, false, zoneId), "displayName LIKE :__value_0", null, 1);
        validate(filterProcessor.convert("username gt \"joe\"", null, false, zoneId), "username > :__value_0", null, 1);
        validate(filterProcessor.convert("userName eq \"joe\" and meta.version eq 0", null, false, zoneId), "(userName = :__value_0 AND version = :__value_1)", null, 2);
        validate(filterProcessor.convert("meta.created gt \"1970-01-01T00:00:00.000Z\"", null, false, zoneId), "created > :__value_0", null, 1);
        validate(filterProcessor.convert("username pr and active eq true", null, false, zoneId), "(username IS NOT NULL AND active = :__value_0)", null, 1);
        validate(filterProcessor.convert("username pr", "username", true, zoneId), "username IS NOT NULL", "ORDER BY username ASC", 0);
        validate(filterProcessor.convert("displayName pr", "displayName", false, zoneId), "displayName IS NOT NULL", "ORDER BY displayName DESC", 0);
        validate(filterProcessor.convert("username pr and emails.value co \".com\"", null, false, zoneId), "(username IS NOT NULL AND email LIKE :__value_0)", null, 1);
        validate(filterProcessor.convert("username eq \"joe\" or emails.value co \".com\"", null, false, zoneId), "(username = :__value_0 OR email LIKE :__value_1)", null, 2);
        validate(filterProcessor.convert("active eq true", null, false, zoneId), "active = :__value_0", null, 1, Boolean.class);
        validate(filterProcessor.convert("Version eq 1000000.45", null, false, zoneId), "Version = :__value_0", null, 1, Double.class);
        validate(filterProcessor.convert("meta.VerSion eq 1000000", null, false, zoneId), "VerSion = :__value_0", null, 1, Double.class);
    }

    @Test
    void canConvertWithReplacePatterns() {
        validate(filterProcessor.convert("emails.value sw \"joe\"", null, false, zoneId), "LOWER(email) LIKE LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("groups.display co \"org.foo\"", null, false, zoneId), "LOWER(authorities) LIKE LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("phoneNumbers.value sw \"+1-222\"", null, false, zoneId), "LOWER(phoneNumber) LIKE LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("username pr", "emails.value", true, zoneId), "username IS NOT NULL", "ORDER BY email ASC", 0);
    }

    @Test
    void filterWithApostrophe() {
        validate(filterProcessor.convert("username eq \"marissa'@test.org\"", null, false, zoneId),
                "LOWER(username) = LOWER(:__value_0)", null, 1);
    }

    @Test
    void canConvertLegacyValidFilters() {
        validate(filterProcessor.convert("username pr", null, false, zoneId), "username IS NOT NULL", null, 0);
        validate(filterProcessor.convert("username eq 'joe'", null, false, zoneId), "LOWER(username) = LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("displayName eq \"openid\"", null, false, zoneId), "LOWER(displayName) = LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("USERNAME eq 'joe'", null, false, zoneId), "LOWER(USERNAME) = LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("username EQ 'joe'", null, false, zoneId), "LOWER(username) = LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("username eq 'Joe'", null, false, zoneId), "LOWER(username) = LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("displayName co 'write'", null, false, zoneId), "LOWER(displayName) LIKE LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("displayName sw 'scim.'", null, false, zoneId), "LOWER(displayName) LIKE LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("username gt 'joe'", null, false, zoneId), "LOWER(username) > LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("userName eq 'joe' and meta.version eq 0", null, false, zoneId), "(LOWER(userName) = LOWER(:__value_0) AND version = :__value_1)", null, 2);
        validate(filterProcessor.convert("meta.created gt '1970-01-01T00:00:00.000Z'", null, false, zoneId), "created > :__value_0", null, 1);
        validate(filterProcessor.convert("username pr and active eq true", null, false, zoneId), "(username IS NOT NULL AND active = :__value_0)", null, 1);
        validate(filterProcessor.convert("username pr", "username", true, zoneId), "username IS NOT NULL", "ORDER BY username ASC", 0);
        validate(filterProcessor.convert("displayName pr", "displayName", false, zoneId), "displayName IS NOT NULL", "ORDER BY displayName DESC", 0);
        validate(filterProcessor.convert("username pr and emails.value co '.com'", null, false, zoneId), "(username IS NOT NULL AND LOWER(email) LIKE LOWER(:__value_0))", null, 1);
        validate(filterProcessor.convert("username eq 'joe' or emails.value co '.com'", null, false, zoneId), "(LOWER(username) = LOWER(:__value_0) OR LOWER(email) LIKE LOWER(:__value_1))", null, 2);
    }

    @Test
    void illegalUnquotedValueInFilter() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> filterProcessor.convert("username eq joe", null, false, zoneId));
    }

    @Test
    void canConvertLegacyWithReplacePatterns() {
        Map<String, String> replaceWith = new HashMap<>();
        replaceWith.put("emails\\.value", "email");
        replaceWith.put("groups\\.display", "authorities");
        replaceWith.put("phoneNumbers\\.value", "phoneNumber");
        filterProcessor.setAttributeNameMapper(new SimpleAttributeNameMapper(replaceWith));

        validate(filterProcessor.convert("emails.value sw 'joe'", null, false, zoneId), "LOWER(email) LIKE LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("groups.display co 'org.foo'", null, false, zoneId), "LOWER(authorities) LIKE LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("phoneNumbers.value sw '+1-222'", null, false, zoneId), "LOWER(phoneNumber) LIKE LOWER(:__value_0)", null, 1);
        validate(filterProcessor.convert("username pr", "emails.value", true, zoneId), "username IS NOT NULL", "ORDER BY email ASC", 0);
    }

    private void validate(ProcessedFilter filter, String expectedWhereClauseBeforeIdentityZoneCheck, String expectedOrderByClause, int expectedParamCount, Class... types) {
        assertThat(filter).isNotNull();
        assertThat(filter.getParamPrefix()).as("Filter's param prefix cannot contain '-': " + filter.getParamPrefix()).doesNotContain("-");

        // There is always an implied "and also the identity zone must match the zone in which the
        // user performed the query" clause, which also causes an extra param on the filter, so
        // account for that in all of the expectations here
        String expectedIdentityZoneWhereClause = expectCaseInsensitiveDbBehavior ?
                " AND identity_zone_id = :__value_" + expectedParamCount
                :
                " AND LOWER(identity_zone_id) = LOWER(:__value_" + expectedParamCount + ")";
        String expectedSql = "(" + expectedWhereClauseBeforeIdentityZoneCheck + expectedIdentityZoneWhereClause + ")";
        if (StringUtils.hasText(expectedOrderByClause)) {
            expectedSql += " " + expectedOrderByClause;
        }
        expectedSql = expectedSql.replaceAll("__value_", filter.getParamPrefix());

        assertThat(filter.getSql()).isEqualTo(expectedSql);
        assertThat(filter.getParams()).hasSize(expectedParamCount + 1);

        int count = 0;
        for (Class type : types) {
            String param = filter.getParamPrefix() + count++;
            Object value = filter.getParams().get(param);
            assertThat(value.getClass()).isEqualTo(type);
        }
    }
}
