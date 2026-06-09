package org.cloudfoundry.identity.uaa.resources.jdbc;

import org.cloudfoundry.identity.uaa.resources.JoinAttributeNameMapper;
import org.cloudfoundry.identity.uaa.test.ModelTestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SimpleSearchQueryConverterTests {

    private SimpleSearchQueryConverter converter;

    @BeforeEach
    void setup() {
        converter = new SimpleSearchQueryConverter();
    }

    @Test
    void query() {
        // The SCIM 2.0 parser rejects the injection payload at parse time (stricter syntax check
        // for '/' in attribute names), so the error comes from the parser rather than the attribute
        // whitelist. The important property is that the filter is rejected as an IllegalArgumentException.
        String query = ModelTestUtils.getResourceAsString(this.getClass(), "testQuery.scimFilter");

        assertThatThrownBy(() -> converter.convert(query, null, false, "foo"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid SCIM Filter");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "origin eq \"origin-value\" and externalGroup eq \"group-value\"",
            "externalGroup eq \"group-value\" and origin eq \"origin-value\""
    })
    void simpleValueExtract(final String query) {
        MultiValueMap<String, Object> result = converter.getFilterValues(query, Arrays.asList("origin", "externalGroup".toLowerCase()));
        assertThat(result)
                .hasSize(2)
                .containsKey("origin");
        assertThat(result.get("origin"))
                .hasSize(1)
                .contains("origin-value");

        assertThat(result).containsKey("externalGroup");
        assertThat(result.get("externalGroup"))
                .hasSize(1)
                .contains("group-value");
    }

    @Test
    void invalidFilterAttribute() {
        String query = "origin eq \"origin-value\" and externalGroup eq \"group-value\"";

        List<String> validAttributes = Arrays.asList("origin", "externalGroup");
        assertThatThrownBy(() -> converter.getFilterValues(query, validAttributes))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid filter attributes:externalGroup");
    }

    @Test
    void invalidConditionalOr() {
        String query = "origin eq \"origin-value\" or externalGroup eq \"group-value\"";
        List<String> validAttributes = Arrays.asList("origin", "externalGroup".toLowerCase());
        assertThatThrownBy(() -> converter.getFilterValues(query, validAttributes))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("[or] operator is not supported.");
    }

    @Test
    void invalidConditionalPr() {
        String query = "origin eq \"origin-value\" and externalGroup pr";
        List<String> validAttributes = Arrays.asList("origin", "externalGroup".toLowerCase());
        assertThatThrownBy(() -> converter.getFilterValues(query, validAttributes))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("[pr] operator is not supported.");
    }

    @ParameterizedTest
    @ValueSource(strings = {"co", "sw", "ge", "gt", "lt", "le"})
    void invalidOperator(final String operator) {
        String query = "origin eq \"origin-value\" and externalGroup " + operator + " \"group-value\"";
        List<String> validAttributes = Arrays.asList("origin", "externalGroup".toLowerCase());
        assertThatThrownBy(() -> converter.getFilterValues(query, validAttributes))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("[" + operator + "] operator is not supported.");
    }

    @Test
    void joinName() {
        assertThat(converter.getJoinName()).isEmpty();
        converter.setAttributeNameMapper(new JoinAttributeNameMapper("myTable"));
        assertThat(converter.getJoinName()).isEqualTo("myTable");
    }

    @Test
    void deeplyNestedFilterIsRejected() {
        // SCIM 2 parser creates flat n-ary AND for chains; explicit parentheses create actual tree depth.
        // Build: ((...((a and a) and a)...) and a) with 22 nestings → depth 22 > MAX_FILTER_DEPTH(20)
        StringBuilder filter = new StringBuilder("username eq \"joe\" and username eq \"joe\"");
        for (int i = 0; i < 22; i++) {
            filter = new StringBuilder("(" + filter + ") and username eq \"joe\"");
        }
        final String deepFilter = filter.toString();
        assertThatThrownBy(() -> converter.convert(deepFilter, null, false, "zone"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void moderatelyNestedFilterIsAccepted() {
        // 5 explicit nestings → depth 5, well within MAX_FILTER_DEPTH(20)
        StringBuilder filter = new StringBuilder("username eq \"joe\" and username eq \"joe\"");
        for (int i = 0; i < 5; i++) {
            filter = new StringBuilder("(" + filter + ") and username eq \"joe\"");
        }
        final String shallowFilter = filter.toString();
        assertThatNoException().isThrownBy(() -> converter.convert(shallowFilter, null, false, "zone"));
    }

    @Test
    void deeplyNestedGetFilterValuesIsRejected() {
        // Same depth limit applies to getFilterValues
        StringBuilder filter = new StringBuilder("origin eq \"uaa\" and origin eq \"uaa\"");
        for (int i = 0; i < 22; i++) {
            filter = new StringBuilder("(" + filter + ") and origin eq \"uaa\"");
        }
        final String deepFilter = filter.toString();
        assertThatThrownBy(() -> converter.getFilterValues(deepFilter, List.of("origin")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void joinFilterAttributes() {
        String query = "origin eq \"origin-value\" and id eq \"group-value\"";
        List<String> validAttributes = Arrays.asList("origin", "id".toLowerCase());
        JoinAttributeNameMapper joinAttributeNameMapper = new JoinAttributeNameMapper("prefix");
        converter.setAttributeNameMapper(joinAttributeNameMapper);
        MultiValueMap<String, Object> filterValues = converter.getFilterValues(query, validAttributes);
        assertThat(filterValues).isNotNull();
        assertThat(filterValues.get("origin")).hasToString("[origin-value]");
        assertThat(filterValues.get("id")).hasToString("[group-value]");
        assertThat(converter.map("origin")).isEqualTo("prefix.origin");
        assertThat(converter.map("id")).isEqualTo("prefix.id");
        assertThat(converter.getJoinName()).isEqualTo("prefix");
        assertThat(joinAttributeNameMapper.mapFromInternal("prefix.origin")).isEqualTo("origin");
    }
}
