package org.cloudfoundry.identity.uaa.resources;

import com.jayway.jsonpath.InvalidPathException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SearchResultsFactoryTests {

    private static final List<String> SCHEMAS = List.of("urn:scim:schemas:core:1.0");

    private final List<Map<String, Object>> input = List.of(Map.of(
            "id", "user-id",
            "user_name", "marissa",
            "app-url", "https://app.example.com",
            "name", Map.of("familyName", "Bloggs"),
            "emails", List.of(Map.of("value", "marissa@test.org"))));

    @Test
    void buildSearchResultFrom_returnsRequestedAttributes() {
        SearchResults<Map<String, Object>> results = SearchResultsFactory.buildSearchResultFrom(
                input, 1, 1, 1, new String[]{"id", "user_name", "app-url", "name.familyName", "missing"}, SCHEMAS);

        assertThat(results.getResources()).singleElement().satisfies(resource -> assertThat(resource)
                .containsEntry("id", "user-id")
                .containsEntry("user_name", "marissa")
                .containsEntry("app-url", "https://app.example.com")
                .containsEntry("name.familyName", "Bloggs")
                .containsEntry("missing", null));
    }

    @Test
    void buildSearchResultFrom_ignoresTrailingWhitespace() {
        SearchResults<Map<String, Object>> results = SearchResultsFactory.buildSearchResultFrom(
                input, 1, 1, 1, new String[]{"id ", "user_name  "}, SCHEMAS);

        assertThat(results.getResources()).singleElement().satisfies(resource -> assertThat(resource)
                .containsEntry("id ", "user-id")
                .containsEntry("user_name  ", "marissa"));
    }

    @Test
    void buildSearchResultFrom_appliesMapperAfterValidation() {
        AttributeNameMapper mapper = new SimpleAttributeNameMapper(Map.of("^emails\\.", "emails[*]."));

        SearchResults<Map<String, Object>> results = SearchResultsFactory.buildSearchResultFrom(
                input, 1, 1, 1, new String[]{"emails.value"}, mapper, SCHEMAS);

        assertThat(results.getResources()).singleElement().satisfies(resource -> assertThat(resource)
                .containsEntry("emails.value", List.of("marissa@test.org")));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            " ",
            "[",
            "$",
            "*",
            ".id",
            "id.",
            "name..familyName",
            "..id",
            "emails[0]",
            "emails[*].value",
            "['id']",
            "length()",
            "[?(@ =~ /.*/)]",
            "..[?(@.id =~ /user.*/)]",
            " id",
            "user name",
            "user:name",
            "<b>"
    })
    void buildSearchResultFrom_rejectsAttributeThatIsNotAPlainName(String attribute) {
        String[] attributes = {"id", attribute};

        assertThatThrownBy(() -> SearchResultsFactory.buildSearchResultFrom(input, 1, 1, 1, attributes, SCHEMAS))
                .isInstanceOf(InvalidPathException.class)
                .hasMessageStartingWith("Invalid attribute name:");
    }

    @Test
    void buildSearchResultFrom_rejectsDeeplyNestedFilter() {
        String[] attributes = {"[?(" + "(".repeat(20000) + "@.id == 1" + ")".repeat(20000) + ")]"};

        assertThatThrownBy(() -> SearchResultsFactory.buildSearchResultFrom(input, 1, 1, 1, attributes, SCHEMAS))
                .isInstanceOf(InvalidPathException.class)
                .hasMessageStartingWith("Invalid attribute name:");
    }
}
