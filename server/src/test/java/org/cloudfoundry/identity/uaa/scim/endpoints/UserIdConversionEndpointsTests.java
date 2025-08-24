/*
 * *****************************************************************************
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

package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static java.util.Collections.singletonList;
import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
@ExtendWith(MockitoExtension.class)
class UserIdConversionEndpointsTests {
    private UserIdConversionEndpoints endpoints;

    @Mock
    private SecurityContextAccessor mockSecurityContextAccessor;
    @Mock
    private ScimUserEndpoints scimUserEndpoints;
    @Mock
    private ScimUserProvisioning scimUserProvisioning;
    @Mock
    private IdentityZoneManager identityZoneManager;

    @SuppressWarnings("rawtypes")
    private final Collection authorities = AuthorityUtils
            .commaSeparatedStringToAuthorityList("orgs.foo,uaa.user");

    @SuppressWarnings("unchecked")
    @BeforeEach
    void init() {
        endpoints = new UserIdConversionEndpoints(mockSecurityContextAccessor, scimUserEndpoints, scimUserProvisioning, identityZoneManager, true);
        lenient().when(mockSecurityContextAccessor.getAuthorities()).thenReturn(authorities);
        lenient().when(mockSecurityContextAccessor.getAuthenticationInfo()).thenReturn("mock object");
        lenient().when(scimUserEndpoints.getUserMaxCount()).thenReturn(10_000);
    }

    @Test
    void happyDay() {
        arrangeCurrentIdentityZone("uaa");
        assertThatNoException()
                .isThrownBy(() -> endpoints.findUsers("userName eq \"marissa\"", "ascending", 0, 100, false));
    }

    @Test
    void sanitizeExceptionInFilter() {
        assertThatExceptionOfType(ScimException.class)
                .isThrownBy(() -> endpoints.findUsers("<svg onload=alert(document.domain)>", "ascending", 0, 100, false))
                .withMessage("Invalid filter '&lt;svg onload=alert(document.domain)&gt;'");
    }

    @Test
    void goodFilterIncludeInactive() {
        final String idzId = randomUUID().toString();
        arrangeCurrentIdentityZone(idzId);

        final String filter = "(username eq \"foo\" and id eq \"bar\") or username eq \"bar\"";

        final List<ScimUser> allScimUsers = new ArrayList<>();
        for (int i = 0; i < 5; ++i) {
            final ScimUser scimUser = new ScimUser(randomUUID().toString(), "bar", "Some", "Name");
            scimUser.setOrigin("idp2");
            allScimUsers.add(scimUser);
        }
        final ScimUser scimUser6 = new ScimUser("bar", "foo", "Some", "Name");
        scimUser6.setOrigin("idp1");
        allScimUsers.add(scimUser6);
        assertThat(allScimUsers).hasSize(6);
        arrangeScimUsersForFilter(filter, allScimUsers, true, idzId);

        // check different page sizes -> should return all users, since 'includeInactive' is true
        assertEndpointReturnsCorrectResult(filter, 1, allScimUsers, true);
        assertEndpointReturnsCorrectResult(filter, 2, allScimUsers, true);
        assertEndpointReturnsCorrectResult(filter, 3, allScimUsers, true);
        assertEndpointReturnsCorrectResult(filter, 4, allScimUsers, true);
        assertEndpointReturnsCorrectResult(filter, 10, allScimUsers, true);
    }

    @Test
    void goodFilterOnlyActive() {
        final String idzId = randomUUID().toString();
        arrangeCurrentIdentityZone(idzId);

        final String filter = "(username eq \"foo\" and id eq \"bar\") or username eq \"bar\"";

        // one active user
        final ScimUser scimUser = new ScimUser("bar", "foo", "Some", "Name");
        scimUser.setOrigin("idp1");
        final List<ScimUser> expectedUsers = singletonList(scimUser);
        arrangeScimUsersForFilter(filter, expectedUsers, false, idzId);

        // check different page sizes
        assertEndpointReturnsCorrectResult(filter, 1, expectedUsers, false);
        assertEndpointReturnsCorrectResult(filter, 2, expectedUsers, false);
        assertEndpointReturnsCorrectResult(filter, 3, expectedUsers, false);
        assertEndpointReturnsCorrectResult(filter, 4, expectedUsers, false);
        assertEndpointReturnsCorrectResult(filter, 10, expectedUsers, false);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "(id eq \"foo\" or username eq \"bar\") and origin eq \"uaa\"",
            "origin eq \"uaa\" and (id eq \"foo\" or username eq \"bar\")",
            "(id eq \"foo\" and username eq \"bar\") or id eq \"bar\"",
            "id eq \"bar\" and (id eq \"foo\" and username eq \"bar\")"
    })
    void goodFilter(final String filter) {
        arrangeCurrentIdentityZone("uaa");
        final ResponseEntity<Object> response = endpoints.findUsers(
                filter,
                "ascending",
                0,
                100,
                false
        );
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "id co \"foo\"",
            "id sw \"foo\"",
            "id pr",
            "id eq \"foo\" or origin co \"uaa\""
    })
    void badFilterWildcardsNotAllowed(final String filter) {
        assertThatExceptionOfType(ScimException.class)
                .isThrownBy(() -> endpoints.findUsers(filter, "ascending", 0, 100, false))
                .withMessage("Wildcards are not allowed in filter.");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "id gt \"foo\"",
            "id le \"foo\"",
            "id lt \"foo\""
    })
    void badFilterUnsupportedOperator(final String filter) {
        assertThatExceptionOfType(ScimException.class)
                .isThrownBy(() -> endpoints.findUsers(filter, "ascending", 0, 100, false))
                .withMessage("Invalid operator.");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "id sq \"foo\""
    })
    void badFilterUnrecognizedOperator(final String filter) {
        assertThatExceptionOfType(ScimException.class)
                .isThrownBy(() -> endpoints.findUsers(filter, "ascending", 0, 100, false))
                .withMessageStartingWith("Invalid filter '");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "origin eq \"uaa\"",
            "emails.value eq \"foo@bar.org\"",
            "origin eq \"uaa\" or origin eq \"bar\"",
            "groups.display eq \"foo\""
    })
    void badFilterDoesNotContainClauseWithIdOrUserName(final String filter) {
        assertThatExceptionOfType(ScimException.class)
                .isThrownBy(() -> endpoints.findUsers(filter, "ascending", 0, 100, false))
                .withMessage("Invalid filter attribute.");
    }

    @Test
    void disabled() {
        endpoints = new UserIdConversionEndpoints(mockSecurityContextAccessor, scimUserEndpoints, scimUserProvisioning, identityZoneManager, false);
        ResponseEntity<Object> response = endpoints.findUsers("id eq \"foo\"", "ascending", 0, 100, false);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isEqualTo("Illegal Operation: Endpoint not enabled.");
    }

    @Test
    void noActiveIdps_ReturnsEmptyResources() {
        arrangeCurrentIdentityZone("uaa");
        SearchResults<?> searchResults = (SearchResults<?>) endpoints.findUsers("username eq \"foo\"", "ascending", 0, 100, false).getBody();
        assertThat(searchResults).isNotNull();
        assertThat(searchResults.getResources()).isEmpty();
    }

    private void arrangeCurrentIdentityZone(final String idzId) {
        when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn(idzId);
    }

    private void arrangeScimUsersForFilter(
            final String filter,
            final List<ScimUser> allScimUsers,
            final boolean includeInactive,
            final String zoneId
    ) {
        if (includeInactive) {
            when(scimUserProvisioning.query(filter, "userName", true, zoneId)).thenReturn(allScimUsers);
        } else {
            when(scimUserProvisioning.retrieveByScimFilterOnlyActive(filter, "userName", true, zoneId))
                    .thenReturn(allScimUsers);
        }
    }

    private void assertEndpointReturnsCorrectResult(
            final String filter,
            final int resultsPerPage,
            final List<ScimUser> expectedUsers,
            final boolean includeInactive
    ) {
        final boolean lastPageIncomplete = expectedUsers.size() % resultsPerPage != 0;
        final int expectedPages = expectedUsers.size() / resultsPerPage + (lastPageIncomplete ? 1 : 0);

        final Function<Integer, SearchResults<Map<String, Object>>> fetchNextPage = startIndex -> {
            final ResponseEntity<Object> response = endpoints.findUsers(
                    filter, "ascending", startIndex, resultsPerPage, includeInactive
            );
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull().isInstanceOf(SearchResults.class);
            return (SearchResults<Map<String, Object>>) response.getBody();
        };

        // collect all users in several pages
        final List<Map<String, Object>> observedUsers = new ArrayList<>();
        int currentStartIndex = 1;
        for (int i = 0; i < expectedPages; i++) {
            final SearchResults<Map<String, Object>> responseBody = fetchNextPage.apply(currentStartIndex);
            assertThat(responseBody.getTotalResults()).isEqualTo(expectedUsers.size());

            final int expectedNumberOfResultsInPage;
            if (i == expectedPages - 1 && lastPageIncomplete) {
                // last page -> might contain less elements
                expectedNumberOfResultsInPage = expectedUsers.size() % resultsPerPage;
            } else {
                // complete page
                expectedNumberOfResultsInPage = resultsPerPage;
            }
            assertThat(responseBody.getResources()).hasSize(expectedNumberOfResultsInPage);

            observedUsers.addAll(responseBody.getResources());
            currentStartIndex += responseBody.getResources().size();
        }

        // check next page -> should be empty
        final SearchResults<Map<String, Object>> responseBody = fetchNextPage.apply(currentStartIndex);
        assertThat(responseBody.getTotalResults()).isEqualTo(expectedUsers.size());
        assertThat(responseBody.getResources()).isNotNull().isEmpty();

        final List<Map<String, Object>> expectedResponse = expectedUsers.stream().map(scimUser -> Map.of(
                "id", (Object) scimUser.getId(),
                "userName", scimUser.getUserName(),
                "origin", scimUser.getOrigin()
        )).toList();

        assertThat(observedUsers).hasSameElementsAs(expectedResponse);
    }
}
