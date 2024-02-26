package org.cloudfoundry.identity.uaa.scim.endpoints;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Optional;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.alias.AliasMockMvcTestBase;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderAliasHandler;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderEndpoints;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserAliasHandler;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.fasterxml.jackson.core.type.TypeReference;

@DefaultTestContext
public class ScimUserEndpointsAliasMockMvcTests extends AliasMockMvcTestBase {
    private IdentityProviderAliasHandler idpEntityAliasHandler;
    private IdentityProviderEndpoints identityProviderEndpoints;
    private ScimUserAliasHandler scimUserAliasHandler;

    @BeforeEach
    void setUp() throws Exception {
        setUpTokensAndCustomZone();

        idpEntityAliasHandler = requireNonNull(webApplicationContext.getBean(IdentityProviderAliasHandler.class));
        identityProviderEndpoints = requireNonNull(webApplicationContext.getBean(IdentityProviderEndpoints.class));
        scimUserAliasHandler = requireNonNull(webApplicationContext.getBean(ScimUserAliasHandler.class));
    }

    @Nested
    class Read {
        @Nested
        class AliasFeatureDisabled {
            @BeforeEach
            void setUp() {
                arrangeAliasFeatureEnabled(false);
            }

            @AfterEach
            void tearDown() {
                arrangeAliasFeatureEnabled(true);
            }

            @Test
            void shouldStillReturnAliasPropertiesOfUsersWithAliasCreatedBeforehand_UaaToCustomZone() throws Throwable {
                shouldStillReturnAliasPropertiesOfUsersWithAliasCreatedBeforehand(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldStillReturnAliasPropertiesOfUsersWithAliasCreatedBeforehand_CustomToUaaZone() throws Throwable {
                shouldStillReturnAliasPropertiesOfUsersWithAliasCreatedBeforehand(customZone, IdentityZone.getUaa());
            }

            private void shouldStillReturnAliasPropertiesOfUsersWithAliasCreatedBeforehand(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                final IdentityProvider<?> idpWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        false,
                        () -> createIdpWithAlias(zone1, zone2)
                );

                // create a user with an alias in zone 1
                final ScimUser scimUser = buildScimUser(
                        idpWithAlias.getOriginKey(),
                        zone1.getId(),
                        null,
                        zone2.getId()
                );
                final ScimUser createdUserWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        false,
                        () -> createScimUser(zone1, scimUser)
                );
                assertThat(createdUserWithAlias.getAliasId()).isNotBlank();
                assertThat(createdUserWithAlias.getAliasZid()).isNotBlank().isEqualTo(zone2.getId());

                // read all users in zone 1 and search for created user
                final List<ScimUser> allUsersInZone1 = readRecentlyCreatedUsersInZone(zone1);
                final Optional<ScimUser> createdUserOpt = allUsersInZone1.stream()
                        .filter(user -> user.getUserName().equals(createdUserWithAlias.getUserName()))
                        .findFirst();
                assertThat(createdUserOpt).isPresent();

                // check if the user has non-empty alias properties
                final ScimUser createdUser = createdUserOpt.get();
                assertThat(createdUser).isEqualTo(createdUserWithAlias);
                assertThat(createdUser.getAliasId()).isNotBlank().isEqualTo(createdUserWithAlias.getAliasId());
                assertThat(createdUser.getAliasZid()).isNotBlank().isEqualTo(zone2.getId());
            }
        }
    }

    private static ScimUser buildScimUser(
            final String origin,
            final String zoneId,
            final String aliasId,
            final String aliasZid
    ) {
        final ScimUser scimUser = new ScimUser();
        scimUser.setOrigin(origin);
        scimUser.setAliasId(aliasId);
        scimUser.setAliasZid(aliasZid);
        scimUser.setZoneId(zoneId);

        scimUser.setUserName("john.doe");
        scimUser.setName(new ScimUser.Name("John", "Doe"));
        scimUser.setPrimaryEmail("john.doe@example.com");
        scimUser.setPassword("some-password");

        return scimUser;
    }

    private ScimUser createScimUser(final IdentityZone zone, final ScimUser scimUser) throws Exception {
        final MvcResult createResult = createScimUserAndReturnResult(zone, scimUser);
        assertThat(createResult.getResponse().getStatus()).isEqualTo(HttpStatus.CREATED.value());
        return JsonUtils.readValue(createResult.getResponse().getContentAsString(), ScimUser.class);
    }

    private MvcResult createScimUserAndReturnResult(
            final IdentityZone zone,
            final ScimUser scimUser
    ) throws Exception {
        final MockHttpServletRequestBuilder createRequestBuilder = post("/Users")
                .header("Authorization", "Bearer " + getAccessTokenForZone(zone.getId()))
                .header(IdentityZoneSwitchingFilter.HEADER, zone.getSubdomain())
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(scimUser));
        return mockMvc.perform(createRequestBuilder).andReturn();
    }

    private List<ScimUser> readRecentlyCreatedUsersInZone(final IdentityZone zone) throws Exception {
        final MockHttpServletRequestBuilder getRequestBuilder = get("/Users")
                .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER, zone.getSubdomain())
                .header("Authorization", "Bearer " + getAccessTokenForZone(zone.getId()))
                // return most recent users in first page to avoid querying for further pages
                .param("sortBy", "created")
                .param("sortOrder", "descending");
        final MvcResult getResult = mockMvc.perform(getRequestBuilder).andExpect(status().isOk()).andReturn();
        final SearchResults<ScimUser> searchResults = JsonUtils.readValue(
                getResult.getResponse().getContentAsString(),
                new TypeReference<>() {
                }
        );
        assertThat(searchResults).isNotNull();
        return searchResults.getResources();
    }

    @Override
    protected void arrangeAliasFeatureEnabled(final boolean enabled) {
        ReflectionTestUtils.setField(idpEntityAliasHandler, "aliasEntitiesEnabled", enabled);
        ReflectionTestUtils.setField(identityProviderEndpoints, "aliasEntitiesEnabled", enabled);
        ReflectionTestUtils.setField(scimUserAliasHandler, "aliasEntitiesEnabled", enabled);
    }
}
