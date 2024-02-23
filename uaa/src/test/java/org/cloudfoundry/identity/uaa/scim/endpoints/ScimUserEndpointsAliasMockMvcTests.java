package org.cloudfoundry.identity.uaa.scim.endpoints;

import static java.util.Objects.requireNonNull;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderAliasHandler;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderEndpoints;
import org.cloudfoundry.identity.uaa.scim.ScimUserAliasHandler;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.function.ThrowingSupplier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;

@DefaultTestContext
public class ScimUserEndpointsAliasMockMvcTests {
    private static final AlphanumericRandomValueStringGenerator RANDOM_STRING_GENERATOR = new AlphanumericRandomValueStringGenerator(8);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private TestClient testClient;

    private IdentityZone customZone;
    private String adminToken;
    private String identityToken;

    private IdentityProviderAliasHandler idpEntityAliasHandler;
    private IdentityProviderEndpoints identityProviderEndpoints;
    private ScimUserAliasHandler scimUserAliasHandler;

    @BeforeEach
    void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
                "admin",
                "adminsecret",
                "");
        identityToken = testClient.getClientCredentialsOAuthAccessToken(
                "identity",
                "identitysecret",
                "zones.write");
        customZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);

        idpEntityAliasHandler = requireNonNull(webApplicationContext.getBean(IdentityProviderAliasHandler.class));
        identityProviderEndpoints = requireNonNull(webApplicationContext.getBean(IdentityProviderEndpoints.class));
        scimUserAliasHandler = requireNonNull(webApplicationContext.getBean(ScimUserAliasHandler.class));
    }

    private void arrangeAliasFeatureEnabled(final boolean enabled) {
        ReflectionTestUtils.setField(idpEntityAliasHandler, "aliasEntitiesEnabled", enabled);
        ReflectionTestUtils.setField(identityProviderEndpoints, "aliasEntitiesEnabled", enabled);
        ReflectionTestUtils.setField(scimUserAliasHandler, "aliasEntitiesEnabled", enabled);
    }

    private <T> T executeWithTemporarilyEnabledAliasFeature(
            final boolean aliasFeatureEnabledBeforeAction,
            final ThrowingSupplier<T> action
    ) throws Throwable {
        arrangeAliasFeatureEnabled(true);
        try {
            return action.get();
        } finally {
            arrangeAliasFeatureEnabled(aliasFeatureEnabledBeforeAction);
        }
    }
}
