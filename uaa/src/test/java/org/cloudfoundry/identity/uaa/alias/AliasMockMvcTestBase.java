package org.cloudfoundry.identity.uaa.alias;

import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.junit.jupiter.api.function.ThrowingSupplier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

public abstract class AliasMockMvcTestBase {
    protected static final AlphanumericRandomValueStringGenerator RANDOM_STRING_GENERATOR = new AlphanumericRandomValueStringGenerator(8);
    private final Map<String, String> accessTokenCache = new HashMap<>();

    @Autowired
    protected WebApplicationContext webApplicationContext;
    @Autowired
    protected MockMvc mockMvc;
    @Autowired
    private TestClient testClient;

    protected IdentityZone customZone;
    protected IdentityZone uaaZone;
    private String adminToken;
    protected String identityToken;

    protected final void setUpTokensAndCustomZone() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
                "admin",
                "adminsecret",
                "");
        identityToken = testClient.getClientCredentialsOAuthAccessToken(
                "identity",
                "identitysecret",
                "zones.write");
        customZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);

        // look up UAA zone
        final JdbcIdentityZoneProvisioning zoneProvisioning = webApplicationContext.getBean(
                JdbcIdentityZoneProvisioning.class
        );
        uaaZone = zoneProvisioning.retrieve(IdentityZone.getUaaZoneId());
    }

    protected static AbstractIdentityProviderDefinition buildIdpDefinition(final String type) {
        switch (type) {
            case OIDC10:
                final OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
                try {
                    return definition
                            .setAuthUrl(URI.create("https://www.example.com/oauth/authorize").toURL())
                            .setLinkText("link text")
                            .setRelyingPartyId("relying-party-id")
                            .setRelyingPartySecret("relying-party-secret")
                            .setShowLinkText(true)
                            .setSkipSslValidation(true)
                            .setTokenKey("key")
                            .setTokenKeyUrl(URI.create("https://www.example.com/token_keys").toURL())
                            .setTokenUrl(URI.create("https://wwww.example.com/oauth/token").toURL());
                } catch (final MalformedURLException e) {
                    throw new RuntimeException(e);
                }
            case UAA:
                final PasswordPolicy passwordPolicy = new PasswordPolicy();
                passwordPolicy.setExpirePasswordInMonths(1);
                passwordPolicy.setMaxLength(100);
                passwordPolicy.setMinLength(10);
                passwordPolicy.setRequireDigit(1);
                passwordPolicy.setRequireUpperCaseCharacter(1);
                passwordPolicy.setRequireLowerCaseCharacter(1);
                passwordPolicy.setRequireSpecialCharacter(1);
                passwordPolicy.setPasswordNewerThan(new Date(System.currentTimeMillis()));
                return new UaaIdentityProviderDefinition(passwordPolicy, null);
            default:
                throw new IllegalArgumentException("IdP type not supported.");
        }
    }

    protected static IdentityProvider<?> buildIdpWithAliasProperties(
            final String idzId,
            final String aliasId,
            final String aliasZid,
            final String originKey,
            final String type
    ) {
        final AbstractIdentityProviderDefinition definition = buildIdpDefinition(type);

        final IdentityProvider<AbstractIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(idzId);
        provider.setAliasId(aliasId);
        provider.setAliasZid(aliasZid);
        provider.setName(originKey);
        provider.setOriginKey(originKey);
        provider.setType(type);
        provider.setConfig(definition);
        provider.setActive(true);
        return provider;
    }

    protected static IdentityProvider<?> buildOidcIdpWithAliasProperties(
            final String idzId,
            final String aliasId,
            final String aliasZid
    ) {
        final String originKey = RANDOM_STRING_GENERATOR.generate();
        return buildIdpWithAliasProperties(idzId, aliasId, aliasZid, originKey, OIDC10);
    }

    protected static List<String> getScopesForZone(final String zoneId, final String... scopes) {
        return Stream.of(scopes).map(scope -> "zones.%s.%s".formatted(zoneId, scope)).toList();
    }

    protected static IdentityProvider<?> buildUaaIdpWithAliasProperties(
            final String idzId,
            final String aliasId,
            final String aliasZid
    ) {
        final String originKey = RANDOM_STRING_GENERATOR.generate();
        return buildIdpWithAliasProperties(idzId, aliasId, aliasZid, originKey, UAA);
    }

    protected final <T> T executeWithTemporarilyEnabledAliasFeature(
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

    protected final String getAccessTokenForZone(final String zoneId) throws Exception {
        final String cacheLookupResult = accessTokenCache.get(zoneId);
        if (cacheLookupResult != null) {
            return cacheLookupResult;
        }

        final List<String> scopesForZone = getScopesForZone(zoneId, "admin");

        final ScimUser adminUser = MockMvcUtils.createAdminForZone(
                mockMvc,
                adminToken,
                String.join(",", scopesForZone),
                IdentityZone.getUaaZoneId()
        );
        final String accessToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(
                mockMvc,
                "identity",
                "identitysecret",
                adminUser.getId(),
                adminUser.getUserName(),
                adminUser.getPassword(),
                String.join(" ", scopesForZone),
                TokenConstants.TokenFormat.JWT // use JWT for later checking if all scopes are present
        );

        // check if the token contains the expected scopes
        final Claims claims = UaaTokenUtils.getClaimsFromTokenString(accessToken);
        assertThat(claims.getScope()).hasSameElementsAs(scopesForZone);

        // cache the access token
        accessTokenCache.put(zoneId, accessToken);

        return accessToken;
    }

    protected final MvcResult createIdpAndReturnResult(final IdentityZone zone, final IdentityProvider<?> idp) throws Exception {
        final MockHttpServletRequestBuilder createRequestBuilder = post("/identity-providers")
                .param("rawConfig", "true")
                .header("Authorization", "Bearer " + getAccessTokenForZone(zone.getId()))
                .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER, zone.getSubdomain())
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(idp));
        return mockMvc.perform(createRequestBuilder).andReturn();
    }

    protected final IdentityProvider<?> createIdp(final IdentityZone zone, final IdentityProvider<?> idp) throws Exception {
        final MvcResult createResult = createIdpAndReturnResult(zone, idp);
        assertThat(createResult.getResponse().getStatus()).isEqualTo(HttpStatus.CREATED.value());
        return JsonUtils.readValue(createResult.getResponse().getContentAsString(), IdentityProvider.class);
    }

    protected final IdentityProvider<?> createIdpWithAlias(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
        final IdentityProvider<?> provider = buildOidcIdpWithAliasProperties(zone1.getId(), null, zone2.getId());
        final IdentityProvider<?> createdOriginalIdp = createIdp(zone1, provider);
        assertThat(createdOriginalIdp.getAliasId()).isNotBlank();
        assertThat(createdOriginalIdp.getAliasZid()).isNotBlank();
        return createdOriginalIdp;
    }

    protected abstract void arrangeAliasFeatureEnabled(final boolean enabled);
}
