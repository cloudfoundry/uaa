package org.cloudfoundry.identity.uaa.mock.token;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthCodeToken;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetcher;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.Authentication;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TOKEN_TYPE_ACCESS;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@Import(TokenExchangeOverrideAuthManagerMockMvcTests.TokenExchangeConfiguration.class)
@DefaultTestContext
public class TokenExchangeOverrideAuthManagerMockMvcTests extends TokenExchangeMockMvcBase {

    static class TokenExchangeConfiguration {
        @Bean
        ExternalOAuthAuthenticationManager tokenExchangeAuthenticationManager(
                @Qualifier("externalOAuthProviderConfigurator") IdentityProviderProvisioning providerProvisioning,
                @Qualifier("identityZoneManager") IdentityZoneManager identityZoneManager,
                @Qualifier("trustingRestTemplate") RestTemplate trustingRestTemplate,
                @Qualifier("nonTrustingRestTemplate") RestTemplate nonTrustingRestTemplate,
                @Qualifier("tokenEndpointBuilder") TokenEndpointBuilder tokenEndpointBuilder,
                @Qualifier("keyInfoService") KeyInfoService keyInfoService,
                @Qualifier("oidcMetadataFetcher") OidcMetadataFetcher oidcMetadataFetcher,
                @Qualifier("userDatabase") UaaUserDatabase userDatabase,
                @Qualifier("externalGroupMembershipManager") ScimGroupExternalMembershipManager externalMembershipManager
        ) {
            ExternalOAuthAuthenticationManager bean = new ExternalOAuthAuthenticationManager(
                    providerProvisioning,
                    identityZoneManager,
                    trustingRestTemplate,
                    nonTrustingRestTemplate,
                    tokenEndpointBuilder,
                    keyInfoService,
                    oidcMetadataFetcher
            ) {
                @Override
                public AuthenticationData getExternalAuthenticationDetails(Authentication authentication) {
                    AuthenticationData result = super.getExternalAuthenticationDetails(authentication);
                    this.setOrigin("override-origin");
                    return result;
                }

                @Override
                public Authentication authenticate(Authentication authentication) {
                    ExternalOAuthCodeToken token = (ExternalOAuthCodeToken)authentication;
                    if (token.getIdToken() == null) {
                        token = new ExternalOAuthCodeToken(
                                token.getCode(),
                                token.getOrigin(),
                                token.getRedirectUrl(),
                                token.getAccessToken(),
                                token.getAccessToken(),
                                token.getSignedRequest(),
                                token.getUaaAuthenticationDetails()
                        );
                    }
                    return super.authenticate(token);
                }
            };
            bean.setUserDatabase(userDatabase);
            bean.setExternalMembershipManager(externalMembershipManager);
            return bean;
        }
    }

    @Test
    void token_exchange_modify_origin_based_on_bean_override() throws Exception {
        ThreeWayUAASetup multiAuthSetup = getThreeWayUaaSetUp();
        AuthorizationServer thirdParty = multiAuthSetup.thirdPartyIdp();
        AuthorizationServer workerServer = multiAuthSetup.workerServer();

        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setAuthUrl(URI.create("http://myauthurl.com").toURL());
        definition.setTokenUrl(null);
        definition.setRelyingPartySecret(SECRET);
        definition.setLinkText("my oidc provider");
        definition.setResponseType("id_token");
        definition.addAttributeMapping("user_name", "user_name");
        IdentityProvider<OIDCIdentityProviderDefinition> pointToThirdParty = MultitenancyFixture.identityProvider(
                "override-origin",
                workerServer.zone().getIdentityZone().getId()
        );
        pointToThirdParty.setType(OriginKeys.OIDC10);
        pointToThirdParty.setConfig(definition);
        createOIDCProvider(workerServer.zone().getIdentityZone(), pointToThirdParty);

        //use the id_token(hub) to make a token-exchange on foundation-uaa
        String accessToken = (String) multiAuthSetup.controlServerTokens().get("access_token");
        String tokenType = TOKEN_TYPE_ACCESS;
        String audience = null;
        String scope = null;

        ResultActions tokenExchangeResult = performTokenExchangeGrantForJWT(
                workerServer.zone().getIdentityZone(),
                accessToken,
                tokenType,
                tokenType,
                audience,
                scope,
                workerServer.client(),
                ClientAuthType.FORM,
                null
        );

        tokenExchangeResult
                .andExpect(status().isOk())
                .andExpect(jsonPath(".access_token").isNotEmpty());
        Map<String, Object> tokens = JsonUtils.readValueAsMap(tokenExchangeResult.andReturn().getResponse().getContentAsString());

        Jwt tokenClaims = JwtHelper.decode((String) tokens.get("access_token"));
        Map<String, Object> claims = JsonUtils.readValueAsMap(tokenClaims.getClaims());

        assertThat(claims.get("user_name")).isEqualTo(thirdParty.user().getUserName());
        assertThat(claims.get("email")).isEqualTo(thirdParty.user().getEmails().get(0).getValue());
        assertThat(claims.get("origin")).isEqualTo("override-origin");
    }




}
