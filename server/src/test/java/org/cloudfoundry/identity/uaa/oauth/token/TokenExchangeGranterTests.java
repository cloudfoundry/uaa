package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.TokenTestSupport;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.oauth.TokenActor;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.OPENID;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_TOKEN_EXCHANGE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TOKEN_TYPE_ACCESS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TOKEN_TYPE_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TOKEN_TYPE_REFRESH;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TokenExchangeGranterTests {

    private TokenExchangeGranter granter;
    private TokenRequest tokenRequest;
    private ClientDetails client;
    private UaaOauth2Authentication authentication;
    private UaaAuthentication uaaAuthentication;
    private AuthorizationServerTokenServices tokenServices;
    private MultitenantClientServices clientDetailsService;
    private OAuth2RequestFactory requestFactory;
    private RevocableTokenProvisioning revocableTokenProvisioning;
    private ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager;
    private Map<String, String> requestParameters;

    @BeforeEach
    void setUp() {
        tokenServices = mock(AuthorizationServerTokenServices.class);
        clientDetailsService = mock(MultitenantClientServices.class);
        requestFactory = mock(OAuth2RequestFactory.class);
        revocableTokenProvisioning = mock(RevocableTokenProvisioning.class);
        externalOAuthAuthenticationManager = mock(ExternalOAuthAuthenticationManager.class);
        // Default: parse-only (mirrors the pre-fix behaviour for tests that don't need
        // signature checking). Individual tests that want verification to fail should
        // override this stub to throw InsufficientAuthenticationException.
        lenient().when(externalOAuthAuthenticationManager.verifySubjectToken(anyString()))
                .thenAnswer(inv -> JwtHelper.decode(inv.getArgument(0, String.class)).getClaimSet());
        granter = spy(new TokenExchangeGranter(tokenServices, clientDetailsService, requestFactory, revocableTokenProvisioning, externalOAuthAuthenticationManager));
        tokenRequest = new TokenRequest(Collections.emptyMap(), "client_ID", Collections.emptySet(), GRANT_TYPE_TOKEN_EXCHANGE);

        authentication = mock(UaaOauth2Authentication.class);
        UaaUser user = new UaaUser("id",
                "username",
                null,
                "user@user.org",
                Collections.emptyList(),
                "Firstname",
                "lastName",
                new Date(),
                new Date(),
                OriginKeys.OIDC10,
                null,
                true,
                IdentityZoneHolder.get().getId(),
                "salt",
                new Date()
        );
        uaaAuthentication = new UaaAuthentication(
                new UaaPrincipal(user), Collections.emptyList(), null
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        client = new UaaClientDetails("clientID", null, "uaa.user", GRANT_TYPE_TOKEN_EXCHANGE, null);
        when(clientDetailsService.loadClientByClientId(eq(client.getClientId()), anyString())).thenReturn(client);
        requestParameters = new HashMap<>();
        requestParameters.put(OAuth2Utils.CLIENT_ID, client.getClientId());
        requestParameters.put(GRANT_TYPE, GRANT_TYPE_TOKEN_EXCHANGE);
        tokenRequest.setRequestParameters(requestParameters);
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void non_authentication_validates_correctly() {
        SecurityContextHolder.clearContext();
        assertThatThrownBy(() -> granter.validateRequest(tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("User authentication not found");
    }

    @Test
    void client_authentication_only() {
        when(authentication.isClientOnly()).thenReturn(true);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertThatThrownBy(() -> granter.validateRequest(tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("User authentication not found");
    }

    @Test
    void missing_token_request() {
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        assertThatThrownBy(() -> granter.validateRequest(null))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("Missing subject token request object");
    }

    @Test
    void missing_request_parameters() {
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        tokenRequest.setRequestParameters(Collections.emptyMap());
        assertThatThrownBy(() -> granter.validateRequest(tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("Missing subject token request object");
    }

    @Test
    void missing_grant_type() {
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        requestParameters.remove(GRANT_TYPE);
        tokenRequest.setRequestParameters(requestParameters);
        assertThatThrownBy(() -> granter.validateRequest(tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("Missing grant type");
    }

    @Test
    void invalid_grant_type() {
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        requestParameters.put(GRANT_TYPE, "password");
        tokenRequest.setRequestParameters(requestParameters);
        assertThatThrownBy(() -> granter.validateRequest(tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("Invalid grant type");
    }

    @Test
    void grant_validates_request() {
        SecurityContextHolder.clearContext();
        assertThatThrownBy(() -> granter.grant(GRANT_TYPE_TOKEN_EXCHANGE, tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("User authentication not found");
        verify(granter, times(1)).validateRequest(same(tokenRequest));
    }

    @Test
    void invalid_subject_token_type() {
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        requestParameters.put("subject_token", "some-fake-token");
        requestParameters.put("subject_token_type", TOKEN_TYPE_REFRESH);
        tokenRequest.setRequestParameters(requestParameters);
        assertThatThrownBy(() -> granter.validateRequest(tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("Invalid subject token type, only urn:ietf:params:oauth:token-type:id_token and urn:ietf:params:oauth:token-type:access_token are supported");
    }

    @Test
    void get_oauth2_authentication_with_id_token() {
        requestParameters.put("subject_token", "some-fake-token");
        requestParameters.put("subject_token_type", TOKEN_TYPE_ID);
        tokenRequest.setRequestParameters(requestParameters);
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        OAuth2Request request = mock(OAuth2Request.class);
        when(requestFactory.createOAuth2Request(same(client), same(tokenRequest))).thenReturn(request);
        OAuth2Authentication result = granter.getOAuth2Authentication(client, tokenRequest);
        assertThat(result.getOAuth2Request()).isSameAs(request);
        assertThat(result.getUserAuthentication()).isSameAs(uaaAuthentication);
    }

    @Test
    void get_oauth2_authentication_with_access_token() {
        requestParameters.put("subject_token", "some-fake-token");
        requestParameters.put("subject_token_type", TOKEN_TYPE_ACCESS);
        requestParameters.put("requested_token_type", TOKEN_TYPE_ACCESS);
        tokenRequest.setRequestParameters(requestParameters);
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        OAuth2Request request = mock(OAuth2Request.class);
        when(requestFactory.createOAuth2Request(same(client), same(tokenRequest))).thenReturn(request);
        OAuth2Authentication result = granter.getOAuth2Authentication(client, tokenRequest);
        assertThat(result.getOAuth2Request()).isSameAs(request);
        assertThat(result.getUserAuthentication()).isSameAs(uaaAuthentication);
    }


    @Test
    void invalid_requested_token_type() {
        requestParameters.put("subject_token", "some-fake-token");
        requestParameters.put("subject_token_type", TOKEN_TYPE_ACCESS);
        requestParameters.put("requested_token_type", TOKEN_TYPE_ID);
        tokenRequest.setRequestParameters(requestParameters);
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        assertThatThrownBy(() -> granter.validateRequest(tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("Invalid requested token type, only urn:ietf:params:oauth:token-type:access_token is supported");
    }

    @Test
    void opaque_subject_token_is_resolved_from_db() {
        // Three Base64URL segments so JWTParser.parse accepts the fixture (third segment is "signature" encoded)
        String jwtValue = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaXNzIjoiaHR0cHM6Ly91YWEuZXhhbXBsZS5jb20iLCJ1c2VyX25hbWUiOiJqb2huIiwidXNlcl9pZCI6InVzZXIxMjMiLCJvcmlnaW4iOiJ1YWEifQ.c2lnbmF0dXJl";
        String opaqueTokenId = "opaque-token-id-no-dots";

        RevocableToken revocableToken = mock(RevocableToken.class);
        when(revocableToken.getValue()).thenReturn(jwtValue);
        when(revocableTokenProvisioning.retrieve(eq(opaqueTokenId), anyString())).thenReturn(revocableToken);

        requestParameters.put("subject_token", opaqueTokenId);
        requestParameters.put("subject_token_type", TOKEN_TYPE_ACCESS);
        tokenRequest.setRequestParameters(requestParameters);

        // getTokenActor will call revocableTokenProvisioning.retrieve() for the opaque token
        // then decode the backing JWT — verify the provisioning was called
        TokenActor actor = granter.getTokenActor(tokenRequest);

        verify(revocableTokenProvisioning, times(1)).retrieve(eq(opaqueTokenId), anyString());
        assertThat(actor.getSubject()).isEqualTo("user123");
        assertThat(actor.getIssuer()).isEqualTo("https://uaa.example.com");
    }

    @Test
    void opaque_subject_token_not_found_throws_invalid_grant() {
        String opaqueTokenId = "expired-or-missing-opaque-token";
        when(revocableTokenProvisioning.retrieve(eq(opaqueTokenId), anyString()))
                .thenThrow(new EmptyResultDataAccessException(1));

        requestParameters.put("subject_token", opaqueTokenId);
        requestParameters.put("subject_token_type", TOKEN_TYPE_ACCESS);
        tokenRequest.setRequestParameters(requestParameters);

        assertThatThrownBy(() -> granter.getTokenActor(tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("Invalid subject_token: not a JWT and not found in the revocable token store");
    }

    @Test
    void jwt_subject_token_does_not_query_revocable_store() throws Exception {
        TokenTestSupport support = new TokenTestSupport(null, null);
        try {
            String jwt = support.getIdTokenAsString(Collections.singletonList(OPENID));
            requestParameters.put("subject_token", jwt);
            requestParameters.put("subject_token_type", TOKEN_TYPE_ACCESS);
            tokenRequest.setRequestParameters(requestParameters);

            granter.getTokenActor(tokenRequest);

            verify(revocableTokenProvisioning, never()).retrieve(anyString(), anyString());
        } finally {
            support.clear();
        }
    }

    /**
     * Verifies that {@link TokenExchangeGranter#getTokenActor} rejects a {@code subject_token}
     * whose signature cannot be verified against the registered identity provider.
     *
     * <p>Provider resolution is driven by the token's {@code iss} claim: the granter looks up
     * the registered IdP whose configured issuer matches the {@code iss} value, then verifies
     * the JWT signature against that IdP's published keys. Any failure — unknown issuer, bad
     * signature, or expired token — must be propagated as {@link InvalidGrantException}.
     */
    @Nested
    class SubjectTokenSignatureVerification {

        private String forgeSelfSignedJwt(String payloadJson) {
            Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
            String header = enc.encodeToString(
                    "{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
            String payload = enc.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
            // A real RS256 signature would be ~342 base64url chars derived from a private RSA key.
            // This is plaintext gibberish — it cannot pass verification for any RSA public key.
            String bogusSignature = enc.encodeToString(
                    "FORGED-NOT-A-REAL-RSA-SIGNATURE".getBytes(StandardCharsets.UTF_8));
            return header + "." + payload + "." + bogusSignature;
        }

        @Test
        void getTokenActor_whenSubjectTokenHasBogusSignature_throwsInvalidGrant() {
            // A JWT with a completely fabricated signature and an issuer that has no
            // corresponding registered IdP.  resolveOriginProvider() looks up by iss,
            // finds nothing, and throws InsufficientAuthenticationException.
            String forgedJwt = forgeSelfSignedJwt(
                    "{\"sub\":\"forged-privileged-user\"" +
                    ",\"iss\":\"https://not-a-registered-idp.example.com\"" +
                    ",\"user_name\":\"forged-admin\"" +
                    ",\"user_id\":\"forged-user-id\"" +
                    ",\"origin\":\"uaa\"}");

            when(externalOAuthAuthenticationManager.verifySubjectToken(forgedJwt))
                    .thenThrow(new InsufficientAuthenticationException("Unable to map issuer to a registered provider"));

            requestParameters.put("subject_token", forgedJwt);
            requestParameters.put("subject_token_type", TOKEN_TYPE_ACCESS);
            tokenRequest.setRequestParameters(requestParameters);

            assertThatThrownBy(() -> granter.getTokenActor(tokenRequest))
                    .isInstanceOf(InvalidGrantException.class);
        }

        @Test
        void getTokenActor_whenSubjectTokenPayloadIsTamperedAfterSigning_throwsInvalidGrant()
                throws Exception {
            // Start with a legitimately signed JWT from this UAA instance.
            TokenTestSupport support = new TokenTestSupport(null, null);
            try {
                String legitimateJwt = support.getIdTokenAsString(Collections.singletonList(OPENID));

                // Replace the payload with attacker-controlled claims while keeping the
                // original header and signature.  The signature now covers different bytes
                // than the new payload, so validateToken() must reject it.
                String[] parts = legitimateJwt.split("\\.");
                String originalHeader    = parts[0];
                String originalSignature = parts[2];

                Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
                String tamperedPayload = enc.encodeToString(
                        ("{\"sub\":\"tampered-admin-user\"" +
                         ",\"iss\":\"https://not-a-registered-idp.example.com\"" +
                         ",\"user_name\":\"tampered-admin\"" +
                         ",\"user_id\":\"tampered-user-id\"" +
                         ",\"origin\":\"uaa\"}").getBytes(StandardCharsets.UTF_8));

                String tamperedJwt = originalHeader + "." + tamperedPayload + "." + originalSignature;

                when(externalOAuthAuthenticationManager.verifySubjectToken(tamperedJwt))
                        .thenThrow(new InsufficientAuthenticationException("Signature verification failed"));

                requestParameters.put("subject_token", tamperedJwt);
                requestParameters.put("subject_token_type", TOKEN_TYPE_ACCESS);
                tokenRequest.setRequestParameters(requestParameters);

                assertThatThrownBy(() -> granter.getTokenActor(tokenRequest))
                        .isInstanceOf(InvalidGrantException.class);
            } finally {
                support.clear();
            }
        }
    }
}
