package org.cloudfoundry.identity.uaa.oauth;

import static org.cloudfoundry.identity.uaa.oauth.Claims.ADDITIONAL_AZ_ATTR;
import static org.cloudfoundry.identity.uaa.oauth.Claims.AUD;
import static org.cloudfoundry.identity.uaa.oauth.Claims.AUTHORITIES;
import static org.cloudfoundry.identity.uaa.oauth.Claims.AZP;
import static org.cloudfoundry.identity.uaa.oauth.Claims.CID;
import static org.cloudfoundry.identity.uaa.oauth.Claims.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.Claims.EMAIL;
import static org.cloudfoundry.identity.uaa.oauth.Claims.EXP;
import static org.cloudfoundry.identity.uaa.oauth.Claims.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.Claims.IAT;
import static org.cloudfoundry.identity.uaa.oauth.Claims.ISS;
import static org.cloudfoundry.identity.uaa.oauth.Claims.JTI;
import static org.cloudfoundry.identity.uaa.oauth.Claims.SUB;
import static org.cloudfoundry.identity.uaa.oauth.Claims.USER_ID;
import static org.cloudfoundry.identity.uaa.oauth.Claims.USER_NAME;
import static org.cloudfoundry.identity.uaa.oauth.Claims.ZONE_ID;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.oauth.token.OpenIdToken;
import org.cloudfoundry.identity.uaa.oauth.token.SignerProvider;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

public class FastRemoteTokenServiceTests {

    private static final String TOKEN_ISSUER_ID = "http://localhost:8080/uaa/oauth/token";

    private static final String TOKEN_KEY_URL = "https://localhost:8080/uaa/token_key";

    private static final String TOKEN_VERIFYING_KEY = "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0m59l2u9iDnMbrXHfqkO\n"
            + "rn2dVQ3vfBJqcDuFUK03d+1PZGbVlNCqnkpIJ8syFppW8ljnWweP7+LiWpRoz0I7\n"
            + "fYb3d8TjhV86Y997Fl4DBrxgM6KTJOuE/uxnoDhZQ14LgOU2ckXjOzOdTsnGMKQB\n"
            + "LCl0vpcXBtFLMaSbpv1ozi8h7DJyVZ6EnFQZUWGdgTMhDrmqevfx95U/16c5WBDO\n"
            + "kqwIn7Glry9n9Suxygbf8g5AzpWcusZgDLIIZ7JTUldBb8qU2a0Dl4mvLZOn4wPo\n"
            + "jfj9Cw2QICsc5+Pwf21fP+hzf+1WSRHbnYv8uanRO0gZ8ekGaghM/2H6gqJbo2nI\n" + "JwIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";

    private static final String TOKEN_SIGNING_KEY = "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIIEowIBAAKCAQEA0m59l2u9iDnMbrXHfqkOrn2dVQ3vfBJqcDuFUK03d+1PZGbV\n"
            + "lNCqnkpIJ8syFppW8ljnWweP7+LiWpRoz0I7fYb3d8TjhV86Y997Fl4DBrxgM6KT\n"
            + "JOuE/uxnoDhZQ14LgOU2ckXjOzOdTsnGMKQBLCl0vpcXBtFLMaSbpv1ozi8h7DJy\n"
            + "VZ6EnFQZUWGdgTMhDrmqevfx95U/16c5WBDOkqwIn7Glry9n9Suxygbf8g5AzpWc\n"
            + "usZgDLIIZ7JTUldBb8qU2a0Dl4mvLZOn4wPojfj9Cw2QICsc5+Pwf21fP+hzf+1W\n"
            + "SRHbnYv8uanRO0gZ8ekGaghM/2H6gqJbo2nIJwIDAQABAoIBAHPV9rSfzllq16op\n"
            + "zoNetIJBC5aCcU4vJQBbA2wBrgMKUyXFpdSheQphgY7GP/BJTYtifRiS9RzsHAYY\n"
            + "pAlTQEQ9Q4RekZAdd5r6rlsFrUzL7Xj/CVjNfQyHPhPocNqwrkxp4KrO5eL06qcw\n"
            + "UzT7UtnoiCdSLI7IL0hIgJZP8J1uPNdXH+kkDEHE9xzU1q0vsi8nBLlim+ioYfEa\n"
            + "Q/Q/ovMNviLKVs+ZUz+wayglDbCzsevuU+dh3Gmfc98DJw6n6iClpd4fDPqvhxUO\n"
            + "BDeQT1mFeHxexDse/kH9nygxT6E4wlU1sw0TQANcT6sHReyHT1TlwnWlCQzoR3l2\n"
            + "RmkzUsECgYEA8W/VIkfyYdUd5ri+yJ3iLdYF2tDvkiuzVmJeA5AK2KO1fNc7cSPK\n"
            + "/sShHruc0WWZKWiR8Tp3d1XwA2rHMFHwC78RsTds+NpROs3Ya5sWd5mvmpEBbL+z\n"
            + "cl3AU9NLHVvsZjogmgI9HIMTTl4ld7GDsFMt0qlCDztqG6W/iguQCx8CgYEA3x/j\n"
            + "UkP45/PaFWd5c1DkWvmfmi9UxrIM7KeyBtDExGIkffwBMWFMCWm9DODw14bpnqAA\n"
            + "jH5AhQCzVYaXIdp12b+1+eOOckYHwzjWOFpJ3nLgNK3wi067jVp0N0UfgV5nfYw/\n"
            + "+YoHfYRCGsM91fowh7wLcyPPwmSAbQAKwbOZKfkCgYEAnccDdZ+m2iA3pitdIiVr\n"
            + "RaDzuoeHx/IfBHjMD2/2ZpS1aZwOEGXfppZA5KCeXokSimj31rjqkWXrr4/8E6u4\n"
            + "PzTiDvm1kPq60r7qi4eSKx6YD15rm/G7ByYVJbKTB+CmoDekToDgBt3xo+kKeyna\n"
            + "cUQqUdyieunM8bxja4ca3ukCgYAfrDAhomJ30qa3eRvFYcs4msysH2HiXq30/g0I\n"
            + "aKQ12FSjyZ0FvHEFuQvMAzZM8erByKarStSvzJyoXFWhyZgHE+6qDUJQOF6ruKq4\n"
            + "DyEDQb1P3Q0TSVbYRunOWrKRM6xvJvSB4LUVfSvBDsv9TumKqwfZDVFVn9yXHHVq\n"
            + "b6sjSQKBgDkcyYkAjpOHoG3XKMw06OE4OKpP9N6qU8uZOuA8ZF9ZyR7vFf4bCsKv\n"
            + "QH+xY/4h8tgL+eASz5QWhj8DItm8wYGI5lKJr8f36jk0JLPUXODyDAeN6ekXY9LI\n"
            + "fudkijw0dnh28LJqbkFF5wLNtATzyCfzjp+czrPMn9uqLNKt/iVD\n" + "-----END RSA PRIVATE KEY-----\n";

    private final SignerProvider signerProvider;
    private final FastRemoteTokenServices services = new FastRemoteTokenServices();

    private final Map<String, Object> body = new HashMap<String, Object>();

    public FastRemoteTokenServiceTests() throws Exception {

        this.signerProvider = new SignerProvider();
        this.signerProvider.setSigningKey(TOKEN_SIGNING_KEY);
        this.signerProvider.setVerifierKey(TOKEN_VERIFYING_KEY);
        this.signerProvider.afterPropertiesSet();

        this.body.put(Claims.CLIENT_ID, "remote");
        this.body.put(Claims.USER_NAME, "olds");
        this.body.put(Claims.EMAIL, "olds@vmware.com");
        this.body.put(Claims.ISS, TOKEN_ISSUER_ID);
        this.body.put(Claims.USER_ID, "HDGFJSHGDF");

        ParameterizedTypeReference<Map<String, Object>> typeRef =
                new ParameterizedTypeReference<Map<String, Object>>() {
                };

        RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
        Mockito.when(restTemplate.exchange(TOKEN_KEY_URL, HttpMethod.GET, null, typeRef)).thenReturn(
                mockTokenKeyReponseEntity());
        this.services.setRestTemplate(restTemplate);
        this.services.setTrustedIssuerIdsRegex("^http://(.*\\.)?localhost:8080/uaa/oauth/token$");
    }

    private String mockAccessToken(final int validitySeconds) {
        return mockAccessToken(TOKEN_ISSUER_ID, System.currentTimeMillis(), validitySeconds);
    }

    private String mockAccessToken(final long issuedAtMillis, final int validitySeconds) {
        return mockAccessToken(TOKEN_ISSUER_ID, issuedAtMillis, validitySeconds);
    }

    private String mockAccessToken(final String issuerId, final long issuedAtMillis, final int validitySeconds) {
        Collection<GrantedAuthority> clientScopes =
                Arrays.asList(new GrantedAuthority[] { new SimpleGrantedAuthority("uaa.resource") });
        Set<String> requestedScopes = new HashSet<>(Arrays.asList(new String[] { "openid" }));
        Set<String> resourceIds = new HashSet<>(Arrays.asList(new String[] { "none" }));
        OpenIdToken openIdToken =
                createAccessToken(issuerId, "1adc931e-d65f-4357-b90d-dd4131b8749a", "marissa", "marissa@test.com",
                        validitySeconds, clientScopes, requestedScopes, "cf", resourceIds, "passsword", null, null,
                        null, null, issuedAtMillis);
        return openIdToken.getValue();
    }

    private OpenIdToken createAccessToken(final String issuerId, final String userId, final String username,
            final String userEmail, final int validitySeconds, final Collection<GrantedAuthority> clientScopes,
            final Set<String> requestedScopes, final String clientId, final Set<String> resourceIds,
            final String grantType, final String refreshToken,
            final Map<String, String> additionalAuthorizationAttributes, final Set<String> responseTypes,
            final String revocableHashSignature, final long issuedAtMillis) {

        String tokenId = UUID.randomUUID().toString();
        OpenIdToken accessToken = new OpenIdToken(tokenId);
        if (validitySeconds > 0) {
            accessToken.setExpiration(new Date(issuedAtMillis + (validitySeconds * 1000L)));
        }
        accessToken.setRefreshToken(refreshToken == null ? null : new DefaultOAuth2RefreshToken(refreshToken));

        if (null == requestedScopes || requestedScopes.size() == 0) {
            // logger.debug("No scopes were granted");
            throw new InvalidTokenException("No scopes were granted");
        }

        accessToken.setScope(requestedScopes);

        Map<String, Object> info = new HashMap<String, Object>();
        info.put(JTI, accessToken.getValue());
        if (null != additionalAuthorizationAttributes) {
            info.put(ADDITIONAL_AZ_ATTR, additionalAuthorizationAttributes);
        }
        accessToken.setAdditionalInformation(info);

        String content;
        try {
            content =
                    JsonUtils.writeValueAsString(createJWTAccessToken(accessToken, issuerId, userId, username,
                            userEmail, clientScopes, requestedScopes, clientId, resourceIds, grantType, refreshToken,
                            revocableHashSignature, issuedAtMillis));
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalStateException("Cannot convert access token to JSON", e);
        }
        String token = JwtHelper.encode(content, this.signerProvider.getSigner()).getEncoded();

        // This setter copies the value and returns. Don't change.
        accessToken.setValue(token);

        return accessToken;

    }

    private static Map<String, ?> createJWTAccessToken(final OAuth2AccessToken token, final String issuerId,
            final String userId, final String username, final String userEmail,
            final Collection<GrantedAuthority> clientScopes, final Set<String> requestedScopes,
            final String clientId, final Set<String> resourceIds, final String grantType, final String refreshToken,
            final String revocableHashSignature, final long issuedAtMillis) {

        Map<String, Object> response = new LinkedHashMap<String, Object>();

        response.put(JTI, token.getAdditionalInformation().get(JTI));
        response.putAll(token.getAdditionalInformation());

        response.put(SUB, userId);
        if (null != clientScopes) {
            response.put(AUTHORITIES, AuthorityUtils.authorityListToSet(clientScopes));
        }

        response.put(OAuth2AccessToken.SCOPE, requestedScopes);
        response.put(CLIENT_ID, clientId);
        response.put(CID, clientId);
        response.put(AZP, clientId); // openId Connect

        if (null != grantType) {
            response.put(GRANT_TYPE, grantType);
        }
        if (!"client_credentials".equals(grantType)) {
            response.put(USER_ID, userId);
            response.put(USER_NAME, username == null ? userId : username);
            if (null != userEmail) {
                response.put(EMAIL, userEmail);
            }
        }

        if (StringUtils.hasText(revocableHashSignature)) {
            response.put(Claims.REVOCATION_SIGNATURE, revocableHashSignature);
        }

        response.put(IAT, issuedAtMillis / 1000);
        if (token.getExpiration() != null) {
            response.put(EXP, token.getExpiration().getTime() / 1000);
        }

        if (issuerId != null) {
            response.put(ISS, issuerId);
            response.put(ZONE_ID, IdentityZoneHolder.get().getId());
        }

        response.put(AUD, resourceIds);

        return response;
    }

    private static ResponseEntity<Map<String, Object>> mockTokenKeyReponseEntity() {
        Map<String, Object> responseEntityBody = new HashMap<>();
        responseEntityBody.put("alg", "SHA256withRSA");
        responseEntityBody.put("value", TOKEN_VERIFYING_KEY);
        responseEntityBody.put("kty", "RSA");
        responseEntityBody.put("use", "sig");
        responseEntityBody
                .put("n",
                        "ANJufZdrvYg5zG61x36pDq59nVUN73wSanA7hVCtN3ftT2Rm1ZTQqp5KSCfLMhaaVvJY51sHj+/i4lqUaM9CO32G93fE44VfOmPfexZ"
                                + "eAwa8YDOikyTrhP7sZ6A4WUNeC4DlNnJF4zsznU7JxjCkASwpdL6XFwbRSzGkm6b9aM4vIewyclWehJxUGVFhnYEzIQ65qnr38feV"
                                + "P9enOVgQzpKsCJ+xpa8vZ/UrscoG3/IOQM6VnLrGYAyyCGeyU1JXQW/KlNmtA5eJry2Tp+MD6I34/QsNkCArHOfj8H9tXz/oc3/tV"
                                + "kkR252L/Lmp0TtIGfHpBmoITP9h+oKiW6NpyCc=");
        responseEntityBody.put("e", "AQAB");
        return new ResponseEntity<Map<String, Object>>(responseEntityBody, HttpStatus.OK);
    }

    @Test
    public void testLoadAuthentication() throws Exception {
        String accessToken = mockAccessToken(60);
        OAuth2Authentication result = this.services.loadAuthentication(accessToken);
        assertNotNull(result);
        assertEquals("cf", result.getOAuth2Request().getClientId());
        assertEquals("marissa", result.getUserAuthentication().getName());
        assertEquals("1adc931e-d65f-4357-b90d-dd4131b8749a",
                ((RemoteUserAuthentication) result.getUserAuthentication()).getId());
        assertNotNull(result.getOAuth2Request().getRequestParameters());
        assertNull(result.getOAuth2Request().getRequestParameters().get(Claims.ISS));
    }

    /**
     * Tests that an token from the an untrusted issuer id throws an
     * InvalidTokenException.
     */
    public void testLoadAuthenticationWithOtherIssuerId() throws Exception {
        String accessToken =
                mockAccessToken("http://testzone1.localhost:8080/uaa/oauth/token",
                        System.currentTimeMillis() - 240000, 60);
        OAuth2Authentication result = this.services.loadAuthentication(accessToken);
        assertNotNull(result);
        assertEquals("cf", result.getOAuth2Request().getClientId());
        assertEquals("marissa", result.getUserAuthentication().getName());
        assertEquals("1adc931e-d65f-4357-b90d-dd4131b8749a",
                ((RemoteUserAuthentication) result.getUserAuthentication()).getId());
        assertNotNull(result.getOAuth2Request().getRequestParameters());
    }

    /**
     * Tests that an token from the an untrusted issuer id throws an
     * InvalidTokenException.
     */
    @Test(expected = InvalidTokenException.class)
    public void testLoadAuthenticationWithUnstrustedIssuerId() throws Exception {
        String accessToken =
                mockAccessToken("http://testzone1localhost:8080/uaa/oauth/token",
                        System.currentTimeMillis() - 240000, 60);
        this.services.loadAuthentication(accessToken);
    }

    /**
     * Tests that an expired token issues an InvalidTokenException.
     */
    @Test(expected = InvalidTokenException.class)
    public void testLoadAuthenticationWithExpiredToken() throws Exception {
        String accessToken = mockAccessToken(System.currentTimeMillis() - 240000, 60);
        this.services.loadAuthentication(accessToken);
    }

    /**
     * Tests that an token that is valid for future use issues an
     * InvalidTokenException.
     */
    @Test(expected = InvalidTokenException.class)
    public void testLoadAuthenticationWithFutureToken() throws Exception {
        String accessToken = mockAccessToken(System.currentTimeMillis() + 240000, 60);
        this.services.loadAuthentication(accessToken);
    }

    /**
     * Tests that a tampered token issues an InvalidTokenException.
     */
    @Test(expected = InvalidSignatureException.class)
    public void testLoadAuthenticationWithTamperedToken() throws Exception {
        String accessToken = mockAccessToken(60);

        // Start tamper ;)
        String[] jwtParts = accessToken.split("\\.");
        String jwtHeader = jwtParts[0];
        String jwtContent = jwtParts[1];
        String jwtSignature = jwtParts[2];

        ObjectMapper objectMapper = new ObjectMapper();
        TypeReference<Map<String, Object>> valueTypeRef = new TypeReference<Map<String, Object>>() {
        };
        String decodedClaims = new String(Base64.decodeBase64(jwtContent));
        Map<String, Object> claims = objectMapper.readValue(decodedClaims, valueTypeRef);
        claims.put(USER_ID, "admin");
        String encodedClaims = Base64.encodeBase64String(objectMapper.writeValueAsBytes(claims));
        accessToken = jwtHeader + "." + encodedClaims + "." + jwtSignature;

        // We've tampered the token so this should fail.
        this.services.loadAuthentication(accessToken);
    }

    /**
     * This tests that we can extract the issuer from the token claims.
     */
    @Test
    public void testGetIssuerFromClaims() {
        String accessToken = mockAccessToken(60);

        assertEquals(TOKEN_ISSUER_ID, this.services.getIssuerFromClaims(this.services.getTokenClaims(accessToken)));

    }

    /**
     * This tests that we can derive the token_key endpoint from the issuer id.
     * E.g. http://localhost:8080/uaa/oauth/token ->
     * https://localhost:8080/uaa/token_key
     */
    @Test
    public void testGetTokenKeyURL() {
        assertEquals("https://localhost:8080/uaa/token_key", this.services.getTokenKeyURL(TOKEN_ISSUER_ID));

        assertEquals("https://sample.com/token_key", this.services.getTokenKeyURL("https://sample.com/oauth/token"));
    }

}
