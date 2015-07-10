package org.cloudfoundry.identity.uaa.oauth;

import static org.cloudfoundry.identity.uaa.oauth.Claims.EXP;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.core.type.TypeReference;

/**
 * FastRemotetokenServices is a replacement for the original
 * RemoteTokenServices. It is "fast" because it does not make calls to UAA's
 * /check_token endpoint every time it verifies a token. Instead, it uses UAA's
 * token signing key, fetched at startup, to verify the token.
 * 
 */
public class FastRemoteTokenServices implements ResourceServerTokenServices {

    private static final Log LOG = LogFactory.getLog(FastRemoteTokenServices.class);

    private RestOperations restTemplate;

    private boolean storeClaims = false;

    private boolean useHttps = true;

    private int maxAcceptableClockSkewSeconds = 60;

    private String trustedIssuerIdsRegex;

    private Pattern trustedIssuerIdsRegexPattern;

    private Map<String, SignatureVerifier> tokenKeys = new HashMap<String, SignatureVerifier>();

    public FastRemoteTokenServices() {
        this.restTemplate = new RestTemplate();
        ((RestTemplate) this.restTemplate).setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            // Ignore 400
            public void handleError(ClientHttpResponse response) throws IOException {
                if (response.getRawStatusCode() != 400) {
                    super.handleError(response);
                }
            }
        });
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException {

        Map<String, Object> claims = getTokenClaims(accessToken);
        String iss = getIssuerFromClaims(claims);

        verifyIssuer(iss);

        // check if the singerProvider for that issuer has already in the cache
        SignatureVerifier verifier = this.tokenKeys.get(iss);
        if (null == verifier) {
            String tokenKey = getTokenKey(iss);
            verifier = getVerifier(tokenKey);
            this.tokenKeys.put(iss, verifier);
        }

        JwtHelper.decodeAndVerify(accessToken, verifier);
        verifyTimeWindow(claims);

        Assert.state(claims.containsKey("client_id"), "Client id must be present in response from auth server");
        String remoteClientId = (String) claims.get("client_id");

        Set<String> scope = new HashSet<String>();
        if (claims.containsKey("scope")) {
            @SuppressWarnings("unchecked")
            Collection<String> values = (Collection<String>) claims.get("scope");
            scope.addAll(values);
        }

        AuthorizationRequest clientAuthentication = new AuthorizationRequest(remoteClientId, scope);

        if (claims.containsKey("resource_ids") || claims.containsKey("client_authorities")) {
            Set<String> resourceIds = new HashSet<String>();
            if (claims.containsKey("resource_ids")) {
                @SuppressWarnings("unchecked")
                Collection<String> values = (Collection<String>) claims.get("resource_ids");
                resourceIds.addAll(values);
            }

            Set<GrantedAuthority> clientAuthorities = new HashSet<GrantedAuthority>();
            if (claims.containsKey("client_authorities")) {
                @SuppressWarnings("unchecked")
                Collection<String> values = (Collection<String>) claims.get("client_authorities");
                clientAuthorities.addAll(getAuthorities(values));
            }

            BaseClientDetails clientDetails = new BaseClientDetails();
            clientDetails.setClientId(remoteClientId);
            clientDetails.setResourceIds(resourceIds);
            clientDetails.setAuthorities(clientAuthorities);
            clientAuthentication.setResourceIdsAndAuthoritiesFromClientDetails(clientDetails);
        }

        Map<String, String> requestParameters = new HashMap<>();
        if (isStoreClaims()) {
            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                if (entry.getValue() != null && entry.getValue() instanceof String) {
                    requestParameters.put(entry.getKey(), (String) entry.getValue());
                }
            }
        }

        if (claims.containsKey(Claims.ADDITIONAL_AZ_ATTR)) {
            try {
                requestParameters.put(Claims.ADDITIONAL_AZ_ATTR,
                        JsonUtils.writeValueAsString(claims.get(Claims.ADDITIONAL_AZ_ATTR)));
            } catch (JsonUtils.JsonUtilException e) {
                throw new IllegalStateException("Cannot convert access token to JSON", e);
            }
        }
        clientAuthentication.setRequestParameters(Collections.unmodifiableMap(requestParameters));

        Authentication userAuthentication = getUserAuthentication(claims, scope);

        clientAuthentication.setApproved(true);
        return new OAuth2Authentication(clientAuthentication.createOAuth2Request(), userAuthentication);
    }

    private void verifyIssuer(String iss) {

        if (null == this.trustedIssuerIdsRegexPattern) {
            if (null == this.trustedIssuerIdsRegex) {
                throw new IllegalStateException("The trustedIssuerIdsFilter property is null. "
                        + "You must set this property as a regular expression of issuer ids that you trust.");
            }
            this.trustedIssuerIdsRegexPattern = Pattern.compile(this.trustedIssuerIdsRegex);
        }

        Matcher matcher = this.trustedIssuerIdsRegexPattern.matcher(iss);
        if (!matcher.matches()) {
            throw new InvalidTokenException("The issuer '" + iss + "' is not trusted "
                    + "because it does not match the regex '"+ this.trustedIssuerIdsRegex +"'.");
        }
    }

    private void verifyTimeWindow(Map<String, Object> claims) {

        Date iatDate = getIatDate(claims);
        Date expDate = getExpDate(claims);

        Date currentDate = new Date();
        if (iatDate != null && iatDate.after(currentDate)) {
            throw new InvalidTokenException("Token validity window is in the future.");
        }

        if (expDate != null && expDate.before(currentDate)) {
            throw new InvalidTokenException("Token is expired");
        }
    }

    protected Date getIatDate(Map<String, Object> claims) {
        Integer iat = (Integer) claims.get("iat");
        return new Date((iat.longValue() - this.maxAcceptableClockSkewSeconds) * 1000l);
    }

    protected Date getExpDate(Map<String, Object> claims) {
        Integer exp = (Integer) claims.get(EXP);
        return new Date((exp.longValue() + this.maxAcceptableClockSkewSeconds) * 1000l);
    }

    protected String getTokenKey(String issuer) {

        String tokenKeyUrl = getTokenKeyURL(issuer);
        ParameterizedTypeReference<Map<String, Object>> typeRef =
                new ParameterizedTypeReference<Map<String, Object>>() {
                };
        Map<String, Object> responseMap =
                this.restTemplate.exchange(tokenKeyUrl, HttpMethod.GET, null, typeRef).getBody();

        String tokenKey = responseMap.get("value").toString();

        if (LOG.isDebugEnabled()) {
            LOG.debug("The downloaded token key from '" + tokenKeyUrl + "' is: '" + tokenKey + "'");
        }

        return tokenKey;

    }

    protected String getTokenKeyURL(String issuer) {
        if (issuer == null) {
            return null;
        }

        String regexPattern = "^(http.*)/oauth/token$";
        Pattern pattern = Pattern.compile(regexPattern);
        Matcher matcher = pattern.matcher(issuer);
        if (!matcher.matches()) {
            throw new IllegalStateException("FastRemoteTokenService cannot process token with issuer id '" + issuer
                    + "' because it does not match the regular expression '" + regexPattern + "'.");
        }
        String issuerPart = matcher.group(1);

        String scheme = "https";
        if (!this.useHttps) {
            scheme = "http";
        }
        return UriComponentsBuilder.fromUriString(issuerPart).scheme(scheme).pathSegment("token_key").build()
                .toUriString();
    }

    protected Set<GrantedAuthority> getAuthorities(Collection<String> authorities) {
        Set<GrantedAuthority> result = new HashSet<GrantedAuthority>();
        for (String authority : authorities) {
            result.add(new SimpleGrantedAuthority(authority));
        }
        return result;
    }

    protected Authentication getUserAuthentication(Map<String, Object> map, Set<String> scope) {
        String username = (String) map.get("user_name");
        if (null == username) {
            String client_id = (String) map.get("client_id");

            if (null == client_id) {
                return null;
            }

            Set<GrantedAuthority> clientAuthorities = new HashSet<GrantedAuthority>();
            clientAuthorities.addAll(getAuthorities(scope));
            clientAuthorities.add(new SimpleGrantedAuthority("isOAuth2Client"));
            return new RemoteUserAuthentication(client_id, client_id, null, clientAuthorities);
        }
        Set<GrantedAuthority> userAuthorities = new HashSet<GrantedAuthority>();
        if (map.containsKey("user_authorities")) {
            @SuppressWarnings("unchecked")
            Collection<String> values = (Collection<String>) map.get("user_authorities");
            userAuthorities.addAll(getAuthorities(values));
        } else {
            // User authorities had better not be empty or we might mistake user
            // for unauthenticated
            userAuthorities.addAll(getAuthorities(scope));
        }
        String email = (String) map.get("email");
        String id = (String) map.get("user_id");
        return new RemoteUserAuthentication(id, username, email, userAuthorities);
    }

    protected String getAuthorizationHeader(String clientId, String clientSecret) {
        String creds = String.format("%s:%s", clientId, clientSecret);
        try {
            return "Basic " + new String(Base64.encode(creds.getBytes("UTF-8")));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Could not convert String");
        }
    }

    protected Map<String, Object> getTokenClaims(String accessToken) {
        if (StringUtils.isEmpty(accessToken)) {
            return null;
        }

        Jwt token = JwtHelper.decode(accessToken);
        Map<String, Object> claims = JsonUtils.readValue(token.getClaims(), new TypeReference<Map<String, Object>>() {
        });
        return claims;
    }

    protected String getIssuerFromClaims(Map<String, Object> claims) {

        return claims.get(Claims.ISS).toString();
    }

    private static SignatureVerifier getVerifier(String signingKey) {
        if (isAssymetricKey(signingKey)) {
            return new RsaVerifier(signingKey);
        }

        throw new IllegalArgumentException(
                "Unsupported key detected. FastRemoteTokenService only supports RSA public keys for token verification.");
    }

    /**
     * @return true if the key has a public verifier
     */
    private static boolean isAssymetricKey(String key) {
        return key.startsWith("-----BEGIN PUBLIC KEY-----");
    }

    @Override
    public OAuth2AccessToken readAccessToken(String accessToken) {
        throw new UnsupportedOperationException("Not supported: read access token");
    }

    public void setRestTemplate(RestOperations restTemplate) {
        this.restTemplate = restTemplate;
    }

    public boolean isStoreClaims() {
        return this.storeClaims;
    }

    public void setStoreClaims(boolean storeClaims) {
        this.storeClaims = storeClaims;
    }

    public void setUseHttps(boolean useHttps) {
        this.useHttps = useHttps;
    }

    public void setMaxAcceptableClockSkewSeconds(int maxAcceptableClockSkewSeconds) {
        this.maxAcceptableClockSkewSeconds = maxAcceptableClockSkewSeconds;
    }

    public void setTrustedIssuerIdsRegex(String trustedIssuerIdsRegex) {
        this.trustedIssuerIdsRegex = trustedIssuerIdsRegex;
    }
}
