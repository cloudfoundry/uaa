package org.cloudfoundry.identity.uaa.integration.util;

import com.dumbster.smtp.SimpleSmtpServer;
import com.dumbster.smtp.SmtpMessage;
import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.io.FileUtils;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.assertj.core.api.Assertions;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.account.UserAccountStatus;
import org.cloudfoundry.identity.uaa.account.UserInfoResponse;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.feature.TestClient;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2RestTemplate;
import org.cloudfoundry.identity.uaa.oauth.client.http.OAuth2ErrorHandler;
import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.AuthenticationScheme;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.PhoneNumber;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Description;
import org.hamcrest.Matchers;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.io.File;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.util.stream.Collectors.joining;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;
import static org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils.createRequestFactory;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.util.StringUtils.hasText;

public class IntegrationTestUtils {

    public static final String SIMPLESAMLPHP_UAA_ACCEPTANCE = "http://simplesamlphp.uaa-acceptance.cf-app.com";
    public static final String SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR =
            "//h1[contains(text(), 'Enter your username and password')]";
    public static final String SAML_AUTH_SOURCE = "example-userpass";

    public static final String EXAMPLE_DOT_COM_SAML_IDP_METADATA = """
            <?xml version="1.0"?>
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="http://example.com/saml2/idp/metadata.php" ID="_7a1d882b1a0cb702f97968d831d70eecce036d6d0c249ae65cca0e91f5656d58"><ds:Signature>
              <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
              <ds:Reference URI="#_7a1d882b1a0cb702f97968d831d70eecce036d6d0c249ae65cca0e91f5656d58"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>HOSWDJYkLvErI1gVynUVmufFVDCKPqExLnnnMjXgoJQ=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>ryMe0PXC+vR/c0nSEhSJsTaF0lHiuZ6PguqCbul7RC9WKLmFS9DD7Dgp3WHQ2zWpRimCTHxw/VO9hyCTxAcW9zxW4OdpD4YorqcmXtLkpasBCVuFLbQ8oylnjrem4kpGflfnuk3bW1mp6AXy52jwALDm8MsTwLK+O74YkeVTPP5bki/PK0N4jHnhYhvhHKUyT8Gug0v2o4KA/1ik83e9vcYEFc/9WGpXFeDMF6pXsJQqC/+eWoLfZJDNrwSsSlg+oD+ZF91YccN9i9lJoaIPcVvPWDfEv7vL79LgnmPBeYxm/fWb4/ANMxvCLIP1R3Ixrz5oFoIX2NP1+uZOpoRWbg==</ds:SignatureValue>
            <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
              <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <ds:X509Data>
                      <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>
                    </ds:X509Data>
                  </ds:KeyInfo>
                </md:KeyDescriptor>
                <md:KeyDescriptor use="encryption">
                  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <ds:X509Data>
                      <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>
                    </ds:X509Data>
                  </ds:KeyInfo>
                </md:KeyDescriptor>
                <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://example.com/saml2/idp/SingleLogoutService.php"/>
                <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
                <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://example.com/saml2/idp/SSOService.php"/>
              </md:IDPSSODescriptor>
              <md:ContactPerson contactType="technical">
                <md:GivenName>Filip</md:GivenName>
                <md:SurName>Hanik</md:SurName>
                <md:EmailAddress>fhanik@pivotal.io</md:EmailAddress>
              </md:ContactPerson>
            </md:EntityDescriptor>
            """;

    public static final String OIDC_ACCEPTANCE_URL = "https://oidc10.uaa-acceptance.cf-app.com/";
    private static final Base64.Encoder BASE_64_ENCODER = Base64.getEncoder();


    private static final DefaultResponseErrorHandler fiveHundredErrorHandler = new DefaultResponseErrorHandler() {
        @Override
        protected boolean hasError(HttpStatus statusCode) {
            return statusCode.is5xxServerError();
        }
    };

    public static void updateUserToForcePasswordChange(RestTemplate restTemplate, String baseUrl, String adminToken, String userId) {
        updateUserToForcePasswordChange(restTemplate, baseUrl, adminToken, userId, null);
    }

    public static void updateUserToForcePasswordChange(RestTemplate restTemplate, String baseUrl, String adminToken, String userId, String zoneId) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + adminToken);
        if (StringUtils.hasText(zoneId)) {
            headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        UserAccountStatus userAccountStatus = new UserAccountStatus();
        userAccountStatus.setPasswordChangeRequired(true);
        final ResponseEntity<UserAccountStatus> response = restTemplate.exchange(baseUrl + "/Users/{user-id}/status", HttpMethod.PATCH, new HttpEntity<>(userAccountStatus, headers), UserAccountStatus.class, userId);
        assertStatusCode(response, HttpStatus.OK);
    }

    public static ScimUser createUnapprovedUser(ServerRunning serverRunning) {
        String userName = "bob-" + new RandomValueStringGenerator().generate();
        String userEmail = userName + "@example.com";

        RestOperations restTemplate = serverRunning.getRestTemplate();

        ScimUser user = new ScimUser();
        user.setUserName(userName);
        user.setPassword("s3Cretsecret");
        user.addEmail(userEmail);
        user.setActive(true);
        user.setVerified(true);

        ResponseEntity<ScimUser> result = restTemplate.postForEntity(serverRunning.getUrl("/Users"), user, ScimUser.class);
        Assertions.assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        return user;
    }

    public static boolean isMember(String userId, ScimGroup group) {
        for (ScimGroupMember<?> member : group.getMembers()) {
            if (userId.equals(member.getMemberId())) {
                return true;
            }
        }
        return false;
    }

    public static UserInfoResponse getUserInfo(String url, String token) throws URISyntaxException {
        RestTemplate rest = new RestTemplate(createRequestFactory(true, 60_000));
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add(AUTHORIZATION, "Bearer " + token);
        headers.add(ACCEPT, APPLICATION_JSON_VALUE);
        RequestEntity<Void> request = new RequestEntity<>(headers, HttpMethod.GET, new URI(url + "/userinfo"));
        final ResponseEntity<UserInfoResponse> response = rest.exchange(request, UserInfoResponse.class);
        assertStatusCode(response, HttpStatus.OK);
        final UserInfoResponse responseBody = response.getBody();
        assertNotNull(responseBody);
        return responseBody;
    }

    public static void deleteZone(String baseUrl, String id, String adminToken) throws URISyntaxException {
        RestTemplate rest = new RestTemplate(createRequestFactory(true, 60_000));
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add(AUTHORIZATION, "Bearer " + adminToken);
        headers.add(ACCEPT, APPLICATION_JSON_VALUE);
        RequestEntity<Void> request = new RequestEntity<>(headers, HttpMethod.DELETE, new URI(baseUrl + "/identity-zones/" + id));
        final ResponseEntity<Void> response = rest.exchange(request, Void.class);
        assertStatusCode(response, HttpStatus.OK);
    }

    public static boolean zoneExists(final String baseUrl, final String id, final String adminToken) throws URISyntaxException {
        final RestTemplate restTemplate = new RestTemplate(createRequestFactory(true, 60_000));

        final MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add(AUTHORIZATION, "Bearer " + adminToken);
        headers.add(ACCEPT, APPLICATION_JSON_VALUE);

        final RequestEntity<Map<Object, Object>> request = new RequestEntity<>(
                headers,
                HttpMethod.GET,
                new URI(baseUrl + "/identity-zones/" + id)
        );
        try {
            restTemplate.exchange(request, Map.class);
        } catch (final RestClientException e) {
            if (e instanceof HttpClientErrorException.NotFound) {
                return false;
            }
            throw new RuntimeException(e);
        }
        return true;
    }

    public static boolean doesSupportZoneDNS() {
        try {
            return Arrays.equals(Inet4Address.getByName("testzone1.localhost").getAddress(), new byte[]{127, 0, 0, 1}) &&
                    Arrays.equals(Inet4Address.getByName("testzone2.localhost").getAddress(), new byte[]{127, 0, 0, 1}) &&
                    Arrays.equals(Inet4Address.getByName("testzone3.localhost").getAddress(), new byte[]{127, 0, 0, 1}) &&
                    Arrays.equals(Inet4Address.getByName("testzone4.localhost").getAddress(), new byte[]{127, 0, 0, 1}) &&
                    Arrays.equals(Inet4Address.getByName("testzonedoesnotexist.localhost").getAddress(), new byte[]{127, 0, 0, 1}) &&
                    Arrays.equals(Inet4Address.getByName("testzoneinactive.localhost").getAddress(), new byte[]{127, 0, 0, 1});
        } catch (UnknownHostException e) {
            return false;
        }
    }

    public static ClientCredentialsResourceDetails getClientCredentialsResource(String url,
                                                                                String[] scope,
                                                                                String clientId,
                                                                                String clientSecret) {
        ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();
        resource.setClientId(clientId);
        resource.setClientSecret(clientSecret);
        resource.setId(clientId);
        if (scope != null) {
            resource.setScope(Arrays.asList(scope));
        }
        resource.setClientAuthenticationScheme(AuthenticationScheme.header);
        resource.setAccessTokenUri(url + "/oauth/token");
        return resource;
    }

    public static RestTemplate getClientCredentialsTemplate(ClientCredentialsResourceDetails details) {
        RestTemplate client = new OAuth2RestTemplate(details);
        client.setRequestFactory(new StatelessRequestFactory());
        client.setErrorHandler(new OAuth2ErrorHandler(details) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
            }
        });
        return client;
    }

    public static ScimUser createUser(RestTemplate client,
                                      String url,
                                      String username,
                                      String firstName,
                                      String lastName,
                                      String email,
                                      boolean verified) {
        return createUserWithPhone(client, url, username, firstName, lastName, email, verified, null);
    }

    public static ScimUser createUserWithPhone(RestTemplate client,
                                               String url,
                                               String username,
                                               String firstName,
                                               String lastName,
                                               String email,
                                               boolean verified,
                                               String phoneNumber) {
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);
        user.setVerified(verified);
        user.setActive(true);
        user.setPassword("secr3T");
        user.setPhoneNumbers(Collections.singletonList(new PhoneNumber(phoneNumber)));
        final ResponseEntity<ScimUser> response = client.postForEntity(url + "/Users", user, ScimUser.class);
        assertStatusCode(response, HttpStatus.CREATED);
        final ScimUser responseBody = response.getBody();
        assertNotNull(responseBody);
        return responseBody;
    }

    public static ScimUser createUser(String token, String url, ScimUser user, String zoneSwitchId) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        headers.add("If-Match", String.valueOf(user.getVersion()));
        if (hasText(zoneSwitchId)) {
            headers.add(IdentityZoneSwitchingFilter.HEADER, zoneSwitchId);
        }
        HttpEntity<ScimUser> getHeaders = new HttpEntity<>(user, headers);
        ResponseEntity<ScimUser> userInfoGet = template.exchange(
                url + "/Users",
                HttpMethod.POST,
                getHeaders,
                ScimUser.class
        );
        if (userInfoGet.getStatusCode() == HttpStatus.CREATED) {
            return userInfoGet.getBody();
        }
        throw new RuntimeException("Invalid return code:" + userInfoGet.getStatusCode());
    }

    public static void updateUser(String token, String url, ScimUser user) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        headers.add("If-Match", String.valueOf(user.getVersion()));
        HttpEntity<ScimUser> getHeaders = new HttpEntity<>(user, headers);
        ResponseEntity<ScimUser> userInfoGet = template.exchange(
                url + "/Users/" + user.getId(),
                HttpMethod.PUT,
                getHeaders,
                ScimUser.class
        );
        if (userInfoGet.getStatusCode() == HttpStatus.OK) {
            userInfoGet.getBody();
            return;
        }
        throw new RuntimeException("Invalid return code:" + userInfoGet.getStatusCode());
    }

    public static ScimUser getUser(String token, String url, String origin, String username) {
        String userId = getUserId(token, url, origin, username);
        return getUser(token, url, userId);
    }

    public static ScimUser getUserByZone(String token, String url, String subdomain, String username) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        headers.add("X-Identity-Zone-Subdomain", subdomain);
        HttpEntity getHeaders = new HttpEntity<>(headers);
        ResponseEntity<String> userInfoGet = template.exchange(
                url + "/Users"
                        + "?filter=userName eq \"" + username + "\"",
                HttpMethod.GET,
                getHeaders,
                String.class
        );
        ScimUser user = null;
        if (userInfoGet.getStatusCode() == HttpStatus.OK) {

            SearchResults<ScimUser> results = JsonUtils.readValue(userInfoGet.getBody(), SearchResults.class);
            assertNotNull(results);
            List<ScimUser> resources = results.getResources();
            if (resources.isEmpty()) {
                return null;
            }
            user = JsonUtils.readValue(JsonUtils.writeValueAsString(resources.get(0)), ScimUser.class);
        }
        return user;
    }

    public static ScimUser getUser(String token, String url, String userId) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        HttpEntity getHeaders = new HttpEntity<>(headers);
        ResponseEntity<ScimUser> userInfoGet = template.exchange(
                url + "/Users/" + userId,
                HttpMethod.GET,
                getHeaders,
                ScimUser.class
        );
        if (userInfoGet.getStatusCode() == HttpStatus.OK) {
            return userInfoGet.getBody();
        }
        throw new RuntimeException("Invalid return code:" + userInfoGet.getStatusCode());
    }

    public static String getUserId(String token, String url, String origin, String username) {
        return getUserIdByField(token, url, origin, "userName", username);
    }

    public static String getUserIdByField(String token, String url, String origin, String field, String fieldValue) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        HttpEntity getHeaders = new HttpEntity<>(headers);
        ResponseEntity<String> userInfoGet = template.exchange(
                url + "/Users"
                        + "?attributes=id"
                        + "&filter=" + field + " eq \"" + fieldValue + "\" and origin eq \"" + origin + "\"",
                HttpMethod.GET,
                getHeaders,
                String.class
        );
        if (userInfoGet.getStatusCode() == HttpStatus.OK) {

            HashMap results = JsonUtils.readValue(userInfoGet.getBody(), HashMap.class);
            assertNotNull(results);
            List resources = (List) results.get("resources");
            if (resources.isEmpty()) {
                return null;
            }
            HashMap resource = (HashMap) resources.get(0);
            return (String) resource.get("id");
        }
        throw new RuntimeException("Invalid return code:" + userInfoGet.getStatusCode());
    }

    public static String getUsernameById(String token, String url, String userId) {
        return getUser(token, url, userId).getUserName();
    }

    public static void deleteUser(String zoneAdminToken, String url, String userId) {

        RestTemplate template = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        HttpEntity deleteHeaders = new HttpEntity<>(headers);
        ResponseEntity<String> userDelete = template.exchange(
                url + "/Users/" + userId,
                HttpMethod.DELETE,
                deleteHeaders,
                String.class
        );
        if (userDelete.getStatusCode() != HttpStatus.OK) {
            throw new RuntimeException("Invalid return code:" + userDelete.getStatusCode());
        }
    }

    @SuppressWarnings("rawtypes")
    private static Map findAllGroups(RestTemplate client,
                                     String url) {
        ResponseEntity<Map> response = client.getForEntity(url + "/Groups", Map.class);

        @SuppressWarnings("rawtypes")
        Map results = response.getBody();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue("There should be more than zero groups", (Integer) results.get("totalResults") > 0);
        return results;
    }

    public static String findGroupId(RestTemplate client,
                                     String url,
                                     String groupName) {
        Map map = findAllGroups(client, url);
        for (Map group : (List<Map>) map.get("resources")) {
            assertTrue(group.containsKey("displayName"));
            assertTrue(group.containsKey("id"));
            if (groupName.equals(group.get("displayName"))) {
                return (String) group.get("id");
            }
        }
        return null;
    }

    public static ScimGroup ensureGroupExists(
            final String token,
            final String zoneId,
            final String url,
            final String displayName
    ) {
        final ScimGroup existingGroup = getGroup(token, zoneId, url, displayName);
        if (existingGroup != null) {
            return existingGroup;
        }
        final ScimGroup group = new ScimGroup(null, displayName, zoneId);
        return createGroup(token, zoneId, url, group);
    }

    /**
     * @return the group or {@code null} if it does not exist
     */
    public static ScimGroup getGroup(String token,
                                     String zoneId,
                                     String url,
                                     String displayName) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        if (hasText(zoneId)) {
            headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        ResponseEntity<SearchResults<ScimGroup>> findGroup = template.exchange(
                url + "/Groups?filter=displayName eq \"{groupId}\"",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                new ParameterizedTypeReference<>() {
                },
                displayName
        );
        assertStatusCode(findGroup, HttpStatus.OK);
        if (findGroup.getBody().getTotalResults() == 0) {
            return null;
        } else {
            return findGroup.getBody().getResources().iterator().next();
        }
    }

    public static ScimGroup createGroup(
            final String token,
            final String zoneId,
            final String url,
            final ScimGroup group
    ) {
        final RestTemplate template = new RestTemplate();
        template.setErrorHandler(fiveHundredErrorHandler);
        final MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        if (hasText(zoneId)) {
            headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        final ResponseEntity<ScimGroup> response = template.exchange(
                url + "/Groups",
                HttpMethod.POST,
                new HttpEntity<>(JsonUtils.writeValueAsBytes(group), headers),
                ScimGroup.class
        );
        assertStatusCode(response, HttpStatus.CREATED);
        final ScimGroup responseBody = response.getBody();
        assertNotNull(responseBody);
        return responseBody;
    }

    private static ScimGroup updateGroup(String token,
                                         String zoneId,
                                         String url,
                                         ScimGroup group) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("If-Match", "*");
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        if (hasText(zoneId)) {
            headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        ResponseEntity<ScimGroup> updateGroup = template.exchange(
                url + "/Groups/{groupId}",
                HttpMethod.PUT,
                new HttpEntity<>(JsonUtils.writeValueAsBytes(group), headers),
                ScimGroup.class,
                group.getId()
        );
        assertEquals(HttpStatus.OK, updateGroup.getStatusCode());
        return updateGroup.getBody();
    }

    public static ScimGroup createOrUpdateGroup(String token,
                                                String zoneId,
                                                String url,
                                                ScimGroup scimGroup) {

        ScimGroup existing = getGroup(token, zoneId, url, scimGroup.getDisplayName());
        if (existing == null) {
            return createGroup(token, zoneId, url, scimGroup);
        } else {
            scimGroup.setId(existing.getId());
            return updateGroup(token, zoneId, url, scimGroup);
        }

    }

    public static ScimGroupExternalMember mapExternalGroup(String token,
                                                           String zoneId,
                                                           String url,
                                                           ScimGroupExternalMember scimGroup) {

        RestTemplate template = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        if (hasText(zoneId)) {
            headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        ResponseEntity<ScimGroupExternalMember> mapGroup = template.exchange(
                url + "/Groups/External",
                HttpMethod.POST,
                new HttpEntity<>(JsonUtils.writeValueAsBytes(scimGroup), headers),
                ScimGroupExternalMember.class
        );
        if (HttpStatus.CREATED.equals(mapGroup.getStatusCode())) {
            return mapGroup.getBody();
        } else if (HttpStatus.CONFLICT.equals(mapGroup.getStatusCode())) {
            return scimGroup;
        }
        throw new IllegalArgumentException("Invalid status code:" + mapGroup.getStatusCode());
    }

    public static void deleteGroup(String token,
                                   String zoneId,
                                   String url,
                                   String groupId
    ) {
        RestTemplate template = new RestTemplate();
        template.setErrorHandler(fiveHundredErrorHandler);
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Authorization", "bearer " + token);
        if (hasText(zoneId)) {
            headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }

        final ResponseEntity<ScimGroup> response = template.exchange(url + "/Groups/{groupId}", HttpMethod.DELETE,
                new HttpEntity<>(headers), ScimGroup.class, groupId);
        assertStatusCode(response, HttpStatus.OK);
    }

    private static IdentityZone createZoneOrUpdateSubdomain(RestTemplate client,
                                                            String url,
                                                            String id,
                                                            String subdomain,
                                                            IdentityZoneConfiguration config,
                                                            boolean active) {

        ResponseEntity<String> zoneGet = client.getForEntity(url + "/identity-zones/{id}", String.class, id);

        if (zoneGet.getStatusCode() == HttpStatus.OK) {
            IdentityZone existing = JsonUtils.readValue(zoneGet.getBody(), IdentityZone.class);
            assertNotNull(existing);
            existing.setSubdomain(subdomain);
            existing.setConfig(config);
            existing.setActive(active);
            HttpEntity<IdentityZone> updateZoneRequest = new HttpEntity<>(existing);
            ResponseEntity<String> getUpdatedZone = client.exchange(url + "/identity-zones/{id}", HttpMethod.PUT, updateZoneRequest, String.class, id);
            return JsonUtils.readValue(getUpdatedZone.getBody(), IdentityZone.class);
        }

        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(subdomain);
        identityZone.setName("The Twiglet Zone[" + id + "]");
        identityZone.setDescription("Like the Twilight Zone but tastier[" + id + "].");
        identityZone.setConfig(config);
        identityZone.setActive(active);
        ResponseEntity<IdentityZone> zone = client.postForEntity(url + "/identity-zones", identityZone, IdentityZone.class);
        assertStatusCode(zone, HttpStatus.CREATED);
        final IdentityZone responseBody = zone.getBody();
        assertNotNull(responseBody);
        return responseBody;
    }

    public static IdentityZone createInactiveIdentityZone(RestTemplate client, String url) {
        createZoneOrUpdateSubdomain(client, url, "testzoneinactive", "testzoneinactive", new IdentityZoneConfiguration(), false);
        ResponseEntity<IdentityZone> zoneGet = client.getForEntity(url + "/identity-zones/{id}", IdentityZone.class, "testzoneinactive");
        if (zoneGet.getStatusCode() != HttpStatus.OK) {
            throw new RuntimeException("Could not create inactive zone.");
        }
        return zoneGet.getBody();
    }

    public static IdentityZone createZoneOrUpdateSubdomain(RestTemplate client,
                                                           String url,
                                                           String id,
                                                           String subdomain,
                                                           IdentityZoneConfiguration config) {
        return createZoneOrUpdateSubdomain(client, url, id, subdomain, config, true);
    }

    public static void addMemberToGroup(RestTemplate client,
                                        String url,
                                        String userId,
                                        String groupId
    ) {
        ScimGroupMember groupMember = new ScimGroupMember(userId);
        ResponseEntity<String> response = client.postForEntity(url + "/Groups/{groupId}/members", groupMember, String.class, groupId);
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
    }

    public static UaaClientDetails getClient(String token,
                                             String url,
                                             String clientId) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);

        HttpEntity getHeaders = new HttpEntity<>(null, headers);

        ResponseEntity<UaaClientDetails> response = template.exchange(
                url + "/oauth/clients/" + clientId,
                HttpMethod.GET,
                getHeaders,
                UaaClientDetails.class
        );
        assertStatusCode(response, HttpStatus.OK);

        return response.getBody();
    }

    private static void assertStatusCode(final ResponseEntity<?> response, final HttpStatus... expectedStatusCodes) {
        final boolean matchesAnyExpectedStatusCode = Stream.of(expectedStatusCodes)
                .anyMatch(it -> it.equals(response.getStatusCode()));
        if (!matchesAnyExpectedStatusCode) {
            final String expectedStatusCodesString = Arrays.stream(expectedStatusCodes)
                    .map(HttpStatus::value)
                    .map(Object::toString)
                    .collect(joining(" or "));
            throw new RuntimeException(
                    "Invalid return code: expected %s, got %d".formatted(expectedStatusCodesString,
                            response.getStatusCode().value())
            );
        }
    }

    public static UaaClientDetails createClientAsZoneAdmin(String zoneAdminToken,
                                                           String url,
                                                           String zoneId,
                                                           UaaClientDetails client) {

        RestTemplate template = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        HttpEntity getHeaders = new HttpEntity<>(JsonUtils.writeValueAsBytes(client), headers);
        ResponseEntity<String> clientCreate = template.exchange(
                url + "/oauth/clients",
                HttpMethod.POST,
                getHeaders,
                String.class
        );
        if (clientCreate.getStatusCode() == HttpStatus.CREATED) {
            return JsonUtils.readValue(clientCreate.getBody(), UaaClientDetails.class);
        }
        throw new RuntimeException("Invalid return code:" + clientCreate.getStatusCode());
    }

    public static UaaClientDetails createClient(String adminToken,
                                                String url,
                                                UaaClientDetails client) {
        return createOrUpdateClient(adminToken, url, null, client);
    }

    public static UaaClientDetails createOrUpdateClient(String adminToken,
                                                        String url,
                                                        String switchToZoneId,
                                                        UaaClientDetails client) {

        RestTemplate template = new RestTemplate();
        template.setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            protected boolean hasError(HttpStatus statusCode) {
                return statusCode.is5xxServerError();
            }
        });
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + adminToken);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        if (hasText(switchToZoneId)) {
            headers.add(IdentityZoneSwitchingFilter.HEADER, switchToZoneId);
        }
        HttpEntity getHeaders = new HttpEntity<>(JsonUtils.writeValueAsBytes(client), headers);
        ResponseEntity<String> clientCreate = template.exchange(
                url + "/oauth/clients",
                HttpMethod.POST,
                getHeaders,
                String.class
        );
        if (clientCreate.getStatusCode() == HttpStatus.CREATED) {
            return JsonUtils.readValue(clientCreate.getBody(), UaaClientDetails.class);
        } else if (clientCreate.getStatusCode() == HttpStatus.CONFLICT) {
            HttpEntity putHeaders = new HttpEntity<>(JsonUtils.writeValueAsBytes(client), headers);
            ResponseEntity<String> clientUpdate = template.exchange(
                    url + "/oauth/clients/" + client.getClientId(),
                    HttpMethod.PUT,
                    putHeaders,
                    String.class
            );
            if (clientUpdate.getStatusCode() == HttpStatus.OK) {
                return JsonUtils.readValue(clientCreate.getBody(), UaaClientDetails.class);
            } else {
                throw new RuntimeException("Invalid update return code:" + clientUpdate.getStatusCode());
            }
        }
        throw new RuntimeException("Invalid create return code:" + clientCreate.getStatusCode());
    }

    public static void updateClient(String url,
                                    String token,
                                    UaaClientDetails client) {

        RestTemplate template = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);

        HttpEntity getHeaders = new HttpEntity<>(client, headers);

        ResponseEntity<UaaClientDetails> response = template.exchange(
                url + "/oauth/clients/" + client.getClientId(),
                HttpMethod.PUT,
                getHeaders,
                UaaClientDetails.class
        );
        assertStatusCode(response, HttpStatus.OK);
        assertNotNull(response.getBody());
    }

    public static IdentityProvider<? extends AbstractIdentityProviderDefinition> getProvider(String zoneAdminToken,
                                                                                             String url,
                                                                                             String zoneId,
                                                                                             String originKey) {
        List<IdentityProvider<? extends AbstractIdentityProviderDefinition>> providers = getProviders(zoneAdminToken, url, zoneId);
        if (providers != null) {
            for (IdentityProvider<? extends AbstractIdentityProviderDefinition> p : providers) {
                if (zoneId.equals(p.getIdentityZoneId()) && originKey.equals(p.getOriginKey())) {
                    return p;
                }
            }
        }
        return null;
    }

    /**
     * @return the list of identity providers or {@code null} if the request was not successful
     */
    private static List<IdentityProvider<? extends AbstractIdentityProviderDefinition>> getProviders(String zoneAdminToken,
                                                                                                     String url,
                                                                                                     String zoneId) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        HttpEntity getHeaders = new HttpEntity<>(headers);
        ResponseEntity<String> providerGet = client.exchange(
                url + "/identity-providers",
                HttpMethod.GET,
                getHeaders,
                String.class
        );
        if (providerGet != null && providerGet.getStatusCode() == HttpStatus.OK) {
            return JsonUtils.readValue(providerGet.getBody(), new TypeReference<List<IdentityProvider<? extends AbstractIdentityProviderDefinition>>>() {
            });
        }
        return null;
    }

    public static void deleteProvider(String zoneAdminToken,
                                      String url,
                                      String zoneId,
                                      String originKey) {
        IdentityProvider<? extends AbstractIdentityProviderDefinition> provider = getProvider(zoneAdminToken, url, zoneId, originKey);
        if (provider == null) {
            return;
        }
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        HttpEntity<?> getHeaders = new HttpEntity<>(headers);
        final ResponseEntity<String> response = client.exchange(
                url + "/identity-providers/" + provider.getId(),
                HttpMethod.DELETE,
                getHeaders,
                String.class
        );
        assertStatusCode(response, HttpStatus.OK);
    }

    /**
     * @param originKey            The unique identifier used to reference the identity provider in UAA.
     * @param addShadowUserOnLogin Specifies whether UAA should automatically create shadow users upon successful SAML authentication.
     * @return An object representation of an identity provider.
     * @throws Exception on error
     */
    public static IdentityProvider<SamlIdentityProviderDefinition> createIdentityProvider(String originKey, boolean addShadowUserOnLogin, String baseUrl, ServerRunning serverRunning) throws Exception {
        getZoneAdminToken(baseUrl, serverRunning);
        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createSimplePHPSamlIDP(originKey, OriginKeys.UAA);
        return createIdentityProvider("simplesamlphp for uaa", addShadowUserOnLogin, baseUrl, serverRunning, samlIdentityProviderDefinition);
    }

    /**
     * @param addShadowUserOnLogin Specifies whether UAA should automatically create shadow users upon successful SAML authentication.
     * @return An object representation of an identity provider.
     * @throws Exception on error
     */
    public static IdentityProvider<SamlIdentityProviderDefinition> createIdentityProvider(String name, boolean addShadowUserOnLogin, String baseUrl, ServerRunning serverRunning, SamlIdentityProviderDefinition samlIdentityProviderDefinition) throws Exception {
        String zoneAdminToken = getZoneAdminToken(baseUrl, serverRunning);

        samlIdentityProviderDefinition.setAddShadowUserOnLogin(addShadowUserOnLogin);

        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(OriginKeys.UAA);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName(name);

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertNotNull(provider.getId());
        return provider;
    }

    public static void createOidcIdentityProvider(String name, String originKey, String baseUrl) throws Exception {
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider = new IdentityProvider<>();
        identityProvider.setName(name);
        identityProvider.setIdentityZoneId(OriginKeys.UAA);
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
        config.setAuthUrl(new URL(OIDC_ACCEPTANCE_URL + "oauth/authorize"));
        config.setTokenUrl(new URL(OIDC_ACCEPTANCE_URL + "oauth/token"));
        config.setTokenKeyUrl(new URL(OIDC_ACCEPTANCE_URL + "token_key"));
        config.setShowLinkText(true);
        config.setLinkText("My OIDC Provider");
        config.setSkipSslValidation(true);
        config.setRelyingPartyId("identity");
        config.setRelyingPartySecret("identitysecret");
        config.setEmailDomain(Collections.singletonList("test.org"));
        identityProvider.setConfig(config);
        identityProvider.setOriginKey(originKey);
        String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        IntegrationTestUtils.createOrUpdateProvider(clientCredentialsToken, baseUrl, identityProvider);
    }

    public static String getZoneAdminToken(String baseUrl, ServerRunning serverRunning) {
        return getZoneAdminToken(baseUrl, serverRunning, OriginKeys.UAA);
    }

    public static String getZoneAdminToken(String baseUrl, ServerRunning serverRunning, String zoneId) {
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        String email = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email, true);

        String groupName = "zones." + zoneId + ".admin";
        ensureGroupExists(getClientCredentialsToken(baseUrl, "admin", "adminsecret"), "", baseUrl, groupName);
        String groupId = IntegrationTestUtils.findGroupId(adminClient, baseUrl, groupName);
        assertThat("Couldn't find group : " + groupId, groupId, is(CoreMatchers.notNullValue()));
        IntegrationTestUtils.addMemberToGroup(adminClient, baseUrl, user.getId(), groupId);

        return IntegrationTestUtils.getAccessTokenByAuthCode(serverRunning,
                UaaTestAccounts.standard(serverRunning),
                "identity",
                "identitysecret",
                email,
                "secr3T");
    }

    public static ScimUser createRandomUser(String baseUrl) {

        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        String email = new RandomValueStringGenerator().generate() + "@samltesting.org";
        return IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email, true);
    }

    public static void updateIdentityProvider(
            String baseUrl, ServerRunning serverRunning, IdentityProvider<? extends AbstractIdentityProviderDefinition> provider) {
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        String email = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email, true);

        String groupId = IntegrationTestUtils.findGroupId(adminClient, baseUrl, "zones.uaa.admin");
        IntegrationTestUtils.addMemberToGroup(adminClient, baseUrl, user.getId(), groupId);

        String zoneAdminToken =
                IntegrationTestUtils.getAccessTokenByAuthCode(serverRunning,
                        UaaTestAccounts.standard(serverRunning),
                        "identity",
                        "identitysecret",
                        email,
                        "secr3T");

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertNotNull(provider.getId());
    }

    public static SamlIdentityProviderDefinition createSimplePHPSamlIDP(String alias, String zoneId) {
        if (!("simplesamlphp".equals(alias) || "simplesamlphp2".equals(alias))) {
            throw new IllegalArgumentException("Only valid origins are: simplesamlphp,simplesamlphp2");
        }
        String idpMetaData = "simplesamlphp".equals(alias) ?
                SIMPLESAMLPHP_UAA_ACCEPTANCE + "/saml2/idp/metadata.php" :
                EXAMPLE_DOT_COM_SAML_IDP_METADATA;
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setZoneId(zoneId);
        def.setMetaDataLocation(idpMetaData);
        def.setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        def.setAssertionConsumerIndex(0);
        def.setMetadataTrustCheck(false);
        def.setShowSamlLink(true);
        def.setIdpEntityAlias(alias);
        def.setLinkText("Login with Simple SAML PHP(" + alias + ")");
        return def;
    }

    public static <T extends AbstractIdentityProviderDefinition> IdentityProvider<T>
    createOrUpdateProvider(String accessToken,
                           String url,
                           IdentityProvider<T> provider) {

        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + accessToken);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, provider.getIdentityZoneId());
        List<IdentityProvider<? extends AbstractIdentityProviderDefinition>> existing = getProviders(accessToken, url, provider.getIdentityZoneId());
        if (existing != null) {
            for (IdentityProvider<? extends AbstractIdentityProviderDefinition> p : existing) {
                if (p.getOriginKey().equals(provider.getOriginKey()) && p.getIdentityZoneId().equals(provider.getIdentityZoneId())) {
                    provider.setId(p.getId());
                    HttpEntity putHeaders = new HttpEntity<>(provider, headers);
                    ResponseEntity<String> providerPut = client.exchange(
                            url + "/identity-providers/{id}",
                            HttpMethod.PUT,
                            putHeaders,
                            String.class,
                            provider.getId()
                    );
                    if (providerPut.getStatusCode() == HttpStatus.OK) {
                        return JsonUtils.readValue(providerPut.getBody(), IdentityProvider.class);
                    }
                }
            }
        }

        HttpEntity postHeaders = new HttpEntity<>(provider, headers);
        ResponseEntity<String> providerPost = client.exchange(
                url + "/identity-providers/{id}",
                HttpMethod.POST,
                postHeaders,
                String.class,
                provider.getId()
        );
        if (providerPost.getStatusCode() == HttpStatus.CREATED) {
            return JsonUtils.readValue(providerPost.getBody(), IdentityProvider.class);
        }
        throw new IllegalStateException("Invalid result code returned, unable to create identity provider:" + providerPost.getStatusCode());
    }

    public static String getClientCredentialsToken(String baseUrl,
                                                   String clientId,
                                                   String clientSecret) {
        RestTemplate template = new RestTemplate();
        template.setRequestFactory(new StatelessRequestFactory());
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "client_credentials");
        formData.add("client_id", clientId);
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "Basic " + new String(BASE_64_ENCODER.encode("%s:%s".formatted(clientId, clientSecret).getBytes())));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = template.exchange(
                baseUrl + "/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(formData, headers),
                Map.class);

        Assert.assertEquals(HttpStatus.OK, response.getStatusCode());

        final Map responseBody = response.getBody();
        assertNotNull(responseBody);
        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(responseBody);
        return accessToken.getValue();
    }

    public static Map getPasswordToken(String baseUrl,
                                       String clientId,
                                       String clientSecret,
                                       String username,
                                       String password,
                                       String scopes) {
        RestTemplate template = new RestTemplate();
        template.getMessageConverters().add(0, new StringHttpMessageConverter(StandardCharsets.UTF_8));
        template.setRequestFactory(new StatelessRequestFactory());
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "password");
        formData.add("client_id", clientId);
        formData.add("username", username);
        formData.add("password", password);
        formData.add("response_type", "token id_token");
        if (hasText(scopes)) {
            formData.add("scope", scopes);
        }
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "Basic " + new String(BASE_64_ENCODER.encode("%s:%s".formatted(clientId, clientSecret).getBytes())));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = template.exchange(
                baseUrl + "/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(formData, headers),
                Map.class);

        Assert.assertEquals(HttpStatus.OK, response.getStatusCode());
        return response.getBody();
    }

    public static String getClientCredentialsToken(ServerRunning serverRunning,
                                                   String clientId,
                                                   String clientSecret) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "client_credentials");
        formData.add("client_id", clientId);
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.set("Authorization",
                "Basic " + new String(BASE_64_ENCODER.encode("%s:%s".formatted(clientId, clientSecret).getBytes())));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
        Assert.assertEquals(HttpStatus.OK, response.getStatusCode());

        final Map responseBody = response.getBody();
        assertNotNull(responseBody);
        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(responseBody);
        return accessToken.getValue();
    }

    public static String getAccessTokenByAuthCode(ServerRunning serverRunning,
                                                  UaaTestAccounts testAccounts,
                                                  String clientId,
                                                  String clientSecret,
                                                  String username,
                                                  String password) {

        return getAuthorizationCodeTokenMap(serverRunning, testAccounts, clientId, clientSecret, username, password)
                .get("access_token");
    }

    public static Map<String, String> getAuthorizationCodeTokenMap(ServerRunning serverRunning,
                                                                   UaaTestAccounts testAccounts,
                                                                   String clientId,
                                                                   String clientSecret,
                                                                   String username,
                                                                   String password) {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
        resource.setClientId(clientId);
        resource.setClientSecret(clientSecret);

        return getAuthorizationCodeTokenMap(serverRunning,
                testAccounts,
                clientId,
                clientSecret,
                username,
                password,
                null,
                null,
                resource.getPreEstablishedRedirectUri(),
                null,
                true);
    }

    public static HttpHeaders getHeaders(CookieStore cookies) {
        HttpHeaders headers = new HttpHeaders();

        headers.setAccept(Arrays.asList(MediaType.TEXT_HTML, MediaType.ALL));

        for (org.apache.http.cookie.Cookie cookie : cookies.getCookies()) {
            headers.add("Cookie", cookie.getName() + "=" + cookie.getValue());
        }
        return headers;
    }

    public static String getAuthorizationResponse(ServerRunning serverRunning,
                                                  String clientId,
                                                  String username,
                                                  String password,
                                                  String redirectUri,
                                                  String codeChallenge,
                                                  String codeChallengeMethod) throws Exception {
        BasicCookieStore cookies = new BasicCookieStore();
        String mystateid = "mystateid";
        ServerRunning.UriBuilder builder = serverRunning.buildUri("/oauth/authorize")
                .queryParam("response_type", "code")
                .queryParam("state", mystateid)
                .queryParam("client_id", clientId);
        if (hasText(redirectUri)) {
            builder = builder.queryParam("redirect_uri", redirectUri);
        }
        if (hasText(codeChallenge)) {
            builder = builder.queryParam("code_challenge", codeChallenge);
        }
        if (hasText(codeChallengeMethod)) {
            builder = builder.queryParam("code_challenge_method", codeChallengeMethod);
        }
        URI uri = builder.build();
        ResponseEntity<Void> result =
                serverRunning.createRestTemplate().exchange(
                        uri.toString(),
                        HttpMethod.GET,
                        new HttpEntity<>(null, getHeaders(cookies)),
                        Void.class
                );
        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        String location = result.getHeaders().getLocation().toString();
        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String header : result.getHeaders().get("Set-Cookie")) {
                int nameLength = header.indexOf('=');
                cookies.addCookie(new BasicClientCookie(header.substring(0, nameLength), header.substring(nameLength + 1)));
            }
        }
        ResponseEntity<String> response = serverRunning.getForString(location, getHeaders(cookies));
        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength + 1)));
            }
        }
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        assertTrue(response.getBody().contains("/login.do"));
        assertTrue(response.getBody().contains("username"));
        assertTrue(response.getBody().contains("password"));
        String csrf = IntegrationTestUtils.extractCookieCsrf(response.getBody());
        formData.add("username", username);
        formData.add("password", password);
        formData.add(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrf);
        // Should be redirected to the original URL, but now authenticated
        result = serverRunning.postForResponse("/login.do", getHeaders(cookies), formData);
        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        cookies.clear();
        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : result.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength + 1)));
            }
        }
        response = serverRunning.createRestTemplate().exchange(
                result.getHeaders().getLocation().toString(), HttpMethod.GET, new HttpEntity<>(null, getHeaders(cookies)),
                String.class);
        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength + 1)));
            }
        }
        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertTrue(response.getBody().contains("<h1>Application Authorization</h1>"));
            formData.clear();
            formData.add(USER_OAUTH_APPROVAL, "true");
            formData.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));
            result = serverRunning.postForResponse("/oauth/authorize", getHeaders(cookies), formData);
            assertEquals(HttpStatus.FOUND, result.getStatusCode());
            location = result.getHeaders().getLocation().toString();
        } else if (response.getStatusCode() == HttpStatus.BAD_REQUEST) {
            return response.getBody();
        } else {
            // Token cached so no need for second approval
            assertEquals(HttpStatus.FOUND, response.getStatusCode());
            location = response.getHeaders().getLocation().toString();
        }
        return location;
    }

    public static ResponseEntity<Map> getTokens(ServerRunning serverRunning,
                                                UaaTestAccounts testAccounts,
                                                String clientId,
                                                String clientSecret,
                                                String redirectUri,
                                                String codeVerifier,
                                                String authorizationCode) throws Exception {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.clear();
        formData.add("client_id", clientId);
        formData.add("grant_type", GRANT_TYPE_AUTHORIZATION_CODE);
        formData.add("code", authorizationCode);
        if (hasText(redirectUri)) {
            formData.add("redirect_uri", redirectUri);
        }
        if (hasText(codeVerifier)) {
            formData.add("code_verifier", codeVerifier);
        }
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization", UaaTestAccounts.getAuthorizationHeader(clientId, clientSecret));
        return serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
    }

    public static void callCheckToken(ServerRunning serverRunning,
                                      UaaTestAccounts testAccounts,
                                      String accessToken,
                                      String clientId,
                                      String clientSecret) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", UaaTestAccounts.getAuthorizationHeader(clientId, clientSecret));
        formData.add("token", accessToken);
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/check_token", formData, headers);
        assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());
        final Map tokenResponseBody = tokenResponse.getBody();
        assertNotNull(tokenResponseBody);
        assertNotNull(tokenResponseBody.get("iss"));
    }

    public static String getAuthorizationCodeToken(
            ServerRunning serverRunning,
            String clientId,
            String clientAssertion,
            String username,
            String password,
            String tokenResponseType,
            String redirectUri,
            String loginHint,
            boolean callCheckToken) {
        return getAuthorizationCodeTokenMap(serverRunning, UaaTestAccounts.standard(serverRunning), clientId, null, clientAssertion,
                username, password, tokenResponseType, null, redirectUri, loginHint, callCheckToken).get("access_token");
    }

    public static Map<String, String> getAuthorizationCodeTokenMap(
            ServerRunning serverRunning,
            UaaTestAccounts testAccounts,
            String clientId,
            String clientSecret,
            String username,
            String password,
            String tokenResponseType,
            String jSessionId,
            String redirectUri,
            String loginHint,
            boolean callCheckToken) {
        return getAuthorizationCodeTokenMap(serverRunning, testAccounts, clientId, clientSecret, null, username, password,
                tokenResponseType, jSessionId, redirectUri, loginHint, callCheckToken);
    }

    public static Map<String, String> getAuthorizationCodeTokenMap(ServerRunning serverRunning,
                                                                   UaaTestAccounts testAccounts,
                                                                   String clientId,
                                                                   String clientSecret,
                                                                   String clientAssertion,
                                                                   String username,
                                                                   String password,
                                                                   String tokenResponseType,
                                                                   String jSessionId,
                                                                   String redirectUri,
                                                                   String loginHint,
                                                                   boolean callCheckToken) {
        BasicCookieStore cookies = new BasicCookieStore();
        if (hasText(jSessionId)) {
            cookies.addCookie(new BasicClientCookie("JSESSIONID", jSessionId));
        }

        String mystateid = "mystateid";
        ServerRunning.UriBuilder builder = serverRunning.buildUri("/oauth/authorize")
                .queryParam("response_type", "code")
                .queryParam("state", mystateid)
                .queryParam("client_id", clientId);
        if (hasText(redirectUri)) {
            builder = builder.queryParam("redirect_uri", redirectUri);
        }
        if (hasText(loginHint)) {
            builder = builder.queryParam("login_hint", loginHint);
        }
        URI uri = builder.build();

        ResponseEntity<Void> result =
                serverRunning.createRestTemplate().exchange(
                        uri.toString(),
                        HttpMethod.GET,
                        new HttpEntity<>(null, getHeaders(cookies)),
                        Void.class
                );

        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        String location = result.getHeaders().getLocation().toString();

        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String header : result.getHeaders().get("Set-Cookie")) {
                int nameLength = header.indexOf('=');
                cookies.addCookie(new BasicClientCookie(header.substring(0, nameLength), header.substring(nameLength + 1)));
            }
        }

        ResponseEntity<String> response = serverRunning.getForString(location, getHeaders(cookies));

        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength + 1)));
            }
        }

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        if (!hasText(jSessionId)) {
            // should be directed to the login screen...
            assertTrue(response.getBody().contains("/login.do"));
            assertTrue(response.getBody().contains("username"));
            assertTrue(response.getBody().contains("password"));
            String csrf = IntegrationTestUtils.extractCookieCsrf(response.getBody());

            formData.add("username", username);
            formData.add("password", password);
            formData.add(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrf);

            // Should be redirected to the original URL, but now authenticated
            result = serverRunning.postForResponse("/login.do", getHeaders(cookies), formData);
            assertEquals(HttpStatus.FOUND, result.getStatusCode());

            cookies.clear();
            if (result.getHeaders().containsKey("Set-Cookie")) {
                for (String cookie : result.getHeaders().get("Set-Cookie")) {
                    int nameLength = cookie.indexOf('=');
                    cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength + 1)));
                }
            }
        }

        response = serverRunning.createRestTemplate().exchange(
                result.getHeaders().getLocation().toString(), HttpMethod.GET, new HttpEntity<>(null, getHeaders(cookies)),
                String.class);

        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength + 1)));
            }
        }
        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertTrue(response.getBody().contains("<h1>Application Authorization</h1>"));

            formData.clear();
            formData.add(USER_OAUTH_APPROVAL, "true");
            formData.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));
            result = serverRunning.postForResponse("/oauth/authorize", getHeaders(cookies), formData);
            assertEquals(HttpStatus.FOUND, result.getStatusCode());
            location = result.getHeaders().getLocation().toString();
        } else {
            // Token cached so no need for second approval
            assertEquals(HttpStatus.FOUND, response.getStatusCode());
            location = response.getHeaders().getLocation().toString();
        }
        if (hasText(redirectUri)) {
            assertTrue("Wrong location: " + location, location.matches(redirectUri + ".*code=.+"));
        }

        formData.clear();
        formData.add("client_id", clientId);
        formData.add("grant_type", GRANT_TYPE_AUTHORIZATION_CODE);
        if (hasText(redirectUri)) {
            formData.add("redirect_uri", redirectUri);
        }
        if (hasText(tokenResponseType)) {
            formData.add("response_type", tokenResponseType);
        }
        formData.add("code", location.split("code=")[1].split("&")[0]);
        HttpHeaders tokenHeaders = new HttpHeaders();
        if (clientSecret != null) {
            tokenHeaders.set("Authorization", UaaTestAccounts.getAuthorizationHeader(clientId, clientSecret));
        } else if (clientAssertion != null) {
            formData.add(JwtClientAuthentication.CLIENT_ASSERTION_TYPE, JwtClientAuthentication.GRANT_TYPE);
            formData.add(JwtClientAuthentication.CLIENT_ASSERTION, clientAssertion);
        }
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
        assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());

        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(tokenResponse.getBody());
        Map<String, String> body = tokenResponse.getBody();

        formData = new LinkedMultiValueMap<>();
        HttpHeaders headers = new HttpHeaders();
        if (clientSecret != null) {
            headers.set("Authorization", UaaTestAccounts.getAuthorizationHeader(clientId, clientSecret));
        } else if (clientAssertion != null) {
            formData.add(JwtClientAuthentication.CLIENT_ASSERTION_TYPE, JwtClientAuthentication.GRANT_TYPE);
            formData.add(JwtClientAuthentication.CLIENT_ASSERTION, clientAssertion);
        }
        formData.add("token", accessToken.getValue());

        if (callCheckToken) {
            tokenResponse = serverRunning.postForMap("/check_token", formData, headers);
            assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());
            assertNotNull(tokenResponse.getBody().get("iss"));
        }
        return body;
    }

    public static String extractCookieCsrf(String body) {
        String pattern = "\\<input type=\\\"hidden\\\" name=\\\"X-Uaa-Csrf\\\" value=\\\"(.*?)\\\"";

        Pattern linkPattern = Pattern.compile(pattern);
        Matcher matcher = linkPattern.matcher(body);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    public static void takeScreenShot(WebDriver webDriver) {
        takeScreenShot("testscreenshot-", webDriver);
    }

    public static void takeScreenShot(String prefix, WebDriver webDriver) {
        File scrFile = ((TakesScreenshot) webDriver).getScreenshotAs(OutputType.FILE);
        try {
            SimpleDateFormat format = new SimpleDateFormat("yyyyMMdd-HHmmss.SSS");
            String now = format.format(new Date(System.currentTimeMillis()));
            FileUtils.copyFile(scrFile, new File("build/reports/", prefix + now + ".png"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void validateAccountChooserCookie(String baseUrl, WebDriver webDriver, IdentityZone identityZone) {
        if (identityZone.getConfig().isAccountChooserEnabled()) {
            List<String> cookies = getAccountChooserCookies(baseUrl, webDriver);
            assertThat(cookies, Matchers.hasItem(startsWith("Saved-Account-")));
        }
    }

    public static void validateUserLastLogon(ScimUser user, Long beforeTestTime, Long afterTestTime) {
        Long userLastLogon = user.getLastLogonTime();
        assertNotNull(userLastLogon);
        assertTrue((userLastLogon > beforeTestTime) && (userLastLogon < afterTestTime));
    }

    public static List<String> getAccountChooserCookies(String baseUrl, WebDriver webDriver) {
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(baseUrl + "/login");
        return webDriver.manage().getCookies().stream().map(Cookie::getName).toList();
    }

    public static String createAnotherUser(WebDriver webDriver, String password, SimpleSmtpServer simpleSmtpServer, String url, TestClient testClient) {
        String userEmail = "user" + new SecureRandom().nextInt() + "@example.com";

        webDriver.get(url + "/create_account");
        webDriver.findElement(By.name("email")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(By.name("password_confirmation")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Send activation link']")).click();

        Iterator receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        receivedEmail.remove();
        webDriver.get(testClient.extractLink(message.getBody()));

        return userEmail;
    }

    public static HttpHeaders getAuthenticatedHeaders(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + token);
        return headers;
    }

    public static String createClientAdminTokenInZone(String baseUrl, String uaaAdminToken, String zoneId, IdentityZoneConfiguration config) {
        RestTemplate identityClient = getClientCredentialsTemplate(getClientCredentialsResource(baseUrl,
                new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret"));
        createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, config);
        String zoneUrl = baseUrl.replace("localhost", zoneId + ".localhost");
        UaaClientDetails zoneClient = new UaaClientDetails("admin-client-in-zone", null, "openid",
                "authorization_code,client_credentials", "uaa.admin,scim.read,scim.write,zones.testzone1.admin ", zoneUrl);
        zoneClient.setClientSecret("admin-secret-in-zone");
        createOrUpdateClient(uaaAdminToken, baseUrl, zoneId, zoneClient);
        return getClientCredentialsToken(zoneUrl, "admin-client-in-zone", "admin-secret-in-zone");
    }

    public static class RegexMatcher extends TypeSafeMatcher<String> {

        private final String regex;

        RegexMatcher(final String regex) {
            this.regex = regex;
        }

        public static RegexMatcher matchesRegex(final String regex) {
            return new RegexMatcher(regex);
        }

        @Override
        public void describeTo(final Description description) {
            description.appendText("matches regex=`" + regex + "`");
        }

        @Override
        public boolean matchesSafely(final String string) {
            return string.matches(regex);
        }
    }

    public static class HttpRequestFactory extends HttpComponentsClientHttpRequestFactory {
        private final boolean disableRedirect;
        private final boolean disableCookieHandling;

        HttpRequestFactory(boolean disableCookieHandling, boolean disableRedirect) {
            this.disableCookieHandling = disableCookieHandling;
            this.disableRedirect = disableRedirect;
        }

        @Override
        public HttpClient getHttpClient() {
            HttpClientBuilder builder = HttpClientBuilder.create()
                    .useSystemProperties();
            if (disableRedirect) {
                builder = builder.disableRedirectHandling();
            }
            if (disableCookieHandling) {
                builder = builder.disableCookieManagement();
            }
            return builder.build();
        }
    }

    public static class StatelessRequestFactory extends HttpRequestFactory {
        public StatelessRequestFactory() {
            super(true, true);
        }
    }

}