/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.mock.util;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.invitations.InvitationsRequest;
import org.cloudfoundry.identity.uaa.invitations.InvitationsResponse;
import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimGroupEndpoints;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.Links;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.mockito.Mockito;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.event.ApplicationEventMulticaster;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.GenericWebApplicationContext;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.Serial;
import java.net.URL;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.cloudfoundry.identity.uaa.scim.ScimGroupMember.Type.USER;
import static org.hamcrest.Matchers.not;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.util.StringUtils.hasText;

public final class MockMvcUtils {

    private MockMvcUtils() {
        throw new java.lang.UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    private static final String SIMPLESAMLPHP_UAA_ACCEPTANCE = "http://simplesamlphp.uaa-acceptance.cf-app.com";

    public static final String IDP_META_DATA =
            "<?xml version=\"1.0\"?>\n" +
                    "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"%s\" ID=\"pfx06ad4153-c17c-d286-194c-dec30bb92796\"><ds:Signature>\n" +
                    "  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                    "    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
                    "  <ds:Reference URI=\"#pfx06ad4153-c17c-d286-194c-dec30bb92796\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>begl1WVCsXSn7iHixtWPP8d/X+k=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>BmbKqA3A0oSLcn5jImz/l5WbpVXj+8JIpT/ENWjOjSd/gcAsZm1QvYg+RxYPBk+iV2bBxD+/yAE/w0wibsHrl0u9eDhoMRUJBUSmeyuN1lYzBuoVa08PdAGtb5cGm4DMQT5Rzakb1P0hhEPPEDDHgTTxop89LUu6xx97t2Q03Khy8mXEmBmNt2NlFxJPNt0FwHqLKOHRKBOE/+BpswlBocjOQKFsI9tG3TyjFC68mM2jo0fpUQCgj5ZfhzolvS7z7c6V201d9Tqig0/mMFFJLTN8WuZPavw22AJlMjsDY9my+4R9HKhK5U53DhcTeECs9fb4gd7p5BJy4vVp7tqqOg==</ds:SignatureValue>\n" +
                    "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n" +
                    "  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
                    "    <md:KeyDescriptor use=\"signing\">\n" +
                    "      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                    "        <ds:X509Data>\n" +
                    "          <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n" +
                    "        </ds:X509Data>\n" +
                    "      </ds:KeyInfo>\n" +
                    "    </md:KeyDescriptor>\n" +
                    "    <md:KeyDescriptor use=\"encryption\">\n" +
                    "      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                    "        <ds:X509Data>\n" +
                    "          <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n" +
                    "        </ds:X509Data>\n" +
                    "      </ds:KeyInfo>\n" +
                    "    </md:KeyDescriptor>\n" +
                    "    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"" + SIMPLESAMLPHP_UAA_ACCEPTANCE + "/saml2/idp/SingleLogoutService.php\"/>\n" +
                    "    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n" +
                    "    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"" + SIMPLESAMLPHP_UAA_ACCEPTANCE + "/saml2/idp/SSOService.php\"/>\n" +
                    "  </md:IDPSSODescriptor>\n" +
                    "  <md:ContactPerson contactType=\"technical\">\n" +
                    "    <md:GivenName>Filip</md:GivenName>\n" +
                    "    <md:SurName>Hanik</md:SurName>\n" +
                    "    <md:EmailAddress>fhanik@pivotal.io</md:EmailAddress>\n" +
                    "  </md:ContactPerson>\n" +
                    "</md:EntityDescriptor>";


    static LimitedModeUaaFilter getLimitedModeUaaFilter(ApplicationContext context) {
        FilterRegistrationBean<LimitedModeUaaFilter> bean =
                (FilterRegistrationBean<LimitedModeUaaFilter>) context.getBean("limitedModeUaaFilter", FilterRegistrationBean.class);
        return bean.getFilter();
    }
    public static File getLimitedModeStatusFile(ApplicationContext context) {
        return getLimitedModeUaaFilter(context).getStatusFile();
    }

    public static File setLimitedModeStatusFile(ApplicationContext context) throws Exception {
        File tempFile = Files.createTempFile("uaa-limited-mode-negative-test.", ".status").toFile();
        getLimitedModeUaaFilter(context).setStatusFile(tempFile);
        return tempFile;
    }

    public static void resetLimitedModeStatusFile(ApplicationContext context, File file) {
        getLimitedModeUaaFilter(context).setStatusFile(file);
    }

    public static MockHttpSession getSavedRequestSession() {
        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = new MockSavedRequest();
        SessionUtils.setSavedRequestSession(session, savedRequest);
        return session;
    }

    public static ScimUser getUserByUsername(MockMvc mockMvc, String username, String accessToken) throws Exception {
        MockHttpServletRequestBuilder get = get("/Users?filter=userName eq \"" + username + "\"")
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", APPLICATION_JSON);
        MvcResult userResult = mockMvc.perform(get)
                .andExpect(status().isOk()).andReturn();
        SearchResults<ScimUser> results = JsonUtils.readValue(userResult.getResponse().getContentAsString(),
                new TypeReference<>() {
                });
        return results.getResources().getFirst();
    }

    public static String extractInvitationCode(String inviteLink) {
        Pattern p = Pattern.compile("accept\\?code=(.*)");
        Matcher m = p.matcher(inviteLink);

        if (m.find()) {
            return m.group(1);
        } else {
            return null;
        }
    }

    public static void setDisableInternalAuth(ApplicationContext context, String zoneId, boolean disable) {
        IdentityProviderProvisioning provisioning = context.getBean(JdbcIdentityProviderProvisioning.class);
        IdentityProvider<UaaIdentityProviderDefinition> uaaIdp = provisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, zoneId);
        uaaIdp.setActive(!disable);
        provisioning.update(uaaIdp, zoneId);
    }

    public static void setSelfServiceLinksEnabled(ApplicationContext context, String zoneId, boolean enabled) {
        IdentityZoneConfiguration config = getZoneConfiguration(context, zoneId);
        config.getLinks().getSelfService().setSelfServiceLinksEnabled(enabled);
        setZoneConfiguration(context, zoneId, config);
    }

    public static void setZoneConfiguration(ApplicationContext context, String zoneId, IdentityZoneConfiguration configuration) {
        IdentityZoneProvisioning provisioning = context.getBean(IdentityZoneProvisioning.class);
        IdentityZone uaaZone = provisioning.retrieve(zoneId);
        uaaZone.setConfig(configuration);
        provisioning.update(uaaZone);
    }

    public static IdentityZoneConfiguration getZoneConfiguration(ApplicationContext context, String zoneId) {
        IdentityZoneProvisioning provisioning = context.getBean(IdentityZoneProvisioning.class);
        IdentityZone uaaZone = provisioning.retrieve(zoneId);
        return uaaZone.getConfig();
    }

    public static void setPrompts(ApplicationContext context, String zoneId, List<Prompt> prompts) {
        IdentityZoneConfiguration config = getZoneConfiguration(context, zoneId);
        config.setPrompts(prompts);
        setZoneConfiguration(context, zoneId, config);
    }

    public static List<Prompt> getPrompts(ApplicationContext context, String zoneId) {
        IdentityZoneConfiguration config = getZoneConfiguration(context, zoneId);
        return config.getPrompts();
    }

    public static Links.Logout getLogout(ApplicationContext context, String zoneId) {
        IdentityZoneConfiguration config = getZoneConfiguration(context, zoneId);
        return config.getLinks().getLogout();
    }

    public static void setLogout(ApplicationContext context, String zoneId, Links.Logout logout) {
        IdentityZoneProvisioning provisioning = context.getBean(IdentityZoneProvisioning.class);
        IdentityZone uaaZone = provisioning.retrieve(zoneId);
        IdentityZoneConfiguration config = uaaZone.getConfig();
        config.getLinks().setLogout(logout);
        setZoneConfiguration(context, zoneId, config);
    }

    public static InvitationsResponse sendRequestWithTokenAndReturnResponse(ApplicationContext context,
            MockMvc mockMvc,
            String token,
            String subdomain,
            String clientId,
            String redirectUri,
            String... emails) throws Exception {
        InvitationsRequest invitations = new InvitationsRequest(emails);

        String requestBody = JsonUtils.writeValueAsString(invitations);

        MockHttpServletRequestBuilder post = post("/invite_users")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, redirectUri)
                .header("Authorization", "Bearer " + token)
                .contentType(APPLICATION_JSON)
                .content(requestBody);
        if (hasText(subdomain)) {
            post.header("Host", (subdomain + ".localhost"));
        }
        MvcResult result = mockMvc.perform(
                post
        )
        .andExpect(status().isOk())
                .andReturn();
        return JsonUtils.readValue(result.getResponse().getContentAsString(), InvitationsResponse.class);
    }

    public static URL inviteUser(ApplicationContext context, MockMvc mockMvc, String email, String userInviteToken, String subdomain, String clientId, String expectedOrigin, String REDIRECT_URI) throws Exception {
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(context, mockMvc, userInviteToken, subdomain, clientId, REDIRECT_URI, email);
        assertThat(response.getNewInvites()).hasSize(1);
        assertThat(context.getBean(JdbcTemplate.class).queryForObject("SELECT origin FROM users WHERE username='" + email + "'", String.class)).isEqualTo(expectedOrigin);
        return response.getNewInvites().getFirst().getInviteLink();
    }

    public static <T extends AbstractIdentityProviderDefinition> IdentityProvider<T> createIdentityProvider(MockMvc mockMvc, IdentityZoneCreationResult zone, String nameAndOriginKey, T definition) throws Exception {
        IdentityProvider<T> provider = new IdentityProvider<>();
        provider.setConfig(definition);
        provider.setActive(true);
        provider.setIdentityZoneId(zone.getIdentityZone().getId());
        provider.setName(nameAndOriginKey);
        provider.setOriginKey(nameAndOriginKey);
        if (definition instanceof SamlIdentityProviderDefinition) {
            provider.setType(OriginKeys.SAML);
        } else if (definition instanceof LdapIdentityProviderDefinition) {
            provider.setType(OriginKeys.LDAP);
        } else if (definition instanceof UaaIdentityProviderDefinition) {
            provider.setType(OriginKeys.UAA);
        }
        provider = MockMvcUtils.createIdpUsingWebRequest(mockMvc,
                zone.getIdentityZone().getId(),
                zone.getZoneAdminToken(),
                provider,
                status().isCreated());
        return provider;
    }

    public static ZoneScimInviteData createZoneForInvites(MockMvc mockMvc, ApplicationContext context, String userId, String redirectUri, String zoneId) throws Exception {
        AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator();
        String superAdmin = getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", "", null);
        IdentityZoneCreationResult zone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(generator.generate().toLowerCase(), mockMvc, context, null, zoneId);

        List<String> redirectUris = Arrays.asList(redirectUri, "http://" + zone.getIdentityZone().getSubdomain() + ".localhost");
        UaaClientDetails appClient = new UaaClientDetails("app", "", "scim.invite", "client_credentials,password,authorization_code", "uaa.admin,clients.admin,scim.write,scim.read,scim.invite", String.join(",", redirectUris));

        appClient.setClientSecret("secret");
        appClient = MockMvcUtils.createClient(mockMvc, zone.getZoneAdminToken(), appClient, zone.getIdentityZone(),
                status().isCreated());
        appClient.setClientSecret("secret");
        String adminToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(
                mockMvc,
                appClient.getClientId(),
                appClient.getClientSecret(),
                "",
                zone.getIdentityZone().getSubdomain()
        );

        String username = new AlphanumericRandomValueStringGenerator().generate().toLowerCase() + "@example.com";
        ScimUser user = new ScimUser(userId, username, "given-name", "family-name");
        user.setPrimaryEmail(username);
        user.setPassword("password");
        user = createUserInZone(mockMvc, adminToken, user, zone.getIdentityZone().getSubdomain());
        user.setPassword("password");

        ScimGroup group = new ScimGroup("scim.invite");
        group.setMembers(Collections.singletonList(new ScimGroupMember(user.getId(), USER)));

        return new ZoneScimInviteData(
                adminToken,
                zone,
                appClient,
                superAdmin
        );
    }

    public static void setDisableInternalUserManagement(ApplicationContext applicationContext, boolean disableInternalUserManagement) {
        IdentityProviderProvisioning identityProviderProvisioning = applicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        IdentityProvider<UaaIdentityProviderDefinition> idp = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaaZoneId());
        UaaIdentityProviderDefinition config = idp.getConfig();
        if (config == null) {
            config = new UaaIdentityProviderDefinition();
        }
        config.setDisableInternalUserManagement(disableInternalUserManagement);
        idp.setConfig(config);
        identityProviderProvisioning.update(idp, idp.getIdentityZoneId());
    }

    public static IdentityZone createZoneUsingWebRequest(MockMvc mockMvc, String accessToken) throws Exception {
        final String zoneId = new AlphanumericRandomValueStringGenerator(12).generate().toLowerCase();
        IdentityZone identityZone = MultitenancyFixture.identityZone(zoneId, zoneId);

        MvcResult result = mockMvc.perform(post("/identity-zones")
                .header("Authorization", "Bearer " + accessToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().isCreated()).andReturn();
        return JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityZone.class);
    }

    public static IdentityZoneCreationResult createOtherIdentityZoneAndReturnResult(
            MockMvc mockMvc,
            ApplicationContext webApplicationContext,
            ClientDetails bootstrapClient,
            IdentityZone identityZone,
            String zoneId) throws Exception {
        return createOtherIdentityZoneAndReturnResult(mockMvc,
                webApplicationContext,
                bootstrapClient,
                identityZone,
                true,
                zoneId);
    }

    public static IdentityZoneCreationResult createOtherIdentityZoneAndReturnResult(MockMvc mockMvc,
            ApplicationContext webApplicationContext,
            ClientDetails bootstrapClient,
            IdentityZone identityZone,
            boolean useWebRequests,
            String zoneId) throws Exception {
        String identityToken = getClientCredentialsOAuthAccessToken(mockMvc, "identity", "identitysecret",
                "zones.write,scim.zones", null);

        if (useWebRequests) {
            mockMvc.perform(post("/identity-zones")
                    .header("Authorization", "Bearer " + identityToken)
                    .contentType(APPLICATION_JSON)
                    .accept(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(identityZone)))
                    .andExpect(status().isCreated());
        } else {
            webApplicationContext.getBean(IdentityZoneProvisioning.class).create(identityZone);
            IdentityProvider<UaaIdentityProviderDefinition> defaultIdp = new IdentityProvider<>();
            defaultIdp.setName(OriginKeys.UAA);
            defaultIdp.setType(OriginKeys.UAA);
            defaultIdp.setOriginKey(OriginKeys.UAA);
            defaultIdp.setIdentityZoneId(identityZone.getId());
            UaaIdentityProviderDefinition idpDefinition = new UaaIdentityProviderDefinition();
            idpDefinition.setPasswordPolicy(null);
            defaultIdp.setConfig(idpDefinition);
            webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class).create(defaultIdp, identityZone.getId());
        }

        // use the identity client to grant the zones.<id>.admin scope to a user
        UaaUserDatabase db = webApplicationContext.getBean(UaaUserDatabase.class);
        UaaPrincipal marissa = new UaaPrincipal(db.retrieveUserByName("marissa", OriginKeys.UAA));
        ScimGroup group = new ScimGroup();
        String zoneAdminScope = "zones." + identityZone.getId() + ".admin";
        group.setDisplayName(zoneAdminScope);
        group.setMembers(Collections.singletonList(new ScimGroupMember(marissa.getId())));
        if (useWebRequests) {
            mockMvc.perform(post("/Groups/zones")
                    .header("Authorization", "Bearer " + identityToken)
                    .contentType(APPLICATION_JSON)
                    .accept(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(group)))
                    .andExpect(status().isCreated());
        } else {
            webApplicationContext.getBean(ScimGroupEndpoints.class).addZoneManagers(group, Mockito.mock(HttpServletResponse.class));
        }

        // use that user to create an admin client in the new zone
        String zoneAdminAuthcodeToken = getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret",
                marissa.getId(), "marissa", "koala", zoneAdminScope);

        if (bootstrapClient != null) {
            if (useWebRequests) {
                mockMvc.perform(post("/oauth/clients")
                        .header("Authorization", "Bearer " + zoneAdminAuthcodeToken)
                        .header("X-Identity-Zone-Id", identityZone.getId())
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(bootstrapClient)))
                        .andExpect(status().isCreated());
            } else {
                webApplicationContext.getBean(MultitenantJdbcClientDetailsService.class).addClientDetails(
                        bootstrapClient,
                        identityZone.getId()
                );
            }
        }
        return new IdentityZoneCreationResult(identityZone, marissa, zoneAdminAuthcodeToken);
    }

    public static IdentityZoneCreationResult createOtherIdentityZoneAndReturnResult(String subdomain,
            MockMvc mockMvc,
            ApplicationContext webApplicationContext,
            ClientDetails bootstrapClient,
            boolean useWebRequests,
            String zoneId) throws Exception {

        IdentityZone identityZone = MultitenancyFixture.identityZone(subdomain, subdomain);
        return createOtherIdentityZoneAndReturnResult(mockMvc, webApplicationContext, bootstrapClient, identityZone, useWebRequests, zoneId);
    }

    public static IdentityZoneCreationResult createOtherIdentityZoneAndReturnResult(String subdomain,
            MockMvc mockMvc,
            ApplicationContext webApplicationContext,
            ClientDetails bootstrapClient,
            String zoneId) throws Exception {

        return createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, bootstrapClient, true, zoneId);
    }

    public static IdentityZone createOtherIdentityZone(String subdomain,
            MockMvc mockMvc,
            ApplicationContext webApplicationContext,
            ClientDetails bootstrapClient, String zoneId) throws Exception {
        return createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, bootstrapClient, true, zoneId);
    }

    public static IdentityZone createOtherIdentityZone(String subdomain,
            MockMvc mockMvc,
            ApplicationContext webApplicationContext,
            ClientDetails bootstrapClient,
            boolean useWebRequests,
            String zoneId) throws Exception {
        return createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, bootstrapClient, useWebRequests, zoneId).getIdentityZone();

    }

    public static IdentityZone createOtherIdentityZone(String subdomain, MockMvc mockMvc,
            ApplicationContext webApplicationContext, String zoneId) throws Exception {
        return createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, true, zoneId);
    }

    public static IdentityZone createOtherIdentityZone(String subdomain,
            MockMvc mockMvc,
            ApplicationContext webApplicationContext,
            boolean useWebRequests,
            String zoneId) throws Exception {

        UaaClientDetails client = new UaaClientDetails("admin", null, null, "client_credentials",
                "clients.admin,scim.read,scim.write,idps.write,uaa.admin", "http://redirect.url");
        client.setClientSecret("admin-secret");

        return createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, client, useWebRequests, zoneId);
    }

    public static IdentityZone updateIdentityZone(IdentityZone zone, ApplicationContext context) {
        return context.getBean(IdentityZoneProvisioning.class).update(zone);
    }

    public static void deleteIdentityZone(String zoneId, MockMvc mockMvc) throws Exception {
        String identityToken = getClientCredentialsOAuthAccessToken(mockMvc, "identity", "identitysecret",
                "zones.write,scim.zones", null);

        mockMvc.perform(delete("/identity-zones/" + zoneId)
                .header("Authorization", "Bearer " + identityToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    public static IdentityProvider createIdpUsingWebRequest(MockMvc mockMvc, String zoneId, String token,
            IdentityProvider identityProvider, ResultMatcher resultMatcher) throws Exception {
        return createIdpUsingWebRequest(mockMvc, zoneId, token, identityProvider, resultMatcher, false);
    }

    public static IdentityProvider createIdpUsingWebRequest(MockMvc mockMvc, String zoneId, String token,
            IdentityProvider identityProvider, ResultMatcher resultMatcher, boolean update) throws Exception {
        MockHttpServletRequestBuilder requestBuilder =
                update ?
                        put("/identity-providers/" + identityProvider.getId())
                                .header("Authorization", "Bearer " + token)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(identityProvider))
                        :
                        post("/identity-providers/")
                                .header("Authorization", "Bearer " + token)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(identityProvider));

        if (zoneId != null) {
            requestBuilder.header(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }

        MvcResult result = mockMvc.perform(requestBuilder)
                .andExpect(resultMatcher)
                .andReturn();
        if (hasText(result.getResponse().getContentAsString())) {
            try {
                return JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityProvider.class);
            } catch (JsonUtils.JsonUtilException e) {
                return null;
            }
        } else {
            return null;
        }
    }

    public static ScimUser createUser(MockMvc mockMvc, String accessToken, ScimUser user) throws Exception {
        return createUserInZone(mockMvc, accessToken, user, "");
    }

    public static ScimUser createUserInZone(MockMvc mockMvc, String accessToken, ScimUser user, String subdomain) throws Exception {
        return createUserInZone(mockMvc, accessToken, user, subdomain, null);
    }

    public static ScimUser createUserInZone(MockMvc mockMvc, String accessToken, ScimUser user, String subdomain, String zoneId) throws Exception {
        String requestDomain = subdomain.isEmpty() ? "localhost" : subdomain + ".localhost";
        MockHttpServletRequestBuilder post = post("/Users");
        post.header("Authorization", "Bearer " + accessToken)
                .with(new SetServerNameRequestPostProcessor(requestDomain))
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsBytes(user));
        if (hasText(zoneId)) {
            post.header(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        MvcResult userResult = mockMvc.perform(post)
                .andExpect(status().isCreated()).andReturn();
        return JsonUtils.readValue(userResult.getResponse().getContentAsString(), ScimUser.class);
    }

    public static ScimUser readUserInZone(MockMvc mockMvc, String accessToken, String userId, String subdomain, String zoneId) throws Exception {
        String requestDomain = subdomain.isEmpty() ? "localhost" : subdomain + ".localhost";
        MockHttpServletRequestBuilder get = get("/Users/" + userId);
        get.header("Authorization", "Bearer " + accessToken)
                .with(new SetServerNameRequestPostProcessor(requestDomain))
                .accept(APPLICATION_JSON);
        if (hasText(zoneId)) {
            get.header(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        MvcResult userResult = mockMvc.perform(get)
                .andExpect(status().isOk()).andReturn();
        return JsonUtils.readValue(userResult.getResponse().getContentAsString(), ScimUser.class);
    }

    public static ScimUser createAdminForZone(MockMvc mockMvc, String accessToken, String scopes, String zoneId) throws Exception {
        String random = RandomStringUtils.randomAlphabetic(6);
        ScimUser user = new ScimUser();
        user.setUserName(random + "@example.com");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(random + "@example.com");
        user.setEmails(Collections.singletonList(email));
        user.setPassword("secr3T");
        ScimUser createdUser = createUser(mockMvc, accessToken, user);

        for (String scope : StringUtils.commaDelimitedListToSet(scopes)) {
            ScimGroup group = getGroup(mockMvc, accessToken, scope);
            if (group == null) {
                group = new ScimGroup(null, scope, zoneId);
                group.setMembers(Collections.singletonList(new ScimGroupMember(createdUser.getId())));
                createGroup(mockMvc, accessToken, group);
            } else {
                List<ScimGroupMember> members = new LinkedList<>(group.getMembers());
                members.add(new ScimGroupMember(createdUser.getId()));
                group.setMembers(members);
                updateGroup(mockMvc, accessToken, group);
            }
        }
        return createdUser;
    }

    public static ScimGroup getGroup(MockMvc mockMvc, String accessToken, String displayName) throws Exception {
        return getGroup(mockMvc, accessToken, displayName, null);
    }

    public static ScimGroup getGroup(MockMvc mockMvc, String accessToken, String displayName, String subdomain) throws Exception {
        String filter = "displayName eq \"" + displayName + "\"";
        MockHttpServletRequestBuilder builder = get("/Groups");
        if (hasText(subdomain)) {
            builder.header("Host", subdomain + ".localhost");
        }
        SearchResults<ScimGroup> results = JsonUtils.readValue(
                mockMvc.perform(builder
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(APPLICATION_JSON)
                        .param("filter", filter))
                        .andReturn().getResponse().getContentAsString(),
                new TypeReference<>() {
                });
        if (results == null || results.getResources() == null || results.getResources().isEmpty()) {
            return null;
        } else {
            return results.getResources().getFirst();
        }
    }

    public static SearchResults<ScimGroup> getGroups(final MockMvc mockMvc, final String accessToken, final String idzId) throws Exception {
        final MockHttpServletRequestBuilder builder = get("/Groups");
        if (hasText(idzId)) {
            builder.header("X-Identity-Zone-Id", idzId);
        }
        final SearchResults<ScimGroup> results = JsonUtils.readValue(
                mockMvc.perform(builder
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(APPLICATION_JSON))
                        .andReturn().getResponse().getContentAsString(),
                new TypeReference<>() {
                });
        if (results == null || results.getResources() == null || results.getResources().isEmpty()) {
            return null;
        }
        return results;
    }

    public static ScimGroup createGroup(MockMvc mockMvc, String accessToken, ScimGroup group) throws Exception {
        return createGroup(mockMvc, accessToken, group, null);
    }

    public static ScimGroup createGroup(MockMvc mockMvc, String accessToken, String subdomain, ScimGroup group) throws Exception {
        MockHttpServletRequestBuilder post = post("/Groups")
                .header("Authorization", "Bearer " + accessToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(group));
        if (hasText(subdomain)) {
            post.header("Host", subdomain + ".localhost");
        }
        return JsonUtils.readValue(
                mockMvc.perform(post)
                        .andExpect(status().isCreated())
                        .andReturn().getResponse().getContentAsString(),
                ScimGroup.class);
    }

    public static ScimGroup createGroup(MockMvc mockMvc, String accessToken, ScimGroup group, String zoneId) throws Exception {
        MockHttpServletRequestBuilder post = post("/Groups")
                .header("Authorization", "Bearer " + accessToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(group));
        if (hasText(zoneId)) {
            post.header(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        return JsonUtils.readValue(
                mockMvc.perform(post)
                        .andExpect(status().isCreated())
                        .andReturn().getResponse().getContentAsString(),
                ScimGroup.class);
    }

    public static ScimGroup updateGroup(MockMvc mockMvc, String accessToken, ScimGroup group) throws Exception {
        return updateGroup(mockMvc, accessToken, group, null);
    }

    public static ScimGroup updateGroup(MockMvc mockMvc, String accessToken, ScimGroup group, IdentityZone zone) throws Exception {
        MockHttpServletRequestBuilder put = put("/Groups/" + group.getId());
        if (zone != null) {
            put.header("Host", zone.getSubdomain() + ".localhost");
        }
        return JsonUtils.readValue(
                mockMvc.perform(put.header("If-Match", group.getVersion())
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(group)))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString(),
                ScimGroup.class);
    }

    public static UaaClientDetails createClient(MockMvc mockMvc, String accessToken, UaaClientDetails clientDetails) throws Exception {
        return createClient(mockMvc, accessToken, clientDetails, IdentityZone.getUaa(), status().isCreated());
    }

    public static UaaClientDetails createClient(MockMvc mockMvc, IdentityZone identityZone, String accessToken, UaaClientDetails clientDetails) throws Exception {
        return createClient(mockMvc, accessToken, clientDetails, identityZone, status().isCreated());
    }

    public static void deleteClient(MockMvc mockMvc, String accessToken, String clientId, String zoneSubdomain) throws Exception {
        MockHttpServletRequestBuilder createClientDelete = delete("/oauth/clients/" + clientId)
                .header("Authorization", "Bearer " + accessToken)
                .accept(APPLICATION_JSON);
        if (!zoneSubdomain.equals(IdentityZone.getUaa())) {
            createClientDelete = createClientDelete.header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER, zoneSubdomain);
        }
        mockMvc.perform(createClientDelete)
                .andExpect(status().is(not(500)));
    }

    public static UaaClientDetails createClient(MockMvc mockMvc, String accessToken, UaaClientDetails clientDetails,
            IdentityZone zone, ResultMatcher status)
            throws Exception {
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + accessToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientDetails));
        if (!zone.isUaa()) {
            createClientPost = createClientPost.header(IdentityZoneSwitchingFilter.HEADER, zone.getId());
        }
        return JsonUtils.readValue(
                mockMvc.perform(createClientPost)
                        .andExpect(status)
                        .andReturn().getResponse().getContentAsString(), UaaClientDetails.class);
    }

    public static UaaClientDetails createClient(ApplicationContext context, UaaClientDetails clientDetails, IdentityZone zone) {

        MultitenantJdbcClientDetailsService service = context.getBean(MultitenantJdbcClientDetailsService.class);
        if (clientDetails.getClientSecret() == null) {
            // provide for tests the empty secret behavior
            clientDetails.setClientSecret("");
        }
        service.addClientDetails(clientDetails, zone.getId());
        return (UaaClientDetails) service.loadClientByClientId(clientDetails.getClientId(), zone.getId());
    }

    public static ClientDetails createClient(MockMvc mockMvc, String adminAccessToken, String id, String secret, Collection<String> resourceIds, List<String> scopes, List<String> grantTypes, String authorities) throws Exception {
        return createClient(mockMvc, adminAccessToken,
                id,
                secret,
                resourceIds,
                scopes,
                grantTypes,
                authorities,
                Collections.singleton("http://redirect.url"),
                IdentityZone.getUaa());
    }

    public static ClientDetails createClient(MockMvc mockMvc, String adminAccessToken, String id, String secret, Collection<String> resourceIds, Collection<String> scopes, Collection<String> grantTypes, String authorities, Set<String> redirectUris, IdentityZone zone) throws Exception {
        ClientDetailsModification client = getClientDetailsModification(id, secret, resourceIds, scopes, grantTypes, authorities, redirectUris);
        return createClient(mockMvc, adminAccessToken, client, zone, status().isCreated());
    }

    public static ClientDetailsModification getClientDetailsModification(String id, String secret, Collection<String> resourceIds, Collection<String> scopes, Collection<String> grantTypes, String authorities, Set<String> redirectUris) {
        ClientDetailsModification detailsModification = new ClientDetailsModification();
        detailsModification.setClientId(id);
        detailsModification.setResourceIds(resourceIds);
        detailsModification.setScope(scopes);
        detailsModification.setAuthorizedGrantTypes(grantTypes);
        detailsModification.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
        detailsModification.setRegisteredRedirectUri(redirectUris);
        detailsModification.setClientSecret(secret);
        return detailsModification;
    }

    public static UaaClientDetails updateClient(ApplicationContext context, UaaClientDetails clientDetails, IdentityZone zone) {
        MultitenantJdbcClientDetailsService service = context.getBean(MultitenantJdbcClientDetailsService.class);
        service.updateClientDetails(clientDetails, zone.getId());
        return (UaaClientDetails) service.loadClientByClientId(clientDetails.getClientId(), zone.getId());
    }

    public static UaaClientDetails updateClient(MockMvc mockMvc, String accessToken, UaaClientDetails clientDetails, IdentityZone zone)
            throws Exception {
        MockHttpServletRequestBuilder updateClientPut =
                put("/oauth/clients/" + clientDetails.getClientId())
                        .header("Authorization", "Bearer " + accessToken)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(clientDetails));
        if (!zone.isUaa()) {
            updateClientPut = updateClientPut.header(IdentityZoneSwitchingFilter.HEADER, zone.getId());
        }

        return JsonUtils.readValue(
                mockMvc.perform(updateClientPut)
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString(), UaaClientDetails.class);
    }

    public static UaaClientDetails getClient(MockMvc mockMvc, String accessToken, String clientId, IdentityZone zone)
            throws Exception {
        MockHttpServletRequestBuilder readClientGet =
                get("/oauth/clients/" + clientId)
                        .header("Authorization", "Bearer " + accessToken)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON);
        if (!zone.isUaa()) {
            readClientGet = readClientGet.header(IdentityZoneSwitchingFilter.HEADER, zone.getId());
        }

        return JsonUtils.readValue(
                mockMvc.perform(readClientGet)
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString(), UaaClientDetails.class);
    }

    public static String getZoneAdminToken(MockMvc mockMvc, String adminToken, String zoneId) throws Exception {
        String scope = "zones." + zoneId + ".admin";
        return getZoneAdminToken(mockMvc, adminToken, zoneId, scope);
    }

    public static String getZoneAdminToken(MockMvc mockMvc, String adminToken, String zoneId, String scope) throws Exception {
        ScimUser user = new ScimUser();
        user.setUserName(new AlphanumericRandomValueStringGenerator().generate());
        user.setPrimaryEmail(user.getUserName() + "@test.org");
        user.setPassword("secr3T");
        user = MockMvcUtils.createUser(mockMvc, adminToken, user);
        ScimGroup group = new ScimGroup(null, scope, IdentityZone.getUaaZoneId());
        group.setMembers(Collections.singletonList(new ScimGroupMember(user.getId())));
        MockMvcUtils.createGroup(mockMvc, adminToken, group);
        return getUserOAuthAccessTokenAuthCode(mockMvc,
                "identity",
                "identitysecret",
                user.getId(),
                user.getUserName(),
                "secr3T",
                group.getDisplayName()
        );
    }

    public static String getUserOAuthAccessToken(MockMvc mockMvc,
            String clientId,
            String clientSecret,
            String username,
            String password,
            String scope) throws Exception {
        return getUserOAuthAccessToken(mockMvc, clientId, clientSecret, username, password, scope, null);
    }

    public static String getUserOAuthAccessToken(MockMvc mockMvc,
            String clientId,
            String clientSecret,
            String username,
            String password,
            String scope,
            IdentityZone zone) throws Exception {
        return getUserOAuthAccessToken(mockMvc,
                clientId,
                clientSecret,
                username,
                password,
                scope,
                zone,
                false);
    }

    public static String getUserOAuthAccessToken(MockMvc mockMvc,
            String clientId,
            String clientSecret,
            String username,
            String password,
            String scope,
            IdentityZone zone,
            boolean opaque) throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost =
                post("/oauth/token")
                        .header("Authorization", basicDigestHeaderValue)
                        .param("grant_type", "password")
                        .param("client_id", clientId)
                        .param("username", username)
                        .param("password", password)
                        .param("scope", scope);
        if (zone != null) {
            oauthTokenPost.header("Host", zone.getSubdomain() + ".localhost");
        }
        if (opaque) {
            oauthTokenPost.param(TokenConstants.REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());
        }

        MvcResult result = mockMvc.perform(oauthTokenPost).andDo(print()).andExpect(status().isOk()).andReturn();
        OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(),
                OAuthToken.class);
        return oauthToken.accessToken;
    }

    public static String getClientOAuthAccessToken(MockMvc mockMvc,
            String clientId,
            String clientSecret,
            String scope)
            throws Exception {
        return getClientOAuthAccessToken(mockMvc, clientId, clientSecret, scope, false);
    }

    public static String getClientOAuthAccessToken(MockMvc mockMvc,
            String clientId,
            String clientSecret,
            String scope,
            boolean opaque)
            throws Exception {
        return getClientCredentialsOAuthAccessToken(mockMvc, clientId, clientSecret, scope, null, opaque);
    }

    public static String getUserOAuthAccessTokenAuthCode(MockMvc mockMvc, String clientId, String clientSecret, String userId, String username, String password, String scope) throws Exception {
        return getUserOAuthAccessTokenAuthCode(mockMvc, clientId, clientSecret, userId, username, password, scope, OPAQUE);
    }

    public static String getUserOAuthAccessTokenAuthCode(MockMvc mockMvc, String clientId, String clientSecret, String userId, String username, String password, String scope, TokenFormat tokenFormat) throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + clientSecret)
                .getBytes()));
        UaaPrincipal p = new UaaPrincipal(userId, username, "test@test.org", OriginKeys.UAA, "", IdentityZone.getUaaZoneId());
        UaaAuthentication auth = new UaaAuthentication(p, UaaAuthority.USER_AUTHORITIES, null);
        assertThat(auth.isAuthenticated()).isTrue();

        SecurityContextHolder.getContext().setAuthentication(auth);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new MockSecurityContext(auth)
        );

        String state = new AlphanumericRandomValueStringGenerator().generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
                .header("Authorization", basicDigestHeaderValue)
                .header("Accept", MediaType.APPLICATION_JSON_VALUE)
                .session(session)
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(TokenConstants.REQUEST_TOKEN_FORMAT, tokenFormat.getStringValue())
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");
        if (StringUtils.hasText(scope)) {
            authRequest.param(OAuth2Utils.SCOPE, scope);
        }

        MvcResult result = mockMvc.perform(authRequest).andDo(print()).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(location);
        String code = builder.build().getQueryParams().get("code").getFirst();

        authRequest = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .header("Accept", MediaType.APPLICATION_JSON_VALUE)
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param("code", code)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");
        if (StringUtils.hasText(scope)) {
            authRequest.param(OAuth2Utils.SCOPE, scope);
        }
        result = mockMvc.perform(authRequest).andExpect(status().is2xxSuccessful()).andReturn();
        OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(),
                OAuthToken.class);
        return oauthToken.accessToken;
    }

    public static String getScimInviteUserToken(MockMvc mockMvc, String clientId, String clientSecret, IdentityZone zone, String adminClientId, String adminClientSecret) throws Exception {
        String adminToken = getClientCredentialsOAuthAccessToken(mockMvc,
                adminClientId,
                adminClientSecret,
                "",
                zone == null ? null : zone.getSubdomain()
        );
        // create a user (with the required permissions) to perform the actual /invite_users action
        String username = new AlphanumericRandomValueStringGenerator().generate().toLowerCase() + "@example.com";
        ScimUser user = new ScimUser(clientId, username, "given-name", "family-name");
        user.setPrimaryEmail(username);
        user.setPassword("password");
        user = zone == null ? createUser(mockMvc, adminToken, user) : createUserInZone(mockMvc, adminToken, user, zone.getSubdomain(), null);

        String scope = "scim.invite";
        ScimGroupMember member = new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER);
        ScimGroup inviteGroup = new ScimGroup(scope);

        if (zone != null) {
            createGroup(mockMvc, adminToken, zone.getSubdomain(), inviteGroup);
        }
        ScimGroup group = getGroup(mockMvc,
                adminToken,
                scope,
                zone == null ? null : zone.getSubdomain()
        );
        group.getMembers().add(member);
        updateGroup(mockMvc, adminToken, group, zone);
        user.getGroups().add(new ScimUser.Group(group.getId(), scope));

        // get a bearer token for the user
        return getUserOAuthAccessToken(mockMvc,
                clientId,
                clientSecret,
                user.getUserName(),
                "password",
                "scim.invite",
                zone
        );
    }

    public static String getClientCredentialsOAuthAccessToken(MockMvc mockMvc,
            String clientId,
            String clientSecret,
            String scope,
            String subdomain) throws Exception {
        return getClientCredentialsOAuthAccessToken(mockMvc, clientId, clientSecret, scope, subdomain, false);
    }

    public static String getClientCredentialsOAuthAccessToken(MockMvc mockMvc,
            String clientId,
            String clientSecret,
            String scope,
            String subdomain,
            boolean opaque) throws Exception {
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .with(httpBasic(clientId, clientSecret))
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param("revocable", "true");
        if (!hasText(scope)) {
            oauthTokenPost.param("scope", scope);
        }
        if (subdomain != null && !subdomain.isEmpty()) {
            oauthTokenPost.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));
        }
        if (opaque) {
            oauthTokenPost.param(TokenConstants.REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());
        }
        MvcResult result = mockMvc.perform(oauthTokenPost)
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();
        OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class);
        return oauthToken.accessToken;
    }

    public static SecurityContext getMarissaSecurityContext(ApplicationContext context, String currentZoneId) {
        return getUaaSecurityContext("marissa", context, currentZoneId);
    }

    public static SecurityContext getUaaSecurityContext(String username, ApplicationContext context, String currentZoneId) {
        return getUaaSecurityContext(username, context, currentZoneId,
                Collections.singletonList(UaaAuthority.fromAuthorities("uaa.user")));
    }

    public static SecurityContext getUaaSecurityContext(String username, ApplicationContext context, String currentZoneId, Collection<? extends GrantedAuthority> authorities) {
        ScimUserProvisioning userProvisioning = context.getBean(JdbcScimUserProvisioning.class);
        ScimUser user = userProvisioning.query("username eq \"" + username + "\" and origin eq \"uaa\"", currentZoneId).getFirst();
        UaaPrincipal uaaPrincipal = new UaaPrincipal(user.getId(), user.getUserName(), user.getPrimaryEmail(), user.getOrigin(), user.getExternalId(), currentZoneId);
        UaaAuthentication principal = new UaaAuthentication(uaaPrincipal, null, authorities, new UaaAuthenticationDetails(new MockHttpServletRequest()), true, System.currentTimeMillis());
        SecurityContext securityContext = new SecurityContextImpl();
        securityContext.setAuthentication(principal);
        return securityContext;
    }

    public static <T extends ApplicationEvent> TestApplicationEventListener<T> addEventListener(ConfigurableApplicationContext applicationContext, Class<T> clazz) {
        TestApplicationEventListener<T> listener = TestApplicationEventListener.forEventClass(clazz);
        applicationContext.addApplicationListener(listener);
        return listener;
    }

    public static <T extends ApplicationEvent> TestApplicationEventListener<T> addEventListener(GenericWebApplicationContext applicationContext, Class<T> clazz) {
        TestApplicationEventListener<T> listener = TestApplicationEventListener.forEventClass(clazz);
        applicationContext.addApplicationListener(listener);
        return listener;
    }

    public static void removeEventListener(ListableBeanFactory applicationContext, ApplicationListener listener) {
        Map<String, ApplicationEventMulticaster> multicasters = applicationContext.getBeansOfType(ApplicationEventMulticaster.class);
        for (Map.Entry<String, ApplicationEventMulticaster> entry : multicasters.entrySet()) {
            entry.getValue().removeApplicationListener(listener);
        }
    }

    public static RequestPostProcessor httpBearer(String authorization) {
        return new HttpBearerAuthRequestPostProcessor(authorization);
    }

    public static IdentityZone updateZone(MockMvc mockMvc, IdentityZone updatedZone) throws Exception {
        String token =
                getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", "uaa.admin", null);

        String responseAsString =
                mockMvc.perform(put("/identity-zones/" + updatedZone.getId())
                        .header("Authorization", "Bearer " + token)
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(updatedZone)))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString();
        return JsonUtils.readValue(responseAsString, IdentityZone.class);
    }

    public static class MockSavedRequest extends DefaultSavedRequest {

        public MockSavedRequest() {
            super(new MockHttpServletRequest(), new PortResolverImpl());
        }

        @Override
        public String getRedirectUrl() {
            return "http://test/redirect/oauth/authorize";
        }

        @Override
        public String[] getParameterValues(String name) {
            if ("client_id".equals(name)) {
                return new String[]{"admin"};
            }
            return new String[0];
        }

        @Override
        public List<Cookie> getCookies() {
            return null;
        }

        @Override
        public String getMethod() {
            return null;
        }

        @Override
        public List<String> getHeaderValues(String name) {
            return null;
        }

        @Override
        public Collection<String> getHeaderNames() {
            return null;
        }

        @Override
        public List<Locale> getLocales() {
            return null;
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            return null;
        }
    }

    public static class ZoneScimInviteData {
        private final IdentityZoneCreationResult zone;
        private final String adminToken;
        private final ClientDetails scimInviteClient;
        private final String defaultZoneAdminToken;

        public ZoneScimInviteData(String adminToken,
                IdentityZoneCreationResult zone,
                ClientDetails scimInviteClient,
                String defaultZoneAdminToken) {
            this.adminToken = adminToken;
            this.zone = zone;
            this.scimInviteClient = scimInviteClient;
            this.defaultZoneAdminToken = defaultZoneAdminToken;
        }

        public ClientDetails getScimInviteClient() {
            return scimInviteClient;
        }

        public String getDefaultZoneAdminToken() {
            return defaultZoneAdminToken;
        }

        public IdentityZoneCreationResult getZone() {
            return zone;
        }

        public String getAdminToken() {
            return adminToken;
        }
    }

    public static class IdentityZoneCreationResult {
        private final IdentityZone identityZone;
        private final UaaPrincipal zoneAdmin;
        private final String zoneAdminToken;

        public IdentityZoneCreationResult(IdentityZone identityZone, UaaPrincipal zoneAdmin, String zoneAdminToken) {
            this.identityZone = identityZone;
            this.zoneAdmin = zoneAdmin;
            this.zoneAdminToken = zoneAdminToken;
        }

        public IdentityZone getIdentityZone() {
            return identityZone;
        }

        public UaaPrincipal getZoneAdminUser() {
            return zoneAdmin;
        }

        public String getZoneAdminToken() {
            return zoneAdminToken;
        }
    }

    public static class MockSecurityContext implements SecurityContext {

        @Serial
        private static final long serialVersionUID = -1386535243513362694L;

        private Authentication authentication;

        public MockSecurityContext(Authentication authentication) {
            this.authentication = authentication;
        }

        @Override
        public Authentication getAuthentication() {
            return this.authentication;
        }

        @Override
        public void setAuthentication(Authentication authentication) {
            this.authentication = authentication;
        }
    }

    public static class CookieCsrfPostProcessor implements RequestPostProcessor {

        private boolean useInvalidToken;

        public static CookieCsrfPostProcessor cookieCsrf() {
            return new CookieCsrfPostProcessor();
        }

        public CookieCsrfPostProcessor useInvalidToken() {
            useInvalidToken = true;
            return this;
        }

        public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {

            CsrfTokenRepository repository = new CookieBasedCsrfTokenRepository();
            CsrfToken token = repository.generateToken(request);
            repository.saveToken(token, request, new MockHttpServletResponse());
            String tokenValue = token.getToken();
            Cookie cookie = new Cookie(token.getParameterName(), tokenValue);
            cookie.setHttpOnly(true);
            Cookie[] cookies = request.getCookies();
            if (cookies == null) {
                request.setCookies(cookie);
            } else {
                addCsrfCookie(request, cookie, cookies);
            }
            request.setParameter(token.getParameterName(), useInvalidToken ? "invalid" + tokenValue : tokenValue);
            return request;
        }

        protected void addCsrfCookie(MockHttpServletRequest request, Cookie cookie, Cookie[] cookies) {
            boolean replaced = false;
            for (int i = 0; i < cookies.length; i++) {
                Cookie c = cookies[i];
                if (cookie.getName().equals(c.getName())) {
                    cookies[i] = cookie;
                    replaced = true;
                }
            }
            if (!replaced) {
                Cookie[] newcookies = new Cookie[cookies.length + 1];
                System.arraycopy(cookies, 0, newcookies, 0, cookies.length);
                newcookies[cookies.length] = cookie;
                request.setCookies(newcookies);
            }
        }
    }

    private static final class HttpBearerAuthRequestPostProcessor implements RequestPostProcessor {
        private final String headerValue;

        private HttpBearerAuthRequestPostProcessor(String authorization) {
            this.headerValue = "Bearer " + authorization;
        }

        @Override
        public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
            request.addHeader("Authorization", this.headerValue);
            return request;
        }
    }

    public static class PredictableGenerator extends RandomValueStringGenerator {
        public AtomicInteger counter = new AtomicInteger(1);

        @Override
        public String generate() {
            return "test" + counter.incrementAndGet();
        }
    }
}
