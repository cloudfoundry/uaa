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
import org.apache.commons.lang.RandomStringUtils;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.invitations.InvitationsRequest;
import org.cloudfoundry.identity.uaa.invitations.InvitationsResponse;
import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
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
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.Links;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.Assert;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.event.ApplicationEventMulticaster;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
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
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.Cookie;
import java.net.URL;
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

import static java.util.Arrays.asList;
import static org.cloudfoundry.identity.uaa.scim.ScimGroupMember.Role.MEMBER;
import static org.cloudfoundry.identity.uaa.scim.ScimGroupMember.Type.USER;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.SAVED_REQUEST_SESSION_ATTRIBUTE;
import static org.junit.Assert.assertEquals;
import static org.springframework.http.HttpHeaders.HOST;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.util.StringUtils.hasText;

public final class MockMvcUtils {

    private MockMvcUtils() {}

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
        "    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://simplesamlphp.cfapps.io/saml2/idp/SingleLogoutService.php\"/>\n" +
        "    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n" +
        "    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://simplesamlphp.cfapps.io/saml2/idp/SSOService.php\"/>\n" +
        "  </md:IDPSSODescriptor>\n" +
        "  <md:ContactPerson contactType=\"technical\">\n" +
        "    <md:GivenName>Filip</md:GivenName>\n" +
        "    <md:SurName>Hanik</md:SurName>\n" +
        "    <md:EmailAddress>fhanik@pivotal.io</md:EmailAddress>\n" +
        "  </md:ContactPerson>\n" +
        "</md:EntityDescriptor>";

    public static MockMvcUtils utils() {
        // this is all static now
        // TODO: replace calls to this method with static references
        return null;
    }

    public static String getSPMetadata(MockMvc mockMvc, String subdomain) throws Exception {
        return mockMvc.perform(
            get("/saml/metadata")
                .accept(MediaType.APPLICATION_XML)
                .header(HOST, hasText(subdomain) ? subdomain + ".localhost" : "localhost")
        ).andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
    }

    public static String getIDPMetaData(MockMvc mockMvc, String subdomain) throws Exception {
        return mockMvc.perform(
            get("/saml/idp/metadata")
                .accept(MediaType.APPLICATION_XML)
                .header(HOST, hasText(subdomain) ? subdomain + ".localhost" : "localhost")
        ).andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
    }

    public static MockHttpSession getSavedRequestSession() {
        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = new MockSavedRequest();
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);
        return session;
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
                return new String[] {"admin"};
            }
            return new String[0];
        }
        @Override public List<Cookie> getCookies() { return null; }
        @Override public String getMethod() { return null; }
        @Override public List<String> getHeaderValues(String name) { return null; }
        @Override
        public Collection<String> getHeaderNames() { return null; }
        @Override public List<Locale> getLocales() { return null; }
        @Override public Map<String, String[]> getParameterMap() { return null; }

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


    public static String extractInvitationCode(String inviteLink) throws Exception {
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
        IdentityProvider<UaaIdentityProviderDefinition> uaaIdp = provisioning.retrieveByOrigin(OriginKeys.UAA, zoneId);
        uaaIdp.setActive(!disable);
        provisioning.update(uaaIdp);
    }

    public static void setDisableInternalUserManagement(ApplicationContext context, String zoneId, boolean disabled) {
        IdentityProviderProvisioning provisioning = context.getBean(JdbcIdentityProviderProvisioning.class);
        IdentityProvider<UaaIdentityProviderDefinition> uaaIdp = provisioning.retrieveByOrigin(OriginKeys.UAA, zoneId);
        uaaIdp.getConfig().setDisableInternalUserManagement(disabled);
        provisioning.update(uaaIdp);
    }

    public static void setSelfServiceLinksEnabled(ApplicationContext context, String zoneId,boolean enabled) {
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
                                                                            String...emails) throws Exception {
        InvitationsRequest invitations = new InvitationsRequest(emails);

        String requestBody = JsonUtils.writeValueAsString(invitations);

        MockHttpServletRequestBuilder post = post("/invite_users")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, redirectUri)
                .header("Authorization", "Bearer " + token)
                .contentType(APPLICATION_JSON)
                .content(requestBody);
        if (hasText(subdomain)) {
            post.header("Host",(subdomain+".localhost"));
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
        assertEquals(1, response.getNewInvites().size());
        assertEquals(expectedOrigin, context.getBean(JdbcTemplate.class).queryForObject("SELECT origin FROM users WHERE username='" + email + "'", String.class));
        return response.getNewInvites().get(0).getInviteLink();
    }

    public static IdentityProvider createIdentityProvider(MockMvc mockMvc, IdentityZoneCreationResult zone, String nameAndOriginKey, AbstractIdentityProviderDefinition definition) throws Exception {
        IdentityProvider provider = new IdentityProvider();
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
        provider = utils().createIdpUsingWebRequest(mockMvc,
                zone.getIdentityZone().getId(),
                zone.getZoneAdminToken(),
                provider,
                status().isCreated());
        return provider;
    }

    public static ZoneScimInviteData createZoneForInvites(MockMvc mockMvc, ApplicationContext context, String clientId, String redirectUri) throws Exception {
        RandomValueStringGenerator generator = new RandomValueStringGenerator();
        String superAdmin = getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", "", null);
        IdentityZoneCreationResult zone = utils().createOtherIdentityZoneAndReturnResult(generator.generate().toLowerCase(), mockMvc, context, null);
        BaseClientDetails appClient = new BaseClientDetails("app","","scim.invite", "client_credentials,password,authorization_code","uaa.admin,clients.admin,scim.write,scim.read,scim.invite", redirectUri);
        appClient.setClientSecret("secret");
        appClient = utils().createClient(mockMvc, zone.getZoneAdminToken(), appClient, zone.getIdentityZone());
        appClient.setClientSecret("secret");
        String adminToken = utils().getClientCredentialsOAuthAccessToken(
            mockMvc,
            appClient.getClientId(),
            appClient.getClientSecret(),
            "",
            zone.getIdentityZone().getSubdomain()
        );


        String username = new RandomValueStringGenerator().generate().toLowerCase()+"@example.com";
        ScimUser user = new ScimUser(clientId, username, "given-name", "family-name");
        user.setPrimaryEmail(username);
        user.setPassword("password");
        user = createUserInZone(mockMvc, adminToken, user, zone.getIdentityZone().getSubdomain());
        user.setPassword("password");

        ScimGroup group = new ScimGroup("scim.invite");
        group.setMembers(Arrays.asList(new ScimGroupMember(user.getId(), USER, Arrays.asList(MEMBER))));

        return new ZoneScimInviteData(
                adminToken,
                zone,
                appClient,
                superAdmin
        );
    }

    public static void setDisableInternalUserManagement(boolean disableInternalUserManagement, ApplicationContext applicationContext) {
        IdentityProviderProvisioning identityProviderProvisioning = applicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        IdentityProvider<UaaIdentityProviderDefinition> idp = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, "uaa");
        UaaIdentityProviderDefinition config = idp.getConfig();
        if (config == null) {
            config = new UaaIdentityProviderDefinition();
        }
        config.setDisableInternalUserManagement(disableInternalUserManagement);
        idp.setConfig(config);
        identityProviderProvisioning.update(idp);
    }

    public static IdentityZone createZoneUsingWebRequest(MockMvc mockMvc, String accessToken) throws Exception {
        final String zoneId = new RandomValueStringGenerator(12).generate().toLowerCase();
        IdentityZone identityZone = MultitenancyFixture.identityZone(zoneId, zoneId);

        MvcResult result = mockMvc.perform(post("/identity-zones")
                .header("Authorization", "Bearer " + accessToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().isCreated()).andReturn();
        return JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityZone.class);
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

    public static IdentityZoneCreationResult createOtherIdentityZoneAndReturnResult(MockMvc mockMvc, ApplicationContext webApplicationContext, ClientDetails bootstrapClient, IdentityZone identityZone) throws Exception {
        String identityToken = getClientCredentialsOAuthAccessToken(mockMvc, "identity", "identitysecret",
                "zones.write,scim.zones", null);

        mockMvc.perform(post("/identity-zones")
                .header("Authorization", "Bearer " + identityToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().isCreated());

        // use the identity client to grant the zones.<id>.admin scope to a user
        UaaUserDatabase db = webApplicationContext.getBean(UaaUserDatabase.class);
        UaaPrincipal marissa = new UaaPrincipal(db.retrieveUserByName("marissa", OriginKeys.UAA));
        ScimGroup group = new ScimGroup();
        String zoneAdminScope = "zones." + identityZone.getId() + ".admin";
        group.setDisplayName(zoneAdminScope);
        group.setMembers(Collections.singletonList(new ScimGroupMember(marissa.getId())));
        mockMvc.perform(post("/Groups/zones")
                .header("Authorization", "Bearer " + identityToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(group)))
                .andExpect(status().isCreated());

        // use that user to create an admin client in the new zone
        String zoneAdminAuthcodeToken = getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret",
                marissa.getId(), "marissa", "koala", zoneAdminScope);

        if (bootstrapClient!=null) {
            mockMvc.perform(post("/oauth/clients")
                    .header("Authorization", "Bearer " + zoneAdminAuthcodeToken)
                    .header("X-Identity-Zone-Id", identityZone.getId())
                    .contentType(APPLICATION_JSON)
                    .accept(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(bootstrapClient)))
                    .andExpect(status().isCreated());
        }
        return new IdentityZoneCreationResult(identityZone, marissa, zoneAdminAuthcodeToken);
    }

    public static IdentityZoneCreationResult createOtherIdentityZoneAndReturnResult(String subdomain, MockMvc mockMvc,
            ApplicationContext webApplicationContext, ClientDetails bootstrapClient) throws Exception {

        IdentityZone identityZone = MultitenancyFixture.identityZone(subdomain, subdomain);
        return createOtherIdentityZoneAndReturnResult(mockMvc, webApplicationContext, bootstrapClient, identityZone);
    }

    public static IdentityZone createOtherIdentityZone(String subdomain, MockMvc mockMvc,
            ApplicationContext webApplicationContext, ClientDetails bootstrapClient) throws Exception {
        return createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, bootstrapClient).getIdentityZone();

    }

    public static IdentityZone createOtherIdentityZone(String subdomain, MockMvc mockMvc,
            ApplicationContext webApplicationContext) throws Exception {

        BaseClientDetails client = new BaseClientDetails("admin", null, null, "client_credentials",
                "clients.admin,scim.read,scim.write,idps.write,uaa.admin", "http://redirect.url");
        client.setClientSecret("admin-secret");

        return createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, client);
    }

    public static IdentityZone updateIdentityZone(IdentityZone zone, ApplicationContext context) {
        return context.getBean(IdentityZoneProvisioning.class).update(zone);
    }

    public static IdentityProvider createIdpUsingWebRequest(MockMvc mockMvc, String zoneId, String token,
                                                     IdentityProvider identityProvider, ResultMatcher resultMatcher) throws Exception {
        return createIdpUsingWebRequest(mockMvc, zoneId, token, identityProvider, resultMatcher, false);
    }
    public static IdentityProvider createIdpUsingWebRequest(MockMvc mockMvc, String zoneId, String token,
            IdentityProvider identityProvider, ResultMatcher resultMatcher, boolean update) throws Exception {
        MockHttpServletRequestBuilder requestBuilder =
            update ?
                put("/identity-providers/"+identityProvider.getId())
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

    public static ScimUser createUserInZone(MockMvc mockMvc, String accessToken, ScimUser user, String subdomain) throws  Exception {
        return createUserInZone(mockMvc, accessToken, user, subdomain, null);
    }
    public static ScimUser createUserInZone(MockMvc mockMvc, String accessToken, ScimUser user, String subdomain, String zoneId) throws  Exception {
        String requestDomain = subdomain.equals("") ? "localhost" : subdomain + ".localhost";
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

    public static ScimUser readUserInZone(MockMvc mockMvc, String accessToken, String userId, String subdomain, String zoneId) throws  Exception {
        String requestDomain = subdomain.equals("") ? "localhost" : subdomain + ".localhost";
        MockHttpServletRequestBuilder get = get("/Users/"+userId);
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

    public static ScimUser createAdminForZone(MockMvc mockMvc, String accessToken, String scopes) throws Exception {
        String random = RandomStringUtils.randomAlphabetic(6);
        ScimUser user = new ScimUser();
        user.setUserName(random + "@example.com");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(random + "@example.com");
        user.setEmails(asList(email));
        user.setPassword("secr3T");
        ScimUser createdUser = createUser(mockMvc, accessToken, user);

        for (String scope : StringUtils.commaDelimitedListToSet(scopes)) {
            ScimGroup group = getGroup(mockMvc, accessToken, scope);
            if (group==null) {
                group = new ScimGroup(null, scope, IdentityZoneHolder.get().getId());
                group.setMembers(Arrays.asList(new ScimGroupMember(createdUser.getId())));
                createGroup(mockMvc, accessToken, group);
            } else {
                List<ScimGroupMember> members = new LinkedList(group.getMembers());
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
        String filter = "displayName eq \""+displayName+"\"";
        MockHttpServletRequestBuilder builder = get("/Groups");
        if (hasText(subdomain)) {
            builder.header("Host", subdomain+".localhost");
        }
        SearchResults<ScimGroup> results = JsonUtils.readValue(
            mockMvc.perform(builder
                .header("Authorization", "Bearer " + accessToken)
                .contentType(APPLICATION_JSON)
                .param("filter", filter))
                .andReturn().getResponse().getContentAsString(),
            new TypeReference<SearchResults<ScimGroup>>() {});
        if (results==null || results.getResources()==null || results.getResources().isEmpty()) {
            return null;
        } else {
            return results.getResources().iterator().next();
        }
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
            post.header("Host", subdomain+".localhost");
        }
        return JsonUtils.readValue(
            mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString(),
            ScimGroup.class);
    }

    public static void createClient(ApplicationContext context, BaseClientDetails client, String zoneId) throws Exception {
        IdentityZone original = IdentityZoneHolder.get();
        try {
            IdentityZoneHolder.set(MultitenancyFixture.identityZone(zoneId,zoneId));
            context.getBean(MultitenantJdbcClientDetailsService.class).addClientDetails(client);
        } finally {
            IdentityZoneHolder.set(original);
        }

    }

    public static void mapExternalGroup(ApplicationContext context, String groupId, String externalGroup, String origin, String zoneId) throws Exception {
        JdbcScimGroupExternalMembershipManager gm = context.getBean(JdbcScimGroupExternalMembershipManager.class);
        IdentityZone original = IdentityZoneHolder.get();
        try {
            IdentityZoneHolder.set(MultitenancyFixture.identityZone(zoneId,zoneId));
            gm.mapExternalGroup(groupId, externalGroup, origin);
        } finally {
            IdentityZoneHolder.set(original);
        }
    }

    public static ScimGroup createGroup(ApplicationContext context, ScimGroup group, String zoneId) throws Exception {
        JdbcScimGroupProvisioning gp = context.getBean(JdbcScimGroupProvisioning.class);
        try {
            return gp.create(group, zoneId);
        } catch (ScimResourceAlreadyExistsException e) {
            String filter = "displayName eq \""+group.getDisplayName()+"\"";
            IdentityZone original = IdentityZoneHolder.get();
            IdentityZoneHolder.set(MultitenancyFixture.identityZone(zoneId, zoneId));
            try {
                return gp.query(filter).get(0);
            } finally {
                IdentityZoneHolder.set(original);
            }
        }
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
        if (zone!=null) {
            put.header("Host", zone.getSubdomain()+".localhost");
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

    public static BaseClientDetails createClient(MockMvc mockMvc, String accessToken, BaseClientDetails clientDetails) throws Exception {
        return createClient(mockMvc, accessToken, clientDetails, IdentityZone.getUaa());
    }

    public static BaseClientDetails createClient(MockMvc mockMvc, String accessToken, BaseClientDetails clientDetails, IdentityZone zone)
            throws Exception {
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + accessToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientDetails));
        if (! zone.equals(IdentityZone.getUaa())) {
            createClientPost = createClientPost.header(IdentityZoneSwitchingFilter.HEADER, zone.getId());
        }
        return JsonUtils.readValue(
            mockMvc.perform(createClientPost)
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString(), BaseClientDetails.class);
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
        return createClient(mockMvc,adminAccessToken, client, zone);
    }

    public static ClientDetailsModification getClientDetailsModification(String id, String secret, Collection<String> resourceIds, Collection<String> scopes, Collection<String> grantTypes, String authorities, Set<String> redirectUris) {
        ClientDetailsModification detailsModification = new ClientDetailsModification();
        detailsModification.setClientId(id);
        detailsModification.setResourceIds(resourceIds);
        detailsModification.setScope(scopes);
        detailsModification.setAuthorizedGrantTypes(grantTypes);
        detailsModification.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
        detailsModification.setRegisteredRedirectUri(redirectUris);
        ClientDetailsModification client = detailsModification;
        client.setClientSecret(secret);
        return client;
    }

    public static BaseClientDetails updateClient(MockMvc mockMvc, String accessToken, BaseClientDetails clientDetails, IdentityZone zone)
        throws Exception {
        MockHttpServletRequestBuilder updateClientPut =
            put("/oauth/clients/" + clientDetails.getClientId())
                .header("Authorization", "Bearer " + accessToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientDetails));
        if (! zone.equals(IdentityZone.getUaa())) {
            updateClientPut = updateClientPut.header(IdentityZoneSwitchingFilter.HEADER, zone.getId());
        }

        return JsonUtils.readValue(
            mockMvc.perform(updateClientPut)
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(), BaseClientDetails.class);
    }

    public static BaseClientDetails getClient(MockMvc mockMvc, String accessToken, String clientId, IdentityZone zone)
        throws Exception {
        MockHttpServletRequestBuilder readClientGet =
            get("/oauth/clients/" + clientId)
                .header("Authorization", "Bearer " + accessToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON);
        if (! zone.equals(IdentityZone.getUaa())) {
            readClientGet = readClientGet.header(IdentityZoneSwitchingFilter.HEADER, zone.getId());
        }

        return JsonUtils.readValue(
            mockMvc.perform(readClientGet)
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(), BaseClientDetails.class);
    }

    public static String getZoneAdminToken(MockMvc mockMvc, String adminToken, String zoneId) throws Exception {
        String scope = "zones." + zoneId + ".admin";
        return getZoneAdminToken(mockMvc, adminToken, zoneId, scope);
    }

    public static String getZoneAdminToken(MockMvc mockMvc, String adminToken, String zoneId, String scope) throws Exception {
        ScimUser user = new ScimUser();
        user.setUserName(new RandomValueStringGenerator().generate());
        user.setPrimaryEmail(user.getUserName() + "@test.org");
        user.setPassword("secr3T");
        user = MockMvcUtils.utils().createUser(mockMvc, adminToken, user);
        ScimGroup group = new ScimGroup(null, scope, IdentityZone.getUaa().getId());
        group.setMembers(Arrays.asList(new ScimGroupMember(user.getId())));
        MockMvcUtils.utils().createGroup(mockMvc, adminToken, group);
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
        if (zone!=null) {
            oauthTokenPost.header("Host", zone.getSubdomain()+".localhost");
        }
        if (opaque) {
            oauthTokenPost.param(TokenConstants.REQUEST_TOKEN_FORMAT, TokenConstants.OPAQUE);
        }

        MvcResult result = mockMvc.perform(oauthTokenPost).andDo(print()).andExpect(status().isOk()).andReturn();
        InjectedMockContextTest.OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(),
            InjectedMockContextTest.OAuthToken.class);
        return oauthToken.accessToken;
    }

    public static String getClientOAuthAccessToken(MockMvc mockMvc, String clientId, String clientSecret, String scope)
        throws Exception {
        return getClientCredentialsOAuthAccessToken(mockMvc, clientId, clientSecret, scope, null);
    }

    public static String getUserOAuthAccessTokenAuthCode(MockMvc mockMvc, String clientId, String clientSecret, String userId, String username, String password, String scope) throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + clientSecret)
                        .getBytes()));
        UaaPrincipal p = new UaaPrincipal(userId, username, "test@test.org", OriginKeys.UAA, "", IdentityZoneHolder.get()
                .getId());
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(p, "",
                UaaAuthority.USER_AUTHORITIES);
        Assert.assertTrue(auth.isAuthenticated());

        SecurityContextHolder.getContext().setAuthentication(auth);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new MockSecurityContext(auth)
                );

        String state = new RandomValueStringGenerator().generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
                .header("Authorization", basicDigestHeaderValue)
                .header("Accept", MediaType.APPLICATION_JSON_VALUE)
                .session(session)
                .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(TokenConstants.REQUEST_TOKEN_FORMAT, TokenConstants.OPAQUE)
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");
        if (StringUtils.hasText(scope)) {
            authRequest.param(OAuth2Utils.SCOPE, scope);
        }

        MvcResult result = mockMvc.perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(location);
        String code = builder.build().getQueryParams().get("code").get(0);

        authRequest = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .header("Accept", MediaType.APPLICATION_JSON_VALUE)
                .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
                .param(OAuth2Utils.RESPONSE_TYPE, "token")
                .param("code", code)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");
        if (StringUtils.hasText(scope)) {
            authRequest.param(OAuth2Utils.SCOPE, scope);
        }
        result = mockMvc.perform(authRequest).andExpect(status().is2xxSuccessful()).andReturn();
        InjectedMockContextTest.OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(),
            InjectedMockContextTest.OAuthToken.class);
        return oauthToken.accessToken;

    }

    public static String getScimInviteUserToken(MockMvc mockMvc, String clientId, String clientSecret, IdentityZone zone) throws Exception {
        String adminToken = getClientCredentialsOAuthAccessToken(mockMvc,
                                                                 "admin",
                                                                 zone==null?"adminsecret":"admin-secret",
                                                                 "",
                                                                 zone==null?null:zone.getSubdomain()
        );
        // create a user (with the required permissions) to perform the actual /invite_users action
        String username = new RandomValueStringGenerator().generate().toLowerCase()+"@example.com";
        ScimUser user = new ScimUser(clientId, username, "given-name", "family-name");
        user.setPrimaryEmail(username);
        user.setPassword("password");
        user = (zone == null) ? createUser(mockMvc, adminToken, user) : createUserInZone(mockMvc,adminToken,user,zone.getSubdomain(), null);

        String scope = "scim.invite";
        ScimGroupMember member = new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.READER));
        ScimGroup inviteGroup = new ScimGroup(scope);

        if (zone!=null) {
            createGroup(mockMvc, adminToken, zone.getSubdomain(), inviteGroup);
        }
        ScimGroup group = getGroup(mockMvc,
                                   adminToken,
                                   scope,
                                   zone==null?null:zone.getSubdomain()
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
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param("recovable","true")
                .param("scope", scope);
        if (subdomain != null && !subdomain.equals("")) {
            oauthTokenPost.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));
        }
        if (opaque) {
            oauthTokenPost.param(TokenConstants.REQUEST_TOKEN_FORMAT, TokenConstants.OPAQUE);
        }
        MvcResult result = mockMvc.perform(oauthTokenPost)
            .andDo(print())
            .andExpect(status().isOk())
            .andReturn();
        InjectedMockContextTest.OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(), InjectedMockContextTest.OAuthToken.class);
        return oauthToken.accessToken;
    }

    public static SecurityContext getMarissaSecurityContext(ApplicationContext context) {
        return getUaaSecurityContext("marissa", context);
    }

    public static SecurityContext getUaaSecurityContext(String username, ApplicationContext context) {
        return getUaaSecurityContext(username, context, IdentityZoneHolder.get());
    }

    public static SecurityContext getUaaSecurityContext(String username, ApplicationContext context, IdentityZone zone) {
            try {
                IdentityZoneHolder.set(zone);
                ScimUserProvisioning userProvisioning = context.getBean(JdbcScimUserProvisioning.class);
                ScimUser user = userProvisioning.query("username eq \""+username+"\" and origin eq \"uaa\"").get(0);
                UaaPrincipal uaaPrincipal = new UaaPrincipal(user.getId(), user.getUserName(), user.getPrimaryEmail(), user.getOrigin(), user.getExternalId(), IdentityZoneHolder.get().getId());
                UaaAuthentication principal = new UaaAuthentication(uaaPrincipal, null, Arrays.asList(UaaAuthority.fromAuthorities("uaa.user")), new UaaAuthenticationDetails(new MockHttpServletRequest()), true, System.currentTimeMillis());
                SecurityContext securityContext = new SecurityContextImpl();
                securityContext.setAuthentication(principal);
                return securityContext;
            } finally {
                IdentityZoneHolder.clear();
            }
        }


    public static <T extends ApplicationEvent>  TestApplicationEventListener<T> addEventListener(ConfigurableApplicationContext applicationContext, Class<T> clazz) {
        TestApplicationEventListener<T> listener = TestApplicationEventListener.forEventClass(clazz);
        applicationContext.addApplicationListener(listener);
        return listener;
    }

    public static void removeEventListener(ConfigurableApplicationContext applicationContext, ApplicationListener listener) {
        Map<String, ApplicationEventMulticaster> multicasters = applicationContext.getBeansOfType(ApplicationEventMulticaster.class);
        for (Map.Entry<String, ApplicationEventMulticaster> entry : multicasters.entrySet()) {
            entry.getValue().removeApplicationListener(listener);
        }
    }

    public static boolean isMySQL(Environment environment) {
        for (String s : environment.getActiveProfiles()) {
            if (s.contains("mysql")) {
                return true;
            }
        }
        return false;
    }

    public static class MockSecurityContext implements SecurityContext {

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

        private boolean useInvalidToken = false;
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
            if (cookies==null) {
                request.setCookies(cookie);
            } else {
                addCsrfCookie(request, cookie, cookies);
            }
            request.setParameter(token.getParameterName(), useInvalidToken ? "invalid" + tokenValue : tokenValue);
            return request;
        }

        protected void addCsrfCookie(MockHttpServletRequest request, Cookie cookie, Cookie[] cookies) {
            boolean replaced = false;
            for (int i=0; i<cookies.length; i++) {
                Cookie c = cookies[i];
                if (cookie.getName()==c.getName()) {
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

        public static CookieCsrfPostProcessor cookieCsrf() {
            return new CookieCsrfPostProcessor();
        }
    }

    public static class PredictableGenerator extends RandomValueStringGenerator {
        public AtomicInteger counter = new AtomicInteger(1);
        @Override
        public String generate() {
            return  "test"+counter.incrementAndGet();
        }
    }
}
