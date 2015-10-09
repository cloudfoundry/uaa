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
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.rest.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.TestClient.OAuthToken;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.UaaIdentityProviderDefinition;
import org.junit.Assert;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.event.ApplicationEventMulticaster;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.Cookie;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.Arrays.asList;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class MockMvcUtils {

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
        return new MockMvcUtils();
    }

    public static void setDisableInternalUserManagement(boolean disableInternalUserManagement, ApplicationContext applicationContext) {
        IdentityProviderProvisioning identityProviderProvisioning = applicationContext.getBean(IdentityProviderProvisioning.class);
        IdentityProvider idp = identityProviderProvisioning.retrieveByOrigin(Origin.UAA, "uaa");
        UaaIdentityProviderDefinition config = idp.getConfigValue(UaaIdentityProviderDefinition.class);
        if (config == null) {
        	config = new UaaIdentityProviderDefinition();
        }
        config.setDisableInternalUserManagement(disableInternalUserManagement);
        idp.setConfig(JsonUtils.writeValueAsString(config));
        identityProviderProvisioning.update(idp);
    }

    public IdentityZone createZoneUsingWebRequest(MockMvc mockMvc, String accessToken) throws Exception {
        final String zoneId = UUID.randomUUID().toString();
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

    public IdentityZoneCreationResult createOtherIdentityZoneAndReturnResult(String subdomain, MockMvc mockMvc,
            ApplicationContext webApplicationContext, ClientDetails bootstrapClient) throws Exception {
        String identityToken = getClientCredentialsOAuthAccessToken(mockMvc, "identity", "identitysecret",
                "zones.write,scim.zones", null);

        IdentityZone identityZone = MultitenancyFixture.identityZone(subdomain, subdomain);

        mockMvc.perform(post("/identity-zones")
                .header("Authorization", "Bearer " + identityToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().isCreated());

        // use the identity client to grant the zones.<id>.admin scope to a user
        UaaUserDatabase db = webApplicationContext.getBean(UaaUserDatabase.class);
        UaaPrincipal marissa = new UaaPrincipal(db.retrieveUserByName("marissa", Origin.UAA));
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

    public IdentityZone createOtherIdentityZone(String subdomain, MockMvc mockMvc,
            ApplicationContext webApplicationContext, ClientDetails bootstrapClient) throws Exception {
        return createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, bootstrapClient).getIdentityZone();

    }

    public IdentityZone createOtherIdentityZone(String subdomain, MockMvc mockMvc,
            ApplicationContext webApplicationContext) throws Exception {

        BaseClientDetails client = new BaseClientDetails("admin", null, null, "client_credentials",
                "clients.admin,scim.read,scim.write,idps.write");
        client.setClientSecret("admin-secret");

        return createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, client);
    }

    public IdentityProvider createIdpUsingWebRequest(MockMvc mockMvc, String zoneId, String token,
                                                     IdentityProvider identityProvider, ResultMatcher resultMatcher) throws Exception {
        return createIdpUsingWebRequest(mockMvc, zoneId, token, identityProvider, resultMatcher, false);
    }
    public IdentityProvider createIdpUsingWebRequest(MockMvc mockMvc, String zoneId, String token,
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
        if (StringUtils.hasText(result.getResponse().getContentAsString())) {
            try {
                return JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityProvider.class);
            } catch (JsonUtils.JsonUtilException e) {
                return null;
            }
        } else {
            return null;
        }
    }

    public ScimUser createUser(MockMvc mockMvc, String accessToken, ScimUser user) throws Exception {
        return createUserInZone(mockMvc, accessToken, user, "");
    }

    public ScimUser createUserInZone(MockMvc mockMvc, String accessToken, ScimUser user, String subdomain) throws  Exception {
        String requestDomain = subdomain.equals("") ? "localhost" : subdomain + ".localhost";
        MvcResult userResult = mockMvc.perform(post("/Users")
                .header("Authorization", "Bearer " + accessToken)
                .with(new SetServerNameRequestPostProcessor(requestDomain))
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsBytes(user)))
                .andExpect(status().isCreated()).andReturn();
        return JsonUtils.readValue(userResult.getResponse().getContentAsString(), ScimUser.class);
    }

    public ScimUser createAdminForZone(MockMvc mockMvc, String accessToken, String scopes) throws Exception {
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

    public ScimGroup getGroup(MockMvc mockMvc, String accessToken, String displayName) throws Exception {
        String filter = "displayName eq \""+displayName+"\"";
        SearchResults<ScimGroup> results = JsonUtils.readValue(
            mockMvc.perform(get("/Groups")
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

    public ScimGroup createGroup(MockMvc mockMvc, String accessToken, ScimGroup group) throws Exception {
        return createGroup(mockMvc, accessToken, group, null);
    }
    public ScimGroup createGroup(MockMvc mockMvc, String accessToken, ScimGroup group, String zoneId) throws Exception {
        MockHttpServletRequestBuilder post = post("/Groups")
            .header("Authorization", "Bearer " + accessToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(group));
        if (StringUtils.hasText(zoneId)) {
            post.header(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        return JsonUtils.readValue(
            mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString(),
            ScimGroup.class);
    }

    public ScimGroup updateGroup(MockMvc mockMvc, String accessToken, ScimGroup group) throws Exception {
        return JsonUtils.readValue(
            mockMvc.perform(put("/Groups/" + group.getId())
                                .header("If-Match", group.getVersion())
                                .header("Authorization", "Bearer " + accessToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(group)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(),
            ScimGroup.class);
    }

    public BaseClientDetails createClient(MockMvc mockMvc, String accessToken, BaseClientDetails clientDetails) throws Exception {
        return createClient(mockMvc, accessToken, clientDetails, IdentityZone.getUaa());
    }

    public BaseClientDetails createClient(MockMvc mockMvc, String accessToken, BaseClientDetails clientDetails, IdentityZone zone)
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

    public ClientDetails createClient(MockMvc mockMvc, String adminAccessToken, String id, String secret, String resourceIds, String scopes, List<GrantType> grantTypes, String authorities) throws Exception {
        return createClient(mockMvc, adminAccessToken, id, secret, resourceIds, scopes, grantTypes, authorities, null, IdentityZone.getUaa());
    }
    public ClientDetails createClient(MockMvc mockMvc, String adminAccessToken, String id, String secret, String resourceIds, String scopes, List<GrantType> grantTypes, String authorities, String redirectUris, IdentityZone zone) throws Exception {
        ClientDetailsModification client = new ClientDetailsModification(id, resourceIds, scopes, commaDelineatedGrantTypes(grantTypes), authorities, redirectUris);
        client.setClientSecret(secret);
        return createClient(mockMvc,adminAccessToken, client, zone);
    }

    public BaseClientDetails updateClient(MockMvc mockMvc, String accessToken, BaseClientDetails clientDetails, IdentityZone zone)
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

    public BaseClientDetails getClient(MockMvc mockMvc, String accessToken, String clientId, IdentityZone zone)
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

    public String getZoneAdminToken(MockMvc mockMvc, String adminToken, String zoneId) throws Exception {
        ScimUser user = new ScimUser();
        user.setUserName(new RandomValueStringGenerator().generate());
        user.setPrimaryEmail(user.getUserName() + "@test.org");
        user.setPassword("secr3T");
        user = MockMvcUtils.utils().createUser(mockMvc, adminToken, user);
        ScimGroup group = new ScimGroup(null, "zones." + zoneId + ".admin", IdentityZone.getUaa().getId());
        group.setMembers(Arrays.asList(new ScimGroupMember(user.getId())));
        MockMvcUtils.utils().createGroup(mockMvc, adminToken, group);
        return getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", user.getId(), user.getUserName(),
            "secr3T", group.getDisplayName());
    }

    public String getUserOAuthAccessToken(MockMvc mockMvc, String clientId, String clientSecret, String username,
            String password, String scope)
            throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("username", username)
                .param("password", password)
                .param("scope", scope);
        MvcResult result = mockMvc.perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        TestClient.OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(),
            TestClient.OAuthToken.class);
        return oauthToken.accessToken;
    }

    public String getClientOAuthAccessToken(MockMvc mockMvc, String clientId, String clientSecret, String scope)
        throws Exception {
        String basicDigestHeaderValue = "Basic "
            + new String(Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
            .header("Authorization", basicDigestHeaderValue)
            .param("grant_type", "client_credentials")
            .param("client_id", clientId)
            .param("scope", scope);
        MvcResult result = mockMvc.perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        TestClient.OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(), TestClient.OAuthToken.class);
        return oauthToken.accessToken;
    }

    public String getUserOAuthAccessTokenAuthCode(MockMvc mockMvc, String clientId, String clientSecret, String userId, String username, String password, String scope) throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + clientSecret)
                        .getBytes()));
        UaaPrincipal p = new UaaPrincipal(userId, username, "test@test.org", Origin.UAA, "", IdentityZoneHolder.get()
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
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");

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
        result = mockMvc.perform(authRequest).andExpect(status().is2xxSuccessful()).andReturn();
        TestClient.OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(),
            TestClient.OAuthToken.class);
        return oauthToken.accessToken;

    }

    public String getScimInviteUserToken(MockMvc mockMvc, String clientId, String clientSecret) throws Exception {
        String adminToken = getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", "", null);
        // create a user (with the required permissions) to perform the actual /invite_users action
        String username = new RandomValueStringGenerator().generate().toLowerCase()+"@example.com";
        ScimUser user = new ScimUser(clientId, username, "given-name", "family-name");
        user.setPrimaryEmail(username);
        user.setPassword("password");
        user = createUser(mockMvc, adminToken, user);

        String scope = "scim.invite";
        ScimGroupMember member = new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.READER));

        ScimGroup group = getGroup(mockMvc, adminToken, scope);
        group.getMembers().add(member);
        updateGroup(mockMvc, adminToken, group);
        user.getGroups().add(new ScimUser.Group(group.getId(), scope));

        // get a bearer token for the user
        return getUserOAuthAccessToken(mockMvc, clientId, clientSecret, user.getUserName(), "password", "scim.invite");
    }


    public String getClientCredentialsOAuthAccessToken(MockMvc mockMvc, String username, String password, String scope,
            String subdomain)
            throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64((username + ":" + password).getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "client_credentials")
                .param("client_id", username)
                .param("scope", scope);
        if (subdomain != null && !subdomain.equals(""))
            oauthTokenPost.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));
        MvcResult result = mockMvc.perform(oauthTokenPost)
                .andExpect(status().isOk())
                .andReturn();
        OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class);
        return oauthToken.accessToken;
    }

    public SecurityContext getMarissaSecurityContext(ApplicationContext context) {
        return getUaaSecurityContext("marissa", context);
    }

    public SecurityContext getUaaSecurityContext(String username, ApplicationContext context) {
        ScimUserProvisioning userProvisioning = context.getBean(JdbcScimUserProvisioning.class);
        ScimUser user = userProvisioning.query("username eq \""+username+"\" and origin eq \"uaa\"").get(0);
        UaaPrincipal uaaPrincipal = new UaaPrincipal(user.getId(), user.getUserName(), user.getPrimaryEmail(), user.getOrigin(), user.getExternalId(), IdentityZoneHolder.get().getId());
        UaaAuthentication principal = new UaaAuthentication(uaaPrincipal, null, Arrays.asList(UaaAuthority.fromAuthorities("uaa.user")), new UaaAuthenticationDetails(new MockHttpServletRequest()), true, System.currentTimeMillis());
        SecurityContext securityContext = new SecurityContextImpl();
        securityContext.setAuthentication(principal);
        return securityContext;
    }


    public <T extends ApplicationEvent>  TestApplicationEventListener<T> addEventListener(ConfigurableApplicationContext applicationContext, Class<T> clazz) {
        TestApplicationEventListener<T> listener = TestApplicationEventListener.forEventClass(clazz);
        applicationContext.addApplicationListener(listener);
        return listener;
    }

    public void removeEventListener(ConfigurableApplicationContext applicationContext, ApplicationListener listener) {
        Map<String, ApplicationEventMulticaster> multicasters = applicationContext.getBeansOfType(ApplicationEventMulticaster.class);
        for (Map.Entry<String, ApplicationEventMulticaster> entry : multicasters.entrySet()) {
            entry.getValue().removeApplicationListener(listener);
        }
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
            String tokenValue = useInvalidToken ? "invalid" + token.getToken() : token.getToken();
            Cookie cookie = new Cookie(token.getParameterName(), tokenValue);
            cookie.setHttpOnly(true);
            Cookie[] cookies = request.getCookies();
            if (cookies==null) {
                request.setCookies(cookie);
            } else {
                Cookie[] newcookies = new Cookie[cookies.length+1];
                System.arraycopy(cookies, 0, newcookies, 0, cookies.length);
                newcookies[cookies.length] = cookie;
                request.setCookies(newcookies);
            }
            request.setParameter(token.getParameterName(), tokenValue);
            return request;
        }

        public static CookieCsrfPostProcessor cookieCsrf() {
            return new CookieCsrfPostProcessor();
        }
    }

    public enum GrantType {
        password, client_credentials, authorization_code, implicit
    }

    private static String commaDelineatedGrantTypes(List<GrantType> grantTypes) {
        StringBuilder grantTypeCommaDelineated = new StringBuilder();
        for (int i = 0; i < grantTypes.size(); i++) {
            if (i > 0) {
                grantTypeCommaDelineated.append(",");
            }
            grantTypeCommaDelineated.append(grantTypes.get(i).name());
        }
        return grantTypeCommaDelineated.toString();
    }

}
