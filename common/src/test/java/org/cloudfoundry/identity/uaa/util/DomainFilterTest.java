/*
 *******************************************************************************
 *       Cloud Foundry Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *       This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *       You may not use this product except in compliance with the License.
 *
 *       This product includes a number of subcomponents with
 *       separate copyright notices and license terms. Your use of these
 *       subcomponents is subject to the terms and conditions of the
 *       subcomponent's license, as noted in the LICENSE file.
 ********************************************************************************
 */

package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.client.ClientConstants;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.UaaIdentityProviderDefinition;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static java.util.Collections.EMPTY_LIST;
import static org.cloudfoundry.identity.uaa.client.ClientConstants.ALLOWED_PROVIDERS;
import static org.junit.Assert.*;

public class DomainFilterTest {

    public static final String alias = "saml";
    public static final String idpMetaData = "<?xml version=\"1.0\"?>\n" +
        "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"http://"+alias+".cfapps.io/saml2/idp/metadata.php\" ID=\"pfx06ad4153-c17c-d286-194c-dec30bb92796\"><ds:Signature>\n" +
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
        "    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://"+alias+".cfapps.io/saml2/idp/SingleLogoutService.php\"/>\n" +
        "    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n" +
        "    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://"+alias+".cfapps.io/saml2/idp/SSOService.php\"/>\n" +
        "  </md:IDPSSODescriptor>\n" +
        "  <md:ContactPerson contactType=\"technical\">\n" +
        "    <md:GivenName>Filip</md:GivenName>\n" +
        "    <md:SurName>Hanik</md:SurName>\n" +
        "    <md:EmailAddress>fhanik@pivotal.io</md:EmailAddress>\n" +
        "  </md:ContactPerson>\n" +
        "</md:EntityDescriptor>";

    BaseClientDetails client;
    List<IdentityProvider> activeProviders = EMPTY_LIST;
    IdentityProvider uaaProvider;
    IdentityProvider ldapProvider;
    IdentityProvider samlProvider1;
    IdentityProvider samlProvider2;

    DomainFilter filter = new DomainFilter();

    String email = "test@test.org";
    private UaaIdentityProviderDefinition uaaDef;
    private LdapIdentityProviderDefinition ldapDef;
    private SamlIdentityProviderDefinition samlDef1;
    private SamlIdentityProviderDefinition samlDef2;

    @Before
    public void setUp() throws Exception {
        client = new BaseClientDetails("clientid","", "", "","","");

        uaaDef = new UaaIdentityProviderDefinition(null, null);
        ldapDef = new LdapIdentityProviderDefinition();
        samlDef1 = new SamlIdentityProviderDefinition(idpMetaData,"","",0,true,true,"","", IdentityZone.getUaa().getId());
        samlDef2 = new SamlIdentityProviderDefinition(idpMetaData,"","",0,true,true,"","", IdentityZone.getUaa().getId());
        configureTestData();
    }

    private void configureTestData() {
        uaaProvider = new IdentityProvider().setActive(true).setType(Origin.UAA).setOriginKey(Origin.UAA).setConfig(JsonUtils.writeValueAsString(uaaDef));
        ldapProvider = new IdentityProvider().setActive(true).setType(Origin.LDAP).setOriginKey(Origin.LDAP).setConfig(JsonUtils.writeValueAsString(ldapDef));
        samlProvider1 = new IdentityProvider().setActive(true).setType(Origin.SAML).setOriginKey("saml1").setConfig(JsonUtils.writeValueAsString(samlDef1));
        samlProvider2 = new IdentityProvider().setActive(true).setType(Origin.SAML).setOriginKey("saml2").setConfig(JsonUtils.writeValueAsString(samlDef2));
        activeProviders = Arrays.asList(uaaProvider, ldapProvider, samlProvider1, samlProvider2);
    }

    @Test
    public void test_null_arguments() throws Exception {
        assertThat(filter.filter(null,null,null), Matchers.containsInAnyOrder());
        assertThat(filter.filter(null,null,email), Matchers.containsInAnyOrder());
        assertThat(filter.filter(null,client,null), Matchers.containsInAnyOrder());
        assertThat(filter.filter(null,client,email), Matchers.containsInAnyOrder());
        assertThat(filter.filter(activeProviders,null,null), Matchers.containsInAnyOrder());
        assertThat(filter.filter(activeProviders,client,null), Matchers.containsInAnyOrder());
    }

    @Test
    public void test_default_idp_and_client_setup() {
        assertThat(filter.filter(activeProviders,null,email), Matchers.containsInAnyOrder(ldapProvider, samlProvider1, samlProvider2));
        assertThat(filter.filter(activeProviders,client,email), Matchers.containsInAnyOrder(ldapProvider, samlProvider1, samlProvider2));
        assertThat(filter.filter(Arrays.asList(ldapProvider),null,email), Matchers.containsInAnyOrder(ldapProvider));
        assertThat(filter.filter(Arrays.asList(ldapProvider),client,email), Matchers.containsInAnyOrder(ldapProvider));
        assertThat(filter.filter(Arrays.asList(uaaProvider, samlProvider2),null,email), Matchers.containsInAnyOrder(samlProvider2));
        assertThat(filter.filter(Arrays.asList(uaaProvider, samlProvider2),client,email), Matchers.containsInAnyOrder(samlProvider2));
        assertThat(filter.filter(Arrays.asList(uaaProvider), null, email), Matchers.containsInAnyOrder(uaaProvider));
        assertThat(filter.filter(Arrays.asList(uaaProvider),client,email), Matchers.containsInAnyOrder(uaaProvider));
    }

    @Test
    public void test_no_allowed_client_providers() {
        client.addAdditionalInformation(ALLOWED_PROVIDERS, EMPTY_LIST);
        assertThat(filter.filter(activeProviders,client,email), Matchers.containsInAnyOrder());
    }

    @Test
    public void test_single_positive_email_domain_match() {
        uaaDef.setEmailDomain(null);
        samlDef1.setEmailDomain(EMPTY_LIST);
        samlDef2.setEmailDomain(EMPTY_LIST);
        ldapDef.setEmailDomain(Arrays.asList("test.org"));
        configureTestData();
        assertThat(filter.filter(activeProviders, client, email), Matchers.containsInAnyOrder(ldapProvider));
    }

    @Test
    public void test_multiple_positive_email_domain_matches() {
        uaaDef.setEmailDomain(null);
        samlDef1.setEmailDomain(EMPTY_LIST);
        samlDef2.setEmailDomain(Arrays.asList("test.org","test2.org"));
        ldapDef.setEmailDomain(Arrays.asList("test.org"));
        configureTestData();
        assertThat(filter.filter(activeProviders, client, email), Matchers.containsInAnyOrder(ldapProvider, samlProvider2));
    }

    @Test
    public void test_multiple_positive_email_domain_matches_single_client_allowed_provider() {
        uaaDef.setEmailDomain(null);
        samlDef1.setEmailDomain(EMPTY_LIST);
        samlDef2.setEmailDomain(Arrays.asList("test.org","test2.org"));
        ldapDef.setEmailDomain(Arrays.asList("test.org"));
        client.addAdditionalInformation(ALLOWED_PROVIDERS, Arrays.asList(samlProvider2.getOriginKey()));
        configureTestData();
        assertThat(filter.filter(activeProviders, client, email), Matchers.containsInAnyOrder(samlProvider2));

        client.addAdditionalInformation(ALLOWED_PROVIDERS, Arrays.asList(samlProvider2.getOriginKey(), samlProvider1.getOriginKey()));
        configureTestData();
        assertThat(filter.filter(activeProviders, client, email), Matchers.containsInAnyOrder(samlProvider2));

        client.addAdditionalInformation(ALLOWED_PROVIDERS, Arrays.asList(samlProvider1.getOriginKey()));
        configureTestData();
        assertThat(filter.filter(activeProviders, client, email), Matchers.containsInAnyOrder());
    }

    @Test
    public void test_single_client_allowed_provider() {
        client.addAdditionalInformation(ALLOWED_PROVIDERS, Arrays.asList(ldapProvider.getOriginKey()));
        assertThat(filter.filter(activeProviders, client, email), Matchers.containsInAnyOrder(ldapProvider));
    }

    @Test
    public void test_multiple_client_allowed_providers() {
        client.addAdditionalInformation(ALLOWED_PROVIDERS, Arrays.asList(ldapProvider.getOriginKey(), uaaProvider.getOriginKey()));
        assertThat(filter.filter(activeProviders, client, email), Matchers.containsInAnyOrder(ldapProvider));

        client.addAdditionalInformation(ALLOWED_PROVIDERS, Arrays.asList(ldapProvider.getOriginKey(), samlProvider2.getOriginKey()));
        assertThat(filter.filter(activeProviders, client, email), Matchers.containsInAnyOrder(ldapProvider, samlProvider2));
    }

    @Test
    public void test_uaa_is_catch_all() {
        ldapDef.setEmailDomain(EMPTY_LIST);
        samlDef1.setEmailDomain(EMPTY_LIST);
        samlDef2.setEmailDomain(EMPTY_LIST);
        configureTestData();
        assertThat(filter.filter(activeProviders, client, email), Matchers.containsInAnyOrder(uaaProvider));
    }

    @Test
    public void test_domain_filter_match() {
        assertFalse(filter.doesEmailDomainMatchProvider(uaaProvider, "test.org", true));
        assertTrue(filter.doesEmailDomainMatchProvider(uaaProvider, "test.org", false));
        assertTrue(filter.doesEmailDomainMatchProvider(ldapProvider, "test.org", false));
        assertTrue(filter.doesEmailDomainMatchProvider(ldapProvider, "test.org", true));
        assertTrue(filter.doesEmailDomainMatchProvider(samlProvider1, "test.org", false));
        assertTrue(filter.doesEmailDomainMatchProvider(samlProvider1, "test.org", true));
    }
}
