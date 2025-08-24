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

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.ALLOWED_PROVIDERS;

class DomainFilterTest {

    private static final String ALIAS = "saml";

    private static final String IDP_META_DATA = """
            <?xml version="1.0"?>
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="http://%1$s.cfapps.io/saml2/idp/metadata.php" ID="pfx06ad4153-c17c-d286-194c-dec30bb92796"><ds:Signature>
              <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
              <ds:Reference URI="#pfx06ad4153-c17c-d286-194c-dec30bb92796"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>begl1WVCsXSn7iHixtWPP8d/X+k=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>BmbKqA3A0oSLcn5jImz/l5WbpVXj+8JIpT/ENWjOjSd/gcAsZm1QvYg+RxYPBk+iV2bBxD+/yAE/w0wibsHrl0u9eDhoMRUJBUSmeyuN1lYzBuoVa08PdAGtb5cGm4DMQT5Rzakb1P0hhEPPEDDHgTTxop89LUu6xx97t2Q03Khy8mXEmBmNt2NlFxJPNt0FwHqLKOHRKBOE/+BpswlBocjOQKFsI9tG3TyjFC68mM2jo0fpUQCgj5ZfhzolvS7z7c6V201d9Tqig0/mMFFJLTN8WuZPavw22AJlMjsDY9my+4R9HKhK5U53DhcTeECs9fb4gd7p5BJy4vVp7tqqOg==</ds:SignatureValue>
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
                <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://%1$s.cfapps.io/saml2/idp/SingleLogoutService.php"/>
                <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
                <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://%1$s.cfapps.io/saml2/idp/SSOService.php"/>
              </md:IDPSSODescriptor>
              <md:ContactPerson contactType="technical">
                <md:GivenName>Filip</md:GivenName>
                <md:SurName>Hanik</md:SurName>
                <md:EmailAddress>fhanik@pivotal.io</md:EmailAddress>
              </md:ContactPerson>
            </md:EntityDescriptor>""".formatted(ALIAS);

    UaaClientDetails client;
    List<IdentityProvider> activeProviders = emptyList();
    IdentityProvider uaaProvider;
    IdentityProvider ldapProvider;
    IdentityProvider samlProvider1;
    IdentityProvider samlProvider2;
    IdentityProvider loginServerProvider;

    String email = "test@test.org";
    private UaaIdentityProviderDefinition uaaDef;
    private LdapIdentityProviderDefinition ldapDef;
    private SamlIdentityProviderDefinition samlDef1;
    private SamlIdentityProviderDefinition samlDef2;

    @BeforeEach
    void setUp() {
        client = new UaaClientDetails("clientid", "", "", "", "", "");
        uaaDef = new UaaIdentityProviderDefinition(null, null);
        ldapDef = new LdapIdentityProviderDefinition();
        samlDef1 = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(IDP_META_DATA)
                .setIdpEntityAlias("")
                .setNameID("")
                .setMetadataTrustCheck(true)
                .setLinkText("")
                .setIconUrl("")
                .setZoneId(IdentityZone.getUaaZoneId());
        samlDef2 = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(IDP_META_DATA)
                .setIdpEntityAlias("")
                .setNameID("")
                .setMetadataTrustCheck(true)
                .setLinkText("")
                .setIconUrl("")
                .setZoneId(IdentityZone.getUaaZoneId());
        configureTestData();
    }

    private void configureTestData() {
        uaaProvider = new IdentityProvider().setActive(true).setType(OriginKeys.UAA).setOriginKey(OriginKeys.UAA).setConfig(uaaDef);
        ldapProvider = new IdentityProvider().setActive(true).setType(OriginKeys.LDAP).setOriginKey(OriginKeys.LDAP).setConfig(ldapDef);
        samlProvider1 = new IdentityProvider().setActive(true).setType(OriginKeys.SAML).setOriginKey("saml1").setConfig(samlDef1);
        samlProvider2 = new IdentityProvider().setActive(true).setType(OriginKeys.SAML).setOriginKey("saml2").setConfig(samlDef2);
        loginServerProvider = new IdentityProvider().setActive(true).setType(LOGIN_SERVER).setOriginKey(LOGIN_SERVER);
        activeProviders = Arrays.asList(uaaProvider, ldapProvider, samlProvider1, samlProvider2, loginServerProvider);
    }

    @Test
    void null_arguments() {
        assertThat(DomainFilter.filter(null, null, null)).containsExactlyInAnyOrder();
        assertThat(DomainFilter.filter(null, null, email)).containsExactlyInAnyOrder();
        assertThat(DomainFilter.filter(null, client, null)).containsExactlyInAnyOrder();
        assertThat(DomainFilter.filter(null, client, email)).containsExactlyInAnyOrder();
        assertThat(DomainFilter.filter(activeProviders, null, null)).containsExactlyInAnyOrder();
        assertThat(DomainFilter.filter(activeProviders, client, null)).containsExactlyInAnyOrder();
        assertThat(DomainFilter.filter(activeProviders, client, email)).containsExactlyInAnyOrder(uaaProvider);
    }

    @Test
    void default_idp_and_client_setup() {
        assertThat(DomainFilter.filter(activeProviders, null, email)).containsExactlyInAnyOrder(uaaProvider);
        assertThat(DomainFilter.filter(activeProviders, client, email)).containsExactlyInAnyOrder(uaaProvider);
        assertThat(DomainFilter.filter(Collections.singletonList(ldapProvider), null, email)).containsExactlyInAnyOrder();
        assertThat(DomainFilter.filter(Collections.singletonList(ldapProvider), client, email)).containsExactlyInAnyOrder();
        assertThat(DomainFilter.filter(Arrays.asList(uaaProvider, samlProvider2), null, email)).containsExactlyInAnyOrder(uaaProvider);
        assertThat(DomainFilter.filter(Arrays.asList(uaaProvider, samlProvider2), client, email)).containsExactlyInAnyOrder(uaaProvider);
        assertThat(DomainFilter.filter(Collections.singletonList(uaaProvider), null, email)).containsExactlyInAnyOrder(uaaProvider);
        assertThat(DomainFilter.filter(Collections.singletonList(uaaProvider), client, email)).containsExactlyInAnyOrder(uaaProvider);
    }

    @Test
    void no_allowed_client_providers() {
        client.addAdditionalInformation(ALLOWED_PROVIDERS, emptyList());
        assertThat(DomainFilter.filter(activeProviders, client, email)).containsExactlyInAnyOrder();
    }

    @Test
    void single_positive_email_domain_match() {
        uaaDef.setEmailDomain(null);
        samlDef1.setEmailDomain(emptyList());
        samlDef2.setEmailDomain(emptyList());
        ldapDef.setEmailDomain(Collections.singletonList("test.org"));
        configureTestData();
        assertThat(DomainFilter.filter(activeProviders, client, email)).containsExactlyInAnyOrder(ldapProvider);
        assertThat(DomainFilter.filter(activeProviders, client, "some@other.domain")).containsExactlyInAnyOrder(uaaProvider);
    }

    @Test
    void multiple_positive_email_domain_matches() {
        uaaDef.setEmailDomain(null);
        samlDef1.setEmailDomain(emptyList());
        samlDef2.setEmailDomain(Arrays.asList("test.org", "test2.org"));
        ldapDef.setEmailDomain(Collections.singletonList("test.org"));
        configureTestData();
        assertThat(DomainFilter.filter(activeProviders, client, email)).containsExactlyInAnyOrder(ldapProvider, samlProvider2);
    }

    @Test
    void multiple_positive_email_domain_matches_wildcard() {
        uaaDef.setEmailDomain(null);
        samlDef1.setEmailDomain(emptyList());
        samlDef2.setEmailDomain(Collections.singletonList("*.org"));
        ldapDef.setEmailDomain(Collections.singletonList("*.org"));
        configureTestData();
        assertThat(DomainFilter.filter(activeProviders, client, email)).containsExactlyInAnyOrder(ldapProvider, samlProvider2);
    }

    @Test
    void multiple_positive_long_email_domain_matches_wildcard() {
        uaaDef.setEmailDomain(null);
        samlDef1.setEmailDomain(emptyList());
        samlDef2.setEmailDomain(Collections.singletonList("*.*.*.com"));
        ldapDef.setEmailDomain(Collections.singletonList("*.*.test2.com"));
        configureTestData();
        assertThat(DomainFilter.filter(activeProviders, client, "user@test.test1.test2.com")).containsExactlyInAnyOrder(ldapProvider, samlProvider2);
    }

    @Test
    void multiple_positive_email_domain_matches_single_client_allowed_provider() {
        uaaDef.setEmailDomain(null);
        samlDef1.setEmailDomain(emptyList());
        samlDef2.setEmailDomain(Arrays.asList("test.org", "test2.org"));
        ldapDef.setEmailDomain(Collections.singletonList("test.org"));
        client.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(samlProvider2.getOriginKey()));
        configureTestData();
        assertThat(DomainFilter.filter(activeProviders, client, email)).containsExactlyInAnyOrder(samlProvider2);

        client.addAdditionalInformation(ALLOWED_PROVIDERS, Arrays.asList(samlProvider2.getOriginKey(), samlProvider1.getOriginKey()));
        configureTestData();
        assertThat(DomainFilter.filter(activeProviders, client, email)).containsExactlyInAnyOrder(samlProvider2);

        client.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(samlProvider1.getOriginKey()));
        configureTestData();
        assertThat(DomainFilter.filter(activeProviders, client, email)).containsExactlyInAnyOrder();
    }

    @Test
    void single_client_allowed_provider() {
        client.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(ldapProvider.getOriginKey()));
        assertThat(DomainFilter.filter(activeProviders, client, email)).containsExactlyInAnyOrder();

        ldapDef.setEmailDomain(Collections.singletonList("test.org"));
        configureTestData();
        assertThat(DomainFilter.filter(activeProviders, client, email)).containsExactlyInAnyOrder(ldapProvider);
    }

    @Test
    void multiple_client_allowed_providers() {
        client.addAdditionalInformation(ALLOWED_PROVIDERS, Arrays.asList(ldapProvider.getOriginKey(), uaaProvider.getOriginKey()));
        assertThat(DomainFilter.filter(activeProviders, client, email)).containsExactlyInAnyOrder(uaaProvider);

        client.addAdditionalInformation(ALLOWED_PROVIDERS, Arrays.asList(ldapProvider.getOriginKey(), samlProvider2.getOriginKey()));
        assertThat(DomainFilter.filter(activeProviders, client, email)).containsExactlyInAnyOrder();

        ldapDef.setEmailDomain(Collections.singletonList("test.org"));
        configureTestData();
        client.addAdditionalInformation(ALLOWED_PROVIDERS, Arrays.asList(ldapProvider.getOriginKey(), uaaProvider.getOriginKey()));
        assertThat(DomainFilter.filter(activeProviders, client, email)).containsExactlyInAnyOrder(ldapProvider);

    }

    @Test
    void uaa_is_catch_all() {
        ldapDef.setEmailDomain(emptyList());
        samlDef1.setEmailDomain(emptyList());
        samlDef2.setEmailDomain(emptyList());
        configureTestData();
        assertThat(DomainFilter.filter(activeProviders, client, email)).containsExactlyInAnyOrder(uaaProvider);
    }

    @Test
    void uaa_is_not_catch_all_without_fallback() {
        ldapDef.setEmailDomain(emptyList());
        samlDef1.setEmailDomain(emptyList());
        samlDef2.setEmailDomain(emptyList());
        configureTestData();
        assertThat(DomainFilter.filter(activeProviders, client, email, false)).doesNotContain(uaaProvider);
    }

    @Test
    void uaa_is_catch_all_with_null_email_domain_list() {
        ldapDef.setEmailDomain(null);
        samlDef1.setEmailDomain(null);
        samlDef2.setEmailDomain(null);
        configureTestData();
        assertThat(DomainFilter.filter(activeProviders, client, email)).containsExactlyInAnyOrder(uaaProvider);
    }

    @Test
    void domain_filter_match() {
        assertThat(DomainFilter.doesEmailDomainMatchProvider(uaaProvider, "test.org", true)).isFalse();
        assertThat(DomainFilter.doesEmailDomainMatchProvider(uaaProvider, "test.org", false)).isTrue();
        assertThat(DomainFilter.doesEmailDomainMatchProvider(ldapProvider, "test.org", false)).isFalse();
        assertThat(DomainFilter.doesEmailDomainMatchProvider(ldapProvider, "test.org", true)).isFalse();
        assertThat(DomainFilter.doesEmailDomainMatchProvider(samlProvider1, "test.org", false)).isFalse();
        assertThat(DomainFilter.doesEmailDomainMatchProvider(samlProvider1, "test.org", true)).isFalse();
    }

    @Test
    void ipds_for_email_domain() {
        samlProvider1.getConfig().setEmailDomain(Collections.singletonList("test.org"));
        samlProvider2.getConfig().setEmailDomain(Collections.singletonList("test.org"));

        List<IdentityProvider> idpsForEmailDomain = DomainFilter.getIdpsForEmailDomain(activeProviders, "abc@test.org");

        assertThat(idpsForEmailDomain).hasSize(2)
                .containsExactlyInAnyOrder(samlProvider1, samlProvider2);
    }

    @Test
    void idp_with_wildcard_for_email_domain() {
        samlProvider1.getConfig().setEmailDomain(Collections.singletonList("t*.org"));

        List<IdentityProvider> idpsForEmailDomain = DomainFilter.getIdpsForEmailDomain(activeProviders, "abc@test.org");

        assertThat(idpsForEmailDomain).hasSize(1)
                .containsExactlyInAnyOrder(samlProvider1);
    }

    @Test
    void idp_with_no_matching_email_domain() {
        samlDef1.setEmailDomain(Collections.singletonList("example.org"));
        List<IdentityProvider> idpsForEmailDomain = DomainFilter.getIdpsForEmailDomain(activeProviders, "abc@test.org");
        assertThat(idpsForEmailDomain).isEmpty();
    }
}
