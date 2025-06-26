/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.saml;

import org.apache.hc.client5.http.ConnectTimeoutException;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdpAlreadyExistsException;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SlowHttpServer;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.web.client.ResourceAccessException;

import java.net.SocketTimeoutException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static java.time.Duration.ofSeconds;
import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class SamlIdentityProviderConfiguratorTests {
    @Mock
    IdentityProviderProvisioning provisioning;

    @Mock
    private FixedHttpMetaDataProvider fixedHttpMetaDataProvider;

    @Mock
    IdentityProvider<SamlIdentityProviderDefinition> idp1;

    @Mock
    IdentityProvider<SamlIdentityProviderDefinition> idp2;

    public static final String singleAddAlias = "sample-alias";
    private SamlIdentityProviderDefinition singleAdd;
    private SlowHttpServer slowHttpServer;
    private SamlIdentityProviderConfigurator configurator;
    private SamlConfiguration samlConfiguration;

    @BeforeAll
    static void beforeAll() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @BeforeEach
    void beforeEach() {
        samlConfiguration = new SamlConfiguration();

        slowHttpServer = new SlowHttpServer();
        singleAdd = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(BootstrapSamlIdentityProviderDataTests.XML_WITHOUT_ID.formatted(new RandomValueStringGenerator().generate()))
                .setIdpEntityAlias(singleAddAlias)
                .setNameID("sample-nameID")
                .setAssertionConsumerIndex(1)
                .setMetadataTrustCheck(true)
                .setLinkText("sample-link-test")
                .setIconUrl("sample-icon-url")
                .setZoneId("uaa");

        fixedHttpMetaDataProvider = mock(FixedHttpMetaDataProvider.class);

        configurator = new SamlIdentityProviderConfigurator(provisioning, new IdentityZoneManagerImpl(), fixedHttpMetaDataProvider);
    }

    @AfterEach
    void afterEach() {
        slowHttpServer.stop();
    }

    @Test
    void addNullProvider() {
        assertThatThrownBy(() -> configurator.validateSamlIdentityProviderDefinition(null, false))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void addNullProviderAlias() {
        singleAdd.setIdpEntityAlias(null);

        assertThatThrownBy(() -> configurator.validateSamlIdentityProviderDefinition(singleAdd, false))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void getEntityID() {
        when(fixedHttpMetaDataProvider.fetchMetadata(any(), anyBoolean())).thenReturn(getSimpleSamlPhpMetadata("http://simplesamlphp.somewhere.com").getBytes());
        BootstrapSamlIdentityProviderData bootstrap = new BootstrapSamlIdentityProviderData(configurator);
        bootstrap.setIdentityProviders(BootstrapSamlIdentityProviderDataTests.parseYaml(BootstrapSamlIdentityProviderDataTests.sampleYaml));
        bootstrap.afterPropertiesSet();
        List<SamlIdentityProviderDefinition> identityProviderDefinitions = bootstrap.getIdentityProviderDefinitions();

        for (SamlIdentityProviderDefinition def : identityProviderDefinitions) {
            switch (def.getIdpEntityAlias()) {
                case "okta-local", "custom-authncontext": {
                    assertThat(def.getIdpEntityId()).isEqualTo("http://www.okta.com/k2lvtem0VAJDMINKEYJW");
                    break;
                }
                case "okta-local-3": {
                    assertThat(def.getIdpEntityId()).isEqualTo("http://www.okta.com/k2lvtem0VAJDMINKEYJX");
                    break;
                }
                case "okta-local-2": {
                    assertThat(def.getIdpEntityId()).isEqualTo("http://www.okta.com/k2lw4l5bPODCMIIDBRYZ");
                    break;
                }
                case "simplesamlphp-url": {
                    RelyingPartyRegistration extendedMetadataDelegate = configurator.getExtendedMetadataDelegate(def);
                    assertThat(extendedMetadataDelegate.getAssertingPartyDetails().getEntityId()).isEqualTo("http://simplesamlphp.somewhere.com/saml2/idp/metadata.php");
                    break;
                }
                default:
                    fail("Unknown provider %s".formatted(def.getIdpEntityAlias()));
            }
        }
    }

    @Test
    void socketFactoryDoesNotGetSet() {
        assertThat(singleAdd.getSocketFactoryClassName()).isNull();
        singleAdd.setSocketFactoryClassName("SHOULD_NOT_SET");
        assertThat(singleAdd.getSocketFactoryClassName()).isNull();
    }

    @Test
    void getEntityIDExists() {
        BootstrapSamlIdentityProviderData bootstrap = new BootstrapSamlIdentityProviderData(configurator);
        bootstrap.setIdentityProviders(BootstrapSamlIdentityProviderDataTests.parseYaml(BootstrapSamlIdentityProviderDataTests.sampleYaml));
        bootstrap.afterPropertiesSet();
        for (SamlIdentityProviderDefinition def : bootstrap.getIdentityProviderDefinitions()) {
            if ("okta-local-2".equalsIgnoreCase(def.getIdpEntityAlias())) {
                when(idp2.getConfig()).thenReturn(def.clone().setIdpEntityAlias("okta-local-1"));
                when(provisioning.retrieveActiveByTypes(anyString(), eq(SAML))).thenReturn(List.of(idp2));
                assertThatThrownBy(() -> configurator.validateSamlIdentityProviderDefinition(def, true))
                        .isInstanceOf(IdpAlreadyExistsException.class)
                        .hasMessageStartingWith("Duplicate entity ID:http://www.okta.com");
            }
        }
    }

    @Test
    void getIdentityProviderDefinitionsForAllowedProviders() {
        List<String> clientIdpAliases = asList("simplesamlphp-url", "okta-local-2");
        String xmlMetadata = getOktaMetadata("http://www.okta.com/k2lw4l5bPODCMIIDBRYZ");

        SamlIdentityProviderDefinition def1 = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(xmlMetadata)
                .setIdpEntityAlias("simplesamlphp-url")
                .setNameID("sample-nameID")
                .setAssertionConsumerIndex(1)
                .setMetadataTrustCheck(true)
                .setLinkText("sample-link-test")
                .setIconUrl("sample-icon-url")
                .setZoneId("other-zone-id");

        when(idp1.getConfig()).thenReturn(def1);
        when(idp2.getConfig()).thenReturn(def1.clone().setIdpEntityAlias("okta-local-2"));
        when(provisioning.retrieveActiveByTypes(anyString(), eq(SAML))).thenReturn(Arrays.asList(idp1, idp2));

        List<SamlIdentityProviderDefinition> clientIdps = configurator.getIdentityProviderDefinitions(clientIdpAliases, new IdentityZoneManagerImpl().getCurrentIdentityZone());
        assertThat(clientIdps).hasSize(2);
        assertThat(clientIdpAliases).contains(clientIdps.getFirst().getIdpEntityAlias(), clientIdps.get(1).getIdpEntityAlias());
    }

    @Test
    void returnNoIdpsInZoneForClientWithNoAllowedProviders() {
        List<String> clientIdpAliases = Collections.singletonList("non-existent");
        String xmlMetadata = getOktaMetadata("http://www.okta.com/k2lw4l5bPODCMIIDBRYZ");

        SamlIdentityProviderDefinition def1 = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(xmlMetadata)
                .setIdpEntityAlias("simplesamlphp-url")
                .setNameID("sample-nameID")
                .setAssertionConsumerIndex(1)
                .setMetadataTrustCheck(true)
                .setLinkText("sample-link-test")
                .setIconUrl("sample-icon-url")
                .setZoneId("other-zone-id");

        when(idp1.getConfig()).thenReturn(def1);
        when(idp2.getConfig()).thenReturn(def1.clone().setIdpEntityAlias("okta-local-2"));
        when(provisioning.retrieveActiveByTypes(anyString(), eq(SAML))).thenReturn(Arrays.asList(idp1, idp2));

        List<SamlIdentityProviderDefinition> clientIdps = configurator.getIdentityProviderDefinitions(clientIdpAliases, new IdentityZoneManagerImpl().getCurrentIdentityZone());
        assertThat(clientIdps).isEmpty();
    }

    FixedHttpMetaDataProvider createNonMockFixedHttpMetaDataProvider(SamlConfiguration samlConfiguration) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        UrlContentCache urlContentCache = samlConfiguration.urlContentCache(samlConfiguration.timeService());

        return samlConfiguration.fixedHttpMetaDataProvider(RestTemplateConfig.createDefaults(), urlContentCache);
    }

    @Test
    void shouldTimeoutOnReadWhenFetchingMetadataURL() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        slowHttpServer.run();
        // set read timeout to value that will cause read timeout before 1s
        samlConfiguration.setSocketReadTimeout(100);
        FixedHttpMetaDataProvider realFixedHttpMetaDataProvider = createNonMockFixedHttpMetaDataProvider(samlConfiguration);
        configurator = new SamlIdentityProviderConfigurator(provisioning, new IdentityZoneManagerImpl(), realFixedHttpMetaDataProvider);

        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setMetaDataLocation(slowHttpServer.getUrl());
        def.setSkipSslValidation(true);

        assertTimeoutPreemptively(ofSeconds(1), () -> assertThatThrownBy(() -> configurator.configureURLMetadata(def))
                .isInstanceOf(ResourceAccessException.class)
                .hasCauseInstanceOf(SocketTimeoutException.class));
    }

    @Test
    void shouldTimeoutOnConnectingWhenFetchingMetadataURL() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        slowHttpServer.run();
        // Set connection timeout to very low value to cause connect timeout
        samlConfiguration.setSocketConnectionTimeout(1);
        fixedHttpMetaDataProvider = createNonMockFixedHttpMetaDataProvider(samlConfiguration);
        configurator = new SamlIdentityProviderConfigurator(provisioning, new IdentityZoneManagerImpl(), fixedHttpMetaDataProvider);

        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setMetaDataLocation("http://10.255.255.1/something");
        def.setSkipSslValidation(true);

        assertTimeoutPreemptively(
                ofSeconds(1),
                () -> assertThatThrownBy(() -> configurator.configureURLMetadata(def))
                    .isInstanceOf(ResourceAccessException.class)
                    .hasCauseInstanceOf(ConnectTimeoutException.class)
        );
    }

    private String getSimpleSamlPhpMetadata(String domain) {
        // %1$s gets replaced with the domain
        return """
                <?xml version="1.0"?>
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="%1$s/saml2/idp/metadata.php" ID="pfx214e4cdb-8fb2-592d-27a1-32ff06dcda69"><ds:Signature>
                  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                  <ds:Reference URI="#pfx214e4cdb-8fb2-592d-27a1-32ff06dcda69"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>+sYzzLx/5TXtBZhC03uaQT0E/L8=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>gt9z/i8o16H0KQfV8+gCLgrBYOgaWsQe1Bon3G3UJQqc+z7YTNXl6rX69wbcQum/95KiLcF41BHoCeA4KZL75HE6mpXAF8NrPZiXlwwJFZe31HIfwmeu7JavuB/8QotWraM/u9DGtHVfDWFT92MPr18Odbvl62Gd2zA2PdZR3rz7DsrFc1QSB/Qz1VnQ+3Y8OUBRFDeZZUsNGRJ/l/GfYkiqmyV4fOak6bz0WeCSxY3tOl+F9X8r2gOHxOp3QRtRaK/UElRmPxnYC7UESI0Rq0AphHO6vRulA/EpSXTwu4qgZ6nDtGBOW/C+nQmg8zkv0QPvzk5IE2eaAAE3jkZq4w==</ds:SignatureValue>
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
                    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%1$s/saml2/idp/ SingleLogoutService.php"/>
                    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
                    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%1$s/saml2/idp/SSOService.php"/>
                  </md:IDPSSODescriptor>
                  <md:ContactPerson contactType="technical">
                    <md:GivenName>Filip</md:GivenName>
                    <md:SurName>Hanik</md:SurName>
                    <md:EmailAddress>fhanik@pivotal.io</md:EmailAddress>
                  </md:ContactPerson>
                </md:EntityDescriptor>
                """.formatted(domain);
    }

    private String getOktaMetadata(String entityId) {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
                    <md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                        <md:KeyDescriptor use="signing">
                            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                                <ds:X509Data>
                                    <ds:X509Certificate>MIICmTCCAgKgAwIBAgIGAUPATqmEMA0GCSqGSIb3DQEBBQUAMIGPMQswCQYDVQQGEwJVUzETMBEG
                                    A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
                                    MBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMMB1Bpdm90YWwxHDAaBgkqhkiG9w0BCQEWDWlu
                                    Zm9Ab2t0YS5jb20wHhcNMTQwMTIzMTgxMjM3WhcNNDQwMTIzMTgxMzM3WjCBjzELMAkGA1UEBhMC
                                    VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoM
                                    BE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdQaXZvdGFsMRwwGgYJKoZIhvcN
                                    AQkBFg1pbmZvQG9rdGEuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeil67/TLOiTZU
                                    WWgW2XEGgFZ94bVO90v5J1XmcHMwL8v5Z/8qjdZLpGdwI7Ph0CyXMMNklpaR/Ljb8fsls3amdT5O
                                    Bw92Zo8ulcpjw2wuezTwL0eC0wY/GQDAZiXL59npE6U+fH1lbJIq92hx0HJSru/0O1q3+A/+jjZL
                                    3tL/SwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAI5BoWZoH6Mz9vhypZPOJCEKa/K+biZQsA4Zqsuk
                                    vvphhSERhqk/Nv76Vkl8uvJwwHbQrR9KJx4L3PRkGCG24rix71jEuXVGZUsDNM3CUKnARx4MEab6
                                    GFHNkZ6DmoT/PFagngecHu+EwmuDtaG0rEkFrARwe+d8Ru0BN558abFb</ds:X509Certificate>
                                </ds:X509Data>
                            </ds:KeyInfo>
                        </md:KeyDescriptor>
                        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
                        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://pivotal.oktapreview.com/app/pivotal_pivotalcfstaging_1/k2lw4l5bPODCMIIDBRYZ/sso/saml"/>
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://pivotal.oktapreview.com/app/pivotal_pivotalcfstaging_1/k2lw4l5bPODCMIIDBRYZ/sso/saml"/>
                    </md:IDPSSODescriptor>
                </md:EntityDescriptor>
                """.formatted(entityId);
    }
}
