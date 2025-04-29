package org.cloudfoundry.identity.uaa.mock.saml;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;

import java.net.URI;

import static org.hamcrest.Matchers.containsString;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_DIGEST_SHA256;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
import static org.springframework.http.HttpHeaders.HOST;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

@DefaultTestContext
class SamlMetadataEndpointMockMvcTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Test
    void samlMetadataRootNoEndingSlash() throws Exception {
        mockMvc.perform(get(new URI("/saml/metadata")))
                .andExpect(status().isOk());
    }

    @Test
    void samlMetadataRootWithEndingSlash() throws Exception {
        mockMvc.perform(get(new URI("/saml/metadata/")))
                .andExpect(status().isOk());
    }

    @Test
    void samlMetadataDefaultNoEndingSlash() throws Exception {
        mockMvc.perform(get(new URI("/saml/metadata/example")))
                .andExpect(status().is4xxClientError());
    }

    @Test
    void samlMetadataDefaultWithEndingSlash() throws Exception {
        mockMvc.perform(get(new URI("/saml/metadata/example/")))
                .andDo(print())
                .andExpect(status().is4xxClientError());
    }

    @Test
    void samlMetadataXMLValidation() throws Exception {

        mockMvc.perform(get(new URI("/saml/metadata")))
                .andDo(print())
                .andExpectAll(
                        status().isOk(),
                        header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("filename=\"saml-sp.xml\";")),
                        xpath("/EntityDescriptor/@entityID").string("integration-saml-entity-id"), // matches UAA config login.entityID
                        xpath("/EntityDescriptor/SPSSODescriptor/@AuthnRequestsSigned").booleanValue(true), // matches UAA config login.saml.signRequest
                        xpath("/EntityDescriptor/SPSSODescriptor/@WantAssertionsSigned").booleanValue(true), // matches UAA config login.saml.wantAssertionSigned
                        xpath("/EntityDescriptor/SPSSODescriptor/NameIDFormat").string("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),  // matches UAA config login.saml.NameID
                        xpath("/EntityDescriptor/SPSSODescriptor/KeyDescriptor[@use='signing']/KeyInfo/X509Data/X509Certificate").string("MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="),
                        xpath("/EntityDescriptor/SPSSODescriptor/KeyDescriptor[@use='encryption']/KeyInfo/X509Data/X509Certificate").string("MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="),
                        xpath("/EntityDescriptor/SPSSODescriptor/AssertionConsumerService/@Location")
                                .string(containsString("/saml/SSO/alias/integration-saml-entity-id")), // last path is the UAA-wide entity ID alias, set by login.saml.entityIDAlias; is not set, fall back to login.entityID
                        xpath("/EntityDescriptor/Signature").exists(),
                        xpath("/EntityDescriptor/Signature/SignedInfo/SignatureMethod/@Algorithm").string(containsString(ALGO_ID_SIGNATURE_RSA_SHA256)),
                        xpath("/EntityDescriptor/Signature/SignatureValue").exists(),
                        xpath("/EntityDescriptor/Signature/SignedInfo/Reference/DigestValue").exists(),
                        xpath("/EntityDescriptor/Signature/SignedInfo/Reference/DigestMethod/@Algorithm").string(containsString(ALGO_ID_DIGEST_SHA256))
                );
    }

    @Test
    void nonDefaultZoneSamlMetadataXMLValidation() throws Exception {
        IdentityZone spZone = setupIdentityZone(true);
        String subdomain = spZone.getSubdomain();

        mockMvc.perform(get(new URI("/saml/metadata"))
                        .header(HOST, subdomain + ".localhost:8080"))
                .andDo(print())
                .andExpectAll(
                        status().isOk(),
                        header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("filename=\"saml-%s-sp.xml\";".formatted(subdomain))),
                        xpath("/EntityDescriptor/@entityID").string(spZone.getConfig().getSamlConfig().getEntityID()), // matches zone config samlConfig.entityID, or fall back on UAA config login.entityID
                        xpath("/EntityDescriptor/SPSSODescriptor/@AuthnRequestsSigned").booleanValue(false), // matches zone config samlConfig.requestSigned
                        xpath("/EntityDescriptor/SPSSODescriptor/@WantAssertionsSigned").booleanValue(false), // matches zone config samlConfig.wantAssertionSigned
                        xpath("/EntityDescriptor/SPSSODescriptor/NameIDFormat").string("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),  // matches UAA config login.saml.NameID???
                        xpath("/EntityDescriptor/SPSSODescriptor/KeyDescriptor[@use='signing']/KeyInfo/X509Data/X509Certificate").string("MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="),
                        xpath("/EntityDescriptor/SPSSODescriptor/KeyDescriptor[@use='encryption']/KeyInfo/X509Data/X509Certificate").string("MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="),
                        xpath("/EntityDescriptor/SPSSODescriptor/AssertionConsumerService/@Location").string(containsString("/saml/SSO/alias/%s.integration-saml-entity-id".formatted(subdomain))) // this needs to be: /saml/SSO/alias/[zone-subdomain].[UAA-wide SAML entity ID, aka UAA.yml's login.saml.entityIDAlias, or fall back on login.entityID in this case]
                );
    }

    @Nested
    @DefaultTestContext
    @TestPropertySource(properties = {"login.saml.signRequest = false",
            "login.saml.signMetaData=false",
            "login.saml.wantAssertionSigned = false",
            "login.saml.entityIDAlias = integration-saml-entity-id-alias"})
    class SamlMetadataAlternativeConfigsMockMvcTests {
        @Autowired
        private MockMvc mockMvc;

        @Test
        void samlMetadataXMLValidation() throws Exception {

            mockMvc.perform(get(new URI("/saml/metadata")))
                    .andDo(print())
                    .andExpectAll(
                            status().isOk(),
                            header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("filename=\"saml-sp.xml\";")),
                            xpath("/EntityDescriptor/@entityID").string("integration-saml-entity-id"), // matches UAA config login.entityID
                            xpath("/EntityDescriptor/SPSSODescriptor/@AuthnRequestsSigned").booleanValue(false), // matches UAA config login.saml.signRequest
                            xpath("/EntityDescriptor/SPSSODescriptor/@WantAssertionsSigned").booleanValue(false), // matches UAA config login.saml.wantAssertionSigned
                            xpath("/EntityDescriptor/SPSSODescriptor/AssertionConsumerService/@Location").string(containsString("/saml/SSO/alias/integration-saml-entity-id-alias")), // path contains login.saml.entityIDAlias
                            xpath("/EntityDescriptor/SPSSODescriptor/Signature").doesNotExist() // login.saml.sign-meta-data=false
                    );
        }

        @Test
        void nonDefaultZoneSamlMetadataXMLValidation() throws Exception {
            IdentityZone spZone = setupIdentityZone(true);
            String subdomain = spZone.getSubdomain();

            mockMvc.perform(get(new URI("/saml/metadata"))
                            .header(HOST, subdomain + ".localhost:8080"))
                    .andDo(print())
                    .andExpectAll(
                            status().isOk(),
                            header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("filename=\"saml-%s-sp.xml\";".formatted(subdomain))),
                            xpath("/EntityDescriptor/@entityID").string(spZone.getConfig().getSamlConfig().getEntityID()), // matches zone config samlConfig.entityID, or fall back on UAA config login.entityID
                            xpath("/EntityDescriptor/SPSSODescriptor/@AuthnRequestsSigned").booleanValue(false), // matches zone config samlConfig.requestSigned
                            xpath("/EntityDescriptor/SPSSODescriptor/@WantAssertionsSigned").booleanValue(false), // matches zone config samlConfig.wantAssertionSigned
                            xpath("/EntityDescriptor/SPSSODescriptor/NameIDFormat").string("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),  // matches UAA config login.saml.NameID???
                            xpath("/EntityDescriptor/SPSSODescriptor/KeyDescriptor[@use='signing']/KeyInfo/X509Data/X509Certificate").string("MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="),
                            xpath("/EntityDescriptor/SPSSODescriptor/KeyDescriptor[@use='encryption']/KeyInfo/X509Data/X509Certificate").string("MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="),
                            xpath("/EntityDescriptor/SPSSODescriptor/AssertionConsumerService/@Location").string(containsString("/saml/SSO/alias/%s.integration-saml-entity-id-alias".formatted(subdomain))), // this needs to be: /saml/SSO/alias/[zone-subdomain].[UAA-wide SAML entity ID, aka UAA.yml's login.saml.entityIDAlias, or fall back on login.entityID]
                            xpath("/EntityDescriptor/Signature").doesNotExist() // No signature with login.saml.sign-meta-data=false
                    );
        }

        @Test
        void nonDefaultZoneSamlMetadataXMLValidationZoneSamlEntityIDNotSet() throws Exception {
            IdentityZone alternativeSpZone = setupIdentityZone(false);
            String zoneSubdomain = alternativeSpZone.getSubdomain();

            mockMvc.perform(get(new URI("/saml/metadata"))
                            .header(HOST, zoneSubdomain + ".localhost:8080"))
                    .andDo(print())
                    .andExpectAll(
                            status().isOk(),
                            header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("filename=\"saml-%s-sp.xml\";".formatted(zoneSubdomain))),
                            xpath("/EntityDescriptor/@entityID").string("%s.integration-saml-entity-id".formatted(zoneSubdomain)), // matches zone config samlConfig.entityID, or fall back on UAA config login.entityID
                            xpath("/EntityDescriptor/SPSSODescriptor/@AuthnRequestsSigned").booleanValue(false), // matches zone config samlConfig.requestSigned
                            xpath("/EntityDescriptor/SPSSODescriptor/@WantAssertionsSigned").booleanValue(false), // matches zone config samlConfig.wantAssertionSigned
                            xpath("/EntityDescriptor/SPSSODescriptor/NameIDFormat").string("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),  // matches UAA config login.saml.NameID???
                            xpath("/EntityDescriptor/SPSSODescriptor/KeyDescriptor[@use='signing']/KeyInfo/X509Data/X509Certificate").string("MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="),
                            xpath("/EntityDescriptor/SPSSODescriptor/KeyDescriptor[@use='encryption']/KeyInfo/X509Data/X509Certificate").string("MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="),
                            xpath("/EntityDescriptor/SPSSODescriptor/AssertionConsumerService/@Location").string(containsString("/saml/SSO/alias/%s.integration-saml-entity-id-alias".formatted(zoneSubdomain))), // this needs to be: /saml/SSO/alias/[zone-subdomain].[UAA-wide SAML entity ID, aka UAA.yml's login.saml.entityIDAlias, or fall back on login.entityID]
                            xpath("/EntityDescriptor/Signature").doesNotExist() // No signature with login.saml.sign-meta-data=false
                    );
        }
    }

    private IdentityZone setupIdentityZone(boolean hasEntityId) throws Exception {
        UaaClientDetails adminClient = new UaaClientDetails("admin", "", "", "client_credentials", "uaa.admin");
        adminClient.setClientSecret("adminsecret");

        RandomValueStringGenerator generator = new RandomValueStringGenerator();
        String zoneSubdomain = "testzone-" + generator.generate();
        String entityId = hasEntityId ? zoneSubdomain + "-entity-id" : null;
        return createZone(zoneSubdomain, adminClient, false, false, entityId);
    }

    private IdentityZone createZone(String zoneSubdomain, UaaClientDetails adminClient, Boolean samlRequestSigned, Boolean samlWantAssertionSigned, String samlZoneEntityID) throws Exception {
        IdentityZone identityZone = MultitenancyFixture.identityZone(zoneSubdomain, zoneSubdomain);
        identityZone.getConfig().getSamlConfig().setRequestSigned(samlRequestSigned);
        identityZone.getConfig().getSamlConfig().setWantAssertionSigned(samlWantAssertionSigned);
        identityZone.getConfig().getSamlConfig().setEntityID(samlZoneEntityID);
        return MockMvcUtils.createOtherIdentityZoneAndReturnResult(mockMvc, webApplicationContext, adminClient, identityZone, true, IdentityZoneHolder.getCurrentZoneId()).getIdentityZone();
    }
}
