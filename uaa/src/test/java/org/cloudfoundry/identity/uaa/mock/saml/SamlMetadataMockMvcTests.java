package org.cloudfoundry.identity.uaa.mock.saml;

import java.net.URI;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DefaultTestContext
class SamlMetadataMockMvcTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void testSamlMetadataRootNoEndingSlash() throws Exception {
        mockMvc.perform(get(new URI("/saml/metadata")))
                .andExpect(status().isOk());
    }

    @Test
    void testSamlMetadataRootWithEndingSlash() throws Exception {
        mockMvc.perform(get(new URI("/saml/metadata/")))
                .andExpect(status().isOk());
    }

    @Test
    void testSamlMetadataDefaultNoEndingSlash() throws Exception {
        mockMvc.perform(get(new URI("/saml/metadata/example")))
                .andExpect(status().isOk());
    }

    @Test
    void testSamlMetadataDefaultWithEndingSlash() throws Exception {
        mockMvc.perform(get(new URI("/saml/metadata/example/")))
                .andExpect(status().isOk());
    }

    @Test
    void testSamlMetadataXMLValidation() throws Exception {

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
                        xpath("/EntityDescriptor/SPSSODescriptor/KeyDescriptor[@use='encryption']/KeyInfo/X509Data/X509Certificate").string("MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=")
                );
    }

    @Nested
    @DefaultTestContext
    @TestPropertySource(properties = {"login.saml.signRequest = false", "login.saml.wantAssertionSigned = false"})
    class SamlMetadataAlternativeConfigsMockMvcTests {
        @Autowired
        private MockMvc mockMvc;

        @Test
        void testSamlMetadataAuthnRequestsSignedIsFalse() throws Exception {
            mockMvc.perform(get(new URI("/saml/metadata")))
                    .andDo(print())
                    .andExpectAll(
                            status().isOk(),
                            header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("filename=\"saml-sp.xml\";")),
                            xpath("/EntityDescriptor/SPSSODescriptor/@AuthnRequestsSigned").booleanValue(false), // matches UAA config login.saml.signRequest
                            xpath("/EntityDescriptor/SPSSODescriptor/@WantAssertionsSigned").booleanValue(false) // matches UAA config login.saml.wantAssertionSigned
                    );
        }
    }
}