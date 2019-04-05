package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Assert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
abstract class BaseSamlServiceProviderEndpointsMockMvcTests {

    private final boolean zoneSwitching;

    private String adminToken;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator(10);
    private String requestBody;
    private String spsWriteToken;
    private IdentityZone zone;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    BaseSamlServiceProviderEndpointsMockMvcTests(boolean zoneSwitching) {
        this.zoneSwitching = zoneSwitching;
    }

    @BeforeEach
    void setup() throws Exception {
        adminToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", "uaa.admin", null);
        String clientId = generator.generate().toLowerCase();
        String clientSecret = generator.generate().toLowerCase();

        zone = zoneSwitching ? MockMvcUtils.createOtherIdentityZone(generator.generate().toLowerCase(), mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId()) : IdentityZone.getUaa();
        String scope = zoneSwitching ? "zones." + zone.getId() + ".sps.write" : "sps.write";
        MockMvcUtils.createClient(this.mockMvc, adminToken, clientId, clientSecret, null, null, Arrays.asList("client_credentials", "password"), scope);

        spsWriteToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, clientId, clientSecret, scope, null);

        String name = generator.generate();
        requestBody = "{\n" +
                "  \"name\" : \"" + name + "\",\n" +
                "  \"entityId\" : \"" + name + ".cloudfoundry-saml-login\",\n" +
                "  \"active\" : true,\n" +
                "  \"config\" : \"{\\\"metaDataLocation\\\" : \\\"<?xml version=\\\\\\\"1.0\\\\\\\" encoding=\\\\\\\"UTF-8\\\\\\\"?><md:EntityDescriptor xmlns:md=\\\\\\\"urn:oasis:names:tc:SAML:2.0:metadata\\\\\\\" ID=\\\\\\\"" + name + ".cloudfoundry-saml-login\\\\\\\" entityID=\\\\\\\"" + name + ".cloudfoundry-saml-login\\\\\\\"><ds:Signature xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\\\\\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\\\\\"/><ds:SignatureMethod Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\\\\\\\"/><ds:Reference URI=\\\\\\\"#" + name + ".cloudfoundry-saml-login\\\\\\\"><ds:Transforms><ds:Transform Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\\\\\\\"/><ds:Transform Algorithm=\\\\\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\\\\\"/></ds:Transforms><ds:DigestMethod Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#sha1\\\\\\\"/><ds:DigestValue>zALgjEFJ7jJSwn2AOBH5H8CX93U=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Rp5XH8eT0ek/vlFGzHgIFOeESchOwSYZ9oh4JA9WqQ0jJtvNQ9IttY2QY9XK3n6TbbtPcEKVgljyTfwD5ymp+oMKfIYQC9JsN8mPADN5rjLFgC+xGceWLbcjoNsCJ7x2ZjyWRblSxoOU5qnzxEA3k3Bu+OkV+ZXcSbmgMWoQACg=</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:SPSSODescriptor AuthnRequestsSigned=\\\\\\\"true\\\\\\\" WantAssertionsSigned=\\\\\\\"true\\\\\\\" protocolSupportEnumeration=\\\\\\\"urn:oasis:names:tc:SAML:2.0:protocol\\\\\\\"><md:KeyDescriptor use=\\\\\\\"signing\\\\\\\"><ds:KeyInfo xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\\\\\\\"encryption\\\\\\\"><ds:KeyInfo xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SingleLogout/alias/" + name + ".cloudfoundry-saml-login\\\\\\\"/><md:SingleLogoutService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SingleLogout/alias/" + name + ".cloudfoundry-saml-login\\\\\\\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</md:NameIDFormat><md:AssertionConsumerService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SSO/alias/" + name + ".cloudfoundry-saml-login\\\\\\\" index=\\\\\\\"0\\\\\\\" isDefault=\\\\\\\"true\\\\\\\"/></md:SPSSODescriptor></md:EntityDescriptor>\\\",\\\"metadataTrustCheck\\\" : true }\"" +
                "}";
    }

    @Test
    void deleteServiceProvider() throws Exception {
        MockHttpServletRequestBuilder post = post("/saml/service-providers")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(APPLICATION_JSON)
                .content(requestBody);
        MockHttpServletResponse createdResponse = perform(
                mockMvc,
                zoneSwitching,
                zone,
                post
        ).andReturn().getResponse();
        SamlServiceProvider samlServiceProvider = JsonUtils.readValue(createdResponse.getContentAsString(), SamlServiceProvider.class);

        assertNotNull(samlServiceProvider);
        MockHttpServletRequestBuilder delete = delete("/saml/service-providers/{id}", samlServiceProvider.getId())
                .header("Authorization", "Bearer " + spsWriteToken)
                .accept(APPLICATION_JSON);
        MockHttpServletResponse deletedResponse = perform(
                mockMvc,
                zoneSwitching,
                zone,
                delete)
                .andExpect(status().isOk())
                .andReturn().getResponse();

        SamlServiceProvider deletedServiceProvider = JsonUtils.readValue(deletedResponse.getContentAsString(), SamlServiceProvider.class);
        Assert.assertNotNull(deletedServiceProvider);
    }

    @Test
    void deleteServiceProviderWithInsufficientScopes() throws Exception {
        String spsReadClientId = generator.generate().toLowerCase();
        String spsReadClientSecret = generator.generate().toLowerCase();
        MockMvcUtils.createClient(this.mockMvc, adminToken, spsReadClientId, spsReadClientSecret, null, null, Arrays.asList("client_credentials", "password"), "sps.read");
        String spsReadToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, spsReadClientId, spsReadClientSecret, "sps.read", null);

        MockHttpServletRequestBuilder post = post("/saml/service-providers")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(APPLICATION_JSON)
                .content(requestBody);
        MockHttpServletResponse createdResponse = perform(mockMvc,
                zoneSwitching,
                zone,
                post
        ).andReturn().getResponse();
        SamlServiceProvider samlServiceProvider = JsonUtils.readValue(createdResponse.getContentAsString(), SamlServiceProvider.class);

        assertNotNull(samlServiceProvider);
        MockHttpServletRequestBuilder delete = delete("/saml/service-providers/{id}", samlServiceProvider.getId())
                .header("Authorization", "Bearer " + spsReadToken)
                .accept(APPLICATION_JSON);
        perform(mockMvc,
                zoneSwitching,
                zone,
                delete)
                .andExpect(status().isForbidden());
    }

    @Test
    void deleteServiceProviderThatDoesNotExist() throws Exception {
        MockHttpServletRequestBuilder delete = delete("/saml/service-providers/{id}", "nonExistentId")
                .header("Authorization", "Bearer " + spsWriteToken)
                .accept(APPLICATION_JSON);
        perform(mockMvc,
                zoneSwitching,
                zone,
                delete)
                .andExpect(status().isNotFound())
                .andExpect(content().string("Provider not found."));
    }

    @Test
    void createServiceProvider() throws Exception {
        performCreateServiceProvider(mockMvc, adminToken, requestBody)
                .andExpect(status().isCreated());
    }

    @Test
    void createServiceProviderInvalidEntityId() throws Exception {
        String name = generator.generate();
        String invalidRequestBody = "{\n" +
                "  \"name\" : \"" + name + "\",\n" +
                "  \"entityId\" : \"invalid.cloudfoundry-saml-login\",\n" +
                "  \"active\" : true,\n" +
                "  \"config\" : \"{\\\"metaDataLocation\\\" : \\\"<?xml version=\\\\\\\"1.0\\\\\\\" encoding=\\\\\\\"UTF-8\\\\\\\"?><md:EntityDescriptor xmlns:md=\\\\\\\"urn:oasis:names:tc:SAML:2.0:metadata\\\\\\\" ID=\\\\\\\"" + name + ".cloudfoundry-saml-login\\\\\\\" entityID=\\\\\\\"" + name + ".cloudfoundry-saml-login\\\\\\\"><ds:Signature xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\\\\\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\\\\\"/><ds:SignatureMethod Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\\\\\\\"/><ds:Reference URI=\\\\\\\"#" + name + ".cloudfoundry-saml-login\\\\\\\"><ds:Transforms><ds:Transform Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\\\\\\\"/><ds:Transform Algorithm=\\\\\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\\\\\"/></ds:Transforms><ds:DigestMethod Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#sha1\\\\\\\"/><ds:DigestValue>zALgjEFJ7jJSwn2AOBH5H8CX93U=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Rp5XH8eT0ek/vlFGzHgIFOeESchOwSYZ9oh4JA9WqQ0jJtvNQ9IttY2QY9XK3n6TbbtPcEKVgljyTfwD5ymp+oMKfIYQC9JsN8mPADN5rjLFgC+xGceWLbcjoNsCJ7x2ZjyWRblSxoOU5qnzxEA3k3Bu+OkV+ZXcSbmgMWoQACg=</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:SPSSODescriptor AuthnRequestsSigned=\\\\\\\"true\\\\\\\" WantAssertionsSigned=\\\\\\\"true\\\\\\\" protocolSupportEnumeration=\\\\\\\"urn:oasis:names:tc:SAML:2.0:protocol\\\\\\\"><md:KeyDescriptor use=\\\\\\\"signing\\\\\\\"><ds:KeyInfo xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\\\\\\\"encryption\\\\\\\"><ds:KeyInfo xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SingleLogout/alias/" + name + ".cloudfoundry-saml-login\\\\\\\"/><md:SingleLogoutService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SingleLogout/alias/" + name + ".cloudfoundry-saml-login\\\\\\\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</md:NameIDFormat><md:AssertionConsumerService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SSO/alias/" + name + ".cloudfoundry-saml-login\\\\\\\" index=\\\\\\\"0\\\\\\\" isDefault=\\\\\\\"true\\\\\\\"/></md:SPSSODescriptor></md:EntityDescriptor>\\\",\\\"metadataTrustCheck\\\" : true }\"" +
                "}";
        mockMvc.perform(post("/saml/service-providers")
                .header("Authorization", "bearer" + adminToken)
                .header("Content-Type", "application/json")
                .content(invalidRequestBody));
    }

    @Test
    void duplicateServiceProviderIsConflict() throws Exception {
        performCreateServiceProvider(mockMvc, adminToken, requestBody)
                .andExpect(status().isCreated());

        performCreateServiceProvider(mockMvc, adminToken, requestBody)
                .andExpect(status().isConflict());
    }

    @Test
    void createServiceProviderAttributeMappings() throws Exception {
        String name = generator.generate();
        requestBody = "{\n" +
                "  \"name\" : \"" + name + "\",\n" +
                "  \"entityId\" : \"" + name + ".cloudfoundry-saml-login\",\n" +
                "  \"active\" : true,\n" +
                "  \"config\" : \"{\\\"metaDataLocation\\\" : \\\"<?xml version=\\\\\\\"1.0\\\\\\\" encoding=\\\\\\\"UTF-8\\\\\\\"?><md:EntityDescriptor xmlns:md=\\\\\\\"urn:oasis:names:tc:SAML:2.0:metadata\\\\\\\" ID=\\\\\\\"" + name + ".cloudfoundry-saml-login\\\\\\\" entityID=\\\\\\\"" + name + ".cloudfoundry-saml-login\\\\\\\"><ds:Signature xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\\\\\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\\\\\"/><ds:SignatureMethod Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\\\\\\\"/><ds:Reference URI=\\\\\\\"#" + name + ".cloudfoundry-saml-login\\\\\\\"><ds:Transforms><ds:Transform Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\\\\\\\"/><ds:Transform Algorithm=\\\\\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\\\\\"/></ds:Transforms><ds:DigestMethod Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#sha1\\\\\\\"/><ds:DigestValue>zALgjEFJ7jJSwn2AOBH5H8CX93U=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Rp5XH8eT0ek/vlFGzHgIFOeESchOwSYZ9oh4JA9WqQ0jJtvNQ9IttY2QY9XK3n6TbbtPcEKVgljyTfwD5ymp+oMKfIYQC9JsN8mPADN5rjLFgC+xGceWLbcjoNsCJ7x2ZjyWRblSxoOU5qnzxEA3k3Bu+OkV+ZXcSbmgMWoQACg=</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:SPSSODescriptor AuthnRequestsSigned=\\\\\\\"true\\\\\\\" WantAssertionsSigned=\\\\\\\"true\\\\\\\" protocolSupportEnumeration=\\\\\\\"urn:oasis:names:tc:SAML:2.0:protocol\\\\\\\"><md:KeyDescriptor use=\\\\\\\"signing\\\\\\\"><ds:KeyInfo xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\\\\\\\"encryption\\\\\\\"><ds:KeyInfo xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SingleLogout/alias/" + name + ".cloudfoundry-saml-login\\\\\\\"/><md:SingleLogoutService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SingleLogout/alias/" + name + ".cloudfoundry-saml-login\\\\\\\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</md:NameIDFormat><md:AssertionConsumerService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SSO/alias/" + name + ".cloudfoundry-saml-login\\\\\\\" index=\\\\\\\"0\\\\\\\" isDefault=\\\\\\\"true\\\\\\\"/></md:SPSSODescriptor></md:EntityDescriptor>\\\",\\\"metadataTrustCheck\\\" : true " +
                ", \\\"attributeMappings\\\": {\\\"given_name\\\" : \\\"firstname\\\"" +
                "                                              ,\\\"family_name\\\" : \\\"lastname\\\"," +
                "                                               \\\"phone_number\\\" : \\\"phone\\\" }" +
                "               }\"" +
                "}";
        String response = performCreateServiceProvider(mockMvc, adminToken, requestBody)
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        SamlServiceProvider serviceProvider = JsonUtils.readValue(response, SamlServiceProvider.class);
        assertNotNull(serviceProvider);
        assertEquals("firstname", serviceProvider.getConfig().getAttributeMappings().get(GIVEN_NAME_ATTRIBUTE_NAME));
        assertEquals("lastname", serviceProvider.getConfig().getAttributeMappings().get(FAMILY_NAME_ATTRIBUTE_NAME));
        assertEquals("phone", serviceProvider.getConfig().getAttributeMappings().get(PHONE_NUMBER_ATTRIBUTE_NAME));
    }

    @Test
    void updateServiceProviderAttributeMappings() throws Exception {
        String name = generator.generate();
        requestBody = "{\n" +
                "  \"name\" : \"" + name + "\",\n" +
                "  \"entityId\" : \"" + name + ".cloudfoundry-saml-login\",\n" +
                "  \"active\" : true,\n" +
                "  \"config\" : \"{\\\"metaDataLocation\\\" : \\\"<?xml version=\\\\\\\"1.0\\\\\\\" encoding=\\\\\\\"UTF-8\\\\\\\"?><md:EntityDescriptor xmlns:md=\\\\\\\"urn:oasis:names:tc:SAML:2.0:metadata\\\\\\\" ID=\\\\\\\"" + name + ".cloudfoundry-saml-login\\\\\\\" entityID=\\\\\\\"" + name + ".cloudfoundry-saml-login\\\\\\\"><ds:Signature xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\\\\\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\\\\\"/><ds:SignatureMethod Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\\\\\\\"/><ds:Reference URI=\\\\\\\"#" + name + ".cloudfoundry-saml-login\\\\\\\"><ds:Transforms><ds:Transform Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\\\\\\\"/><ds:Transform Algorithm=\\\\\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\\\\\"/></ds:Transforms><ds:DigestMethod Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#sha1\\\\\\\"/><ds:DigestValue>zALgjEFJ7jJSwn2AOBH5H8CX93U=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Rp5XH8eT0ek/vlFGzHgIFOeESchOwSYZ9oh4JA9WqQ0jJtvNQ9IttY2QY9XK3n6TbbtPcEKVgljyTfwD5ymp+oMKfIYQC9JsN8mPADN5rjLFgC+xGceWLbcjoNsCJ7x2ZjyWRblSxoOU5qnzxEA3k3Bu+OkV+ZXcSbmgMWoQACg=</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:SPSSODescriptor AuthnRequestsSigned=\\\\\\\"true\\\\\\\" WantAssertionsSigned=\\\\\\\"true\\\\\\\" protocolSupportEnumeration=\\\\\\\"urn:oasis:names:tc:SAML:2.0:protocol\\\\\\\"><md:KeyDescriptor use=\\\\\\\"signing\\\\\\\"><ds:KeyInfo xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\\\\\\\"encryption\\\\\\\"><ds:KeyInfo xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SingleLogout/alias/" + name + ".cloudfoundry-saml-login\\\\\\\"/><md:SingleLogoutService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SingleLogout/alias/" + name + ".cloudfoundry-saml-login\\\\\\\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</md:NameIDFormat><md:AssertionConsumerService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SSO/alias/" + name + ".cloudfoundry-saml-login\\\\\\\" index=\\\\\\\"0\\\\\\\" isDefault=\\\\\\\"true\\\\\\\"/></md:SPSSODescriptor></md:EntityDescriptor>\\\",\\\"metadataTrustCheck\\\" : true " +
                ", \\\"attributeMappings\\\": {\\\"given_name\\\" : \\\"firstname\\\"" +
                "                                              ,\\\"family_name\\\" : \\\"lastname\\\"," +
                "                                               \\\"phone_number\\\" : \\\"phone\\\" }" +
                "               }\"" +
                "}";
        String response = performCreateServiceProvider(mockMvc, adminToken, requestBody)
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        SamlServiceProvider serviceProvider = JsonUtils.readValue(response, SamlServiceProvider.class);

        assertNotNull(serviceProvider);
        serviceProvider.getConfig().getAttributeMappings().put(GIVEN_NAME_ATTRIBUTE_NAME, "Ramanujan");
        requestBody = JsonUtils.writeValueAsString(serviceProvider);

        response = performUpdateServiceProvider(mockMvc, adminToken, requestBody, serviceProvider.getId())
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        serviceProvider = JsonUtils.readValue(response, SamlServiceProvider.class);
        assertNotNull(serviceProvider);
        assertEquals("Ramanujan", serviceProvider.getConfig().getAttributeMappings().get(GIVEN_NAME_ATTRIBUTE_NAME));
        assertEquals("lastname", serviceProvider.getConfig().getAttributeMappings().get(FAMILY_NAME_ATTRIBUTE_NAME));
        assertEquals("phone", serviceProvider.getConfig().getAttributeMappings().get(PHONE_NUMBER_ATTRIBUTE_NAME));
    }

    private static ResultActions perform(
            MockMvc mockMvc,
            boolean zoneSwitching,
            IdentityZone zone,
            MockHttpServletRequestBuilder request
    ) throws Exception {
        return mockMvc.perform(zoneSwitching ? request.header("X-Identity-Zone-Id", zone.getId()) : request);
    }

    private static ResultActions performCreateServiceProvider(
            MockMvc mockMvc,
            String adminToken,
            String requestBody
    ) throws Exception {
        return mockMvc.perform(post("/saml/service-providers")
                .header("Authorization", "bearer" + adminToken)
                .header("Content-Type", "application/json")
                .content(requestBody));
    }

    private static ResultActions performUpdateServiceProvider(
            MockMvc mockMvc,
            String adminToken,
            String requestBody,
            String id) throws Exception {
        return mockMvc.perform(put("/saml/service-providers/" + id)
                .header("Authorization", "bearer" + adminToken)
                .header("Content-Type", "application/json")
                .content(requestBody));
    }
}
