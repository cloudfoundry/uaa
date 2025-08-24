package org.cloudfoundry.identity.uaa.mock.token;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.TestOpenSamlObjects;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.NameID;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.security.Security;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.legacyCertificate;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.legacyKey;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.legacyPassphrase;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.createLocalSamlIdpDefinition;
import static org.springframework.http.HttpHeaders.HOST;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class Saml2BearerGrantMockMvcTests extends AbstractTokenMockMvcTests {

    @BeforeAll
    static void beforeAll() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @BeforeEach
    void beforeEach() {
        IdentityZone.getUaa().getConfig().getSamlConfig().setPrivateKey(legacyKey());
        IdentityZone.getUaa().getConfig().getSamlConfig().setPrivateKeyPassword(legacyPassphrase());
        IdentityZone.getUaa().getConfig().getSamlConfig().setCertificate(legacyCertificate());
    }

    @Test
    void getTokenUsingSaml2BearerGrant() throws Exception {
        final String subdomain = "68uexx";
        // all our SAML defaults use `:8080/uaa/` so we have to use that here too
        final String host = "%s.localhost".formatted(subdomain);
        final String fullPath = "/uaa/oauth/token/alias/%s.integration-saml-entity-id".formatted(subdomain);
        final String origin = "%s.integration-saml-entity-id".formatted(subdomain);
        final String entityId = "%s.cloudfoundry-saml-login".formatted(subdomain);
        MockMvcUtils.IdentityZoneCreationResult testZone =
                MockMvcUtils.createOtherIdentityZoneAndReturnResult(
                        subdomain, mockMvc, this.webApplicationContext, null,
                        IdentityZoneHolder.getCurrentZoneId());

        //create an IDP in the test zone
        String idpMetadata = getIdpMetadata(host, origin);
        SamlIdentityProviderDefinition idpDef = createLocalSamlIdpDefinition(
                origin, testZone.getIdentityZone().getId(), idpMetadata);
        idpDef.setIdpEntityId(entityId);
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setConfig(idpDef);
        provider.setActive(true);
        provider.setIdentityZoneId(testZone.getIdentityZone().getId());
        provider.setName(origin);
        provider.setOriginKey(origin);

        IdentityZoneHolder.set(testZone.getIdentityZone());
        identityProviderProvisioning.create(provider, testZone.getIdentityZone().getId());
        IdentityZoneHolder.clear();

        String spEndpoint = "http://%s:8080/uaa/oauth/token/alias/%s".formatted(host, origin);
        String assertionStr = TestOpenSamlObjects.getEncodedAssertion(entityId, NameID.UNSPECIFIED,
                "Saml2BearerIntegrationUser", spEndpoint, origin, true);

        // create a client in the test zone
        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, "uaa.none", "uaa.user,openid",
                GRANT_TYPE_SAML2_BEARER + ",password,refresh_token", true,
                TEST_REDIRECT_URI, null, 600, testZone.getIdentityZone());

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.post(fullPath)
                .with(request -> {
                    request.setServerPort(8080);
                    request.setRequestURI(fullPath);
                    request.setServerName(host);
                    return request;
                })
                .contextPath("/uaa")
                .accept(APPLICATION_JSON)
                .header(HOST, host)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param("grant_type", TokenConstants.GRANT_TYPE_SAML2_BEARER)
                .param("client_id", clientId)
                .param("client_secret", "secret")
                .param("client_assertion", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZDU1YzUwMGNjNmI1ODM3OTYxN2UwNmU3ZGVjNmNhIn0.eyJzdWIiOiJsb2dpbiIsImlzcyI6ImxvZ2luIiwianRpIjoiNThkNTVjNTAwY2M2YjU4Mzc5NjE3ZTA2ZTdhZmZlZSIsImV4cCI6MTIzNDU2NzgsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4ifQ.jwWw0OKZecd4ZjtwQ_ievqBVrh2SieqMF6vY74Oo5H6v-Ibcmumq96NLNtoUEwaAEQQOHb8MWcC8Gwi9dVQdCrtpomC86b_LKkihRBSKuqpw0udL9RMH5kgtC04ctsN0yZNifUWMP85VHn97Ual5eZ2miaBFob3H5jUe98CcBj1TSRehr64qBFYuwt9vD19q6U-ONhRt0RXBPB7ayHAOMYtb1LFIzGAiKvqWEy9f-TBPXSsETjKkAtSuM-WVWi4EhACMtSvI6iJN15f7qlverRSkGIdh1j2vPXpKKBJoRhoLw6YqbgcUC9vAr17wfa_POxaRHvh9JPty0ZXLA4XPtA")
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param("assertion", assertionStr)
                .param("scope", "openid");

        mockMvc.perform(post)
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.scope").value("openid"));
    }

    private String getIdpMetadata(String host, String origin) {
        // Mock an IDP metadata: %1$s is the host; %2$s is the origin
        // Maps to TestCredentialObjects.legacyCertificate
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="%2$s"
                                     entityID="68uexx.cloudfoundry-saml-login">
                    <md:IDPSSODescriptor WantAuthnRequestsSigned="false"
                                         protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                        <md:KeyDescriptor use="signing">
                            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                                <ds:X509Data>
                                    <ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF
                                        YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM
                                        BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2
                                        MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE
                                        ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx
                                        HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
                                        gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR
                                        4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY
                                        xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy
                                        GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3
                                        MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL
                                        EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA
                                        MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am
                                        2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o
                                        ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=
                                    </ds:X509Certificate>
                                </ds:X509Data>
                            </ds:KeyInfo>
                        </md:KeyDescriptor>
                        <md:KeyDescriptor use="encryption">
                            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                                <ds:X509Data>
                                    <ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF
                                        YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM
                                        BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2
                                        MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE
                                        ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx
                                        HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
                                        gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR
                                        4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY
                                        xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy
                                        GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3
                                        MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL
                                        EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA
                                        MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am
                                        2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o
                                        ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=
                                    </ds:X509Certificate>
                                </ds:X509Data>
                            </ds:KeyInfo>
                        </md:KeyDescriptor>
                        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
                        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
                        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                                Location="http://%1$s:8080/uaa/saml/idp/SSO/alias/%2$s"/>
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                                Location="http://%1$s:8080/uaa/saml/idp/SSO/alias/%2$s"/>
                    </md:IDPSSODescriptor>
                </md:EntityDescriptor>""".formatted(host, origin);
    }
}
