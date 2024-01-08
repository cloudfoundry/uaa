package org.cloudfoundry.identity.uaa.mock.token;

import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.Test;
import org.opensaml.saml2.core.NameID;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.createLocalSamlIdpDefinition;
import static org.springframework.http.HttpHeaders.HOST;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class Saml2BearerGrantMockMvcTests extends AbstractTokenMockMvcTests {
    @Test
    void getTokenUsingSaml2BearerGrant() throws Exception {
        SamlTestUtils samlTestUtils = new SamlTestUtils();
        samlTestUtils.initializeSimple();

        final String subdomain = "68uexx";
        //all our SAML defaults use :8080/uaa/ so we have to use that here too
        final String host = subdomain + ".localhost";
        final String fullPath = "/uaa/oauth/token/alias/" + subdomain +
                ".cloudfoundry-saml-login";
        final String origin = subdomain + ".cloudfoundry-saml-login";

        MockMvcUtils.IdentityZoneCreationResult testZone =
                MockMvcUtils.createOtherIdentityZoneAndReturnResult(
                    subdomain, mockMvc, this.webApplicationContext, null,
                        IdentityZoneHolder.getCurrentZoneId());

        //Mock an IDP metadata
        String idpMetadata = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"" + origin + "\"\n" +
                "                     entityID=\"68uexx.cloudfoundry-saml-login\">\n" +
                "    <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "        <ds:SignedInfo>\n" +
                "            <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "            <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
                "            <ds:Reference URI=\"#" + origin + "\">\n" +
                "                <ds:Transforms>\n" +
                "                    <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
                "                    <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "                </ds:Transforms>\n" +
                "                <ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n" +
                "                <ds:DigestValue>MNO5mOgijKliauTLhxL1pqT15s4=</ds:DigestValue>\n" +
                "            </ds:Reference>\n" +
                "        </ds:SignedInfo>\n" +
                "        <ds:SignatureValue>\n" +
                "            CwxB189hOth7P4g+jswYiG1XHyy0a8Pci6LahimDi0sSuWF5ui1Dw8MSamNDfi2GC5QGArrupPdxgX5F8BFFuio3XkmcQqRhsC01R2u1/NhpabGTgczrk1LYMpCaIOitaXRM2cEkqrmf/s6S3zXDQkQJTcJefc/0NrYgFN6Pisc=\n" +
                "        </ds:SignatureValue>\n" +
                "        <ds:KeyInfo>\n" +
                "            <ds:X509Data>\n" +
                "                <ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\n" +
                "                    YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\n" +
                "                    BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\n" +
                "                    MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\n" +
                "                    ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\n" +
                "                    HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\n" +
                "                    gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\n" +
                "                    4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\n" +
                "                    xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\n" +
                "                    GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\n" +
                "                    MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\n" +
                "                    EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\n" +
                "                    MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\n" +
                "                    2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\n" +
                "                    ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=\n" +
                "                </ds:X509Certificate>\n" +
                "            </ds:X509Data>\n" +
                "        </ds:KeyInfo>\n" +
                "    </ds:Signature>\n" +
                "    <md:IDPSSODescriptor WantAuthnRequestsSigned=\"false\"\n" +
                "                         protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
                "        <md:KeyDescriptor use=\"signing\">\n" +
                "            <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "                <ds:X509Data>\n" +
                "                    <ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\n" +
                "                        YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\n" +
                "                        BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\n" +
                "                        MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\n" +
                "                        ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\n" +
                "                        HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\n" +
                "                        gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\n" +
                "                        4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\n" +
                "                        xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\n" +
                "                        GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\n" +
                "                        MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\n" +
                "                        EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\n" +
                "                        MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\n" +
                "                        2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\n" +
                "                        ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=\n" +
                "                    </ds:X509Certificate>\n" +
                "                </ds:X509Data>\n" +
                "            </ds:KeyInfo>\n" +
                "        </md:KeyDescriptor>\n" +
                "        <md:KeyDescriptor use=\"encryption\">\n" +
                "            <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "                <ds:X509Data>\n" +
                "                    <ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\n" +
                "                        YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\n" +
                "                        BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\n" +
                "                        MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\n" +
                "                        ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\n" +
                "                        HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\n" +
                "                        gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\n" +
                "                        4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\n" +
                "                        xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\n" +
                "                        GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\n" +
                "                        MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\n" +
                "                        EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\n" +
                "                        MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\n" +
                "                        2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\n" +
                "                        ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=\n" +
                "                    </ds:X509Certificate>\n" +
                "                </ds:X509Data>\n" +
                "            </ds:KeyInfo>\n" +
                "        </md:KeyDescriptor>\n" +
                "        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\n" +
                "        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>\n" +
                "        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>\n" +
                "        <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n" +
                "                                Location=\"http://" + host + ":8080/uaa/saml/idp/SSO/alias/" + origin + "\"/>\n" +
                "        <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"\n" +
                "                                Location=\"http://" + host + ":8080/uaa/saml/idp/SSO/alias/" + origin + "\"/>\n" +
                "    </md:IDPSSODescriptor>\n" +
                "</md:EntityDescriptor>";

        //create an IDP in the test zone
        SamlIdentityProviderDefinition idpDef = createLocalSamlIdpDefinition(
                origin, testZone.getIdentityZone().getId(), idpMetadata);
        IdentityProvider provider = new IdentityProvider();
        provider.setConfig(idpDef);
        provider.setActive(true);
        provider.setIdentityZoneId(testZone.getIdentityZone().getId());
        provider.setName(origin);
        provider.setOriginKey(origin);

        IdentityZoneHolder.set(testZone.getIdentityZone());
        identityProviderProvisioning.create(provider,
                testZone.getIdentityZone().getId());
        IdentityZoneHolder.clear();

        String assertion = samlTestUtils.mockAssertionEncoded(
                origin,
                NameID.UNSPECIFIED,
                "Saml2BearerIntegrationUser",
                "http://" + host + ":8080/uaa/oauth/token/alias/" + origin,
                origin);

        //create client in test zone
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
                .param("assertion", assertion)
                .param("scope", "openid");

        mockMvc.perform(post)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.scope").value("openid"));
    }
}
