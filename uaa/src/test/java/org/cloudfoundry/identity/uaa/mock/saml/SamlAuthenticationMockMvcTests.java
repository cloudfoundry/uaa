package org.cloudfoundry.identity.uaa.mock.saml;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.audit.LoggingAuditService;
import org.cloudfoundry.identity.uaa.authentication.SamlResponseLoggerBinding;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.InterceptingLogger;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.jupiter.api.*;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.function.Consumer;

import static javax.xml.crypto.dsig.Transform.BASE64;
import static org.apache.logging.log4j.Level.DEBUG;
import static org.apache.logging.log4j.Level.WARN;
import static org.cloudfoundry.identity.uaa.authentication.SamlResponseLoggerBinding.X_VCAP_REQUEST_ID_HEADER;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpHeaders.HOST;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.util.Assert.doesNotContain;

@DefaultTestContext
class SamlAuthenticationMockMvcTests {

    private RandomValueStringGenerator generator;

    private IdentityZone spZone;
    private IdentityZone idpZone;
    private String spZoneEntityId;
    private IdentityProvider<SamlIdentityProviderDefinition> idp;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    private JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning;

    @Autowired
    private LoggingAuditService loggingAuditService;
    private InterceptingLogger testLogger;
    private Logger originalAuditServiceLogger;

    private static final String RESPONSE_XML = """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                ID="_242cbecb94e341d3895248b1899ddaa315839d4d39"
                                Version="2.0"
                                IssueInstant="2024-05-20T17:05:55Z"
                                Destination="http://localhost:8080/uaa/saml/SSO/alias/cloudfoundry-saml-login"
                                InResponseTo="ARQd92de0f-2c29-44ef-96ba-ea5c0e5f8a79">
                    <saml:Issuer>http://uaa-acceptance.cf-app.com/saml-idp</saml:Issuer>
                    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                        <ds:SignedInfo>
                            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
                            <ds:Reference URI="#_242cbecb94e341d3895248b1899ddaa315839d4d39">
                                <ds:Transforms>
                                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /></ds:Transforms>
                                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
                                <ds:DigestValue>MyMS6YmKuVkw7mwKjEM0yNDBeg/exvjiGcnqh2tb5Ao=</ds:DigestValue>
                            </ds:Reference>
                        </ds:SignedInfo>
                        <ds:SignatureValue>
                            avMFpID6wL5teuIjAikAUMGpLIDD8jlg39w9ZHHyoUzXhTV3/PxI4jzzMBcUjp+3PrlaKAy0na1P7x1zl3OOLHBfxlSCntXtafTXuzlqao4UEWmL28t/S6fT18F1DPcVh0aXXpoiYzqgN8VthTIVd3mcrUjgkjtcLYqotFrQAY47ojBCX9u9hOBm0sYzn6R6UdG1in0qCWTzM08FHhXlicwniugNlxRWaFY9WAoosUcmChIr7ecOsHdbeRcZN7cjrAlW7sFxHK6guGR3QZHt3jTWPKn6Wc+rmqom199iXOnY9ItejGArEKQxIeAWBpUgRj65oQdjYhbPBBH8yl6Exg==
                        </ds:SignatureValue>
                        <ds:KeyInfo>
                            <ds:X509Data>
                                <ds:X509Certificate>
                                    MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk
                                </ds:X509Certificate>
                            </ds:X509Data>
                        </ds:KeyInfo>
                    </ds:Signature>
                    <samlp:Status>
                        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>
                    <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                    xmlns:xs="http://www.w3.org/2001/XMLSchema"
                                    ID="_61499ba4a69885cc761ce32905866c75a8722aedd5"
                                    Version="2.0"
                                    IssueInstant="2024-05-20T17:05:55Z">
                        <saml:Issuer>http://uaa-acceptance.cf-app.com/saml-idp</saml:Issuer>
                        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                            <ds:SignedInfo>
                                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
                                <ds:Reference URI="#_61499ba4a69885cc761ce32905866c75a8722aedd5">
                                    <ds:Transforms>
                                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /></ds:Transforms>
                                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
                                    <ds:DigestValue>e7tjmX8XYbLZEepND4FUVjhT7CTU1HFEIg2jvFZnROk=</ds:DigestValue>
                                </ds:Reference>
                            </ds:SignedInfo>
                            <ds:SignatureValue>
                                snhPsfhCFKCInTy1e1UfDMMW2lXDCdjpUXCQ60lDtsFkwq2FbNP1EdVmKZcN+6OqhW4e69DX9ts78/6C9kgGs3VmT2gadyZz/1PuK202NvaiOodJ/v5mIA8U07Ebq6bZxu7AcDcpPsH3x0cYbF7DGsLsCOFWgCJP9FStrdk3ERkuvNUF9CfY8Z7Phle3HbvCi18bXXtnZ5nURNRi5omHrgp8DUN5idx/cIEM2vaEWwENnFU7zLLVSJVTf4lWT5AkZInO6RYoAlbL/9hblJ8Vbs3cYDxvRomGaH4KRxVVYo9MX8zbzyyVnqVIL3rm9s6+Z30Cs5b+aJF0AfpKx4B+lA==
                            </ds:SignatureValue>
                            <ds:KeyInfo>
                                <ds:X509Data>
                                    <ds:X509Certificate>
                                        MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk
                                    </ds:X509Certificate>
                                </ds:X509Data>
                            </ds:KeyInfo>
                        </ds:Signature>
                        <saml:Subject>
                            <saml:NameID SPNameQualifier="cloudfoundry-saml-login"
                                         Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_797b2928346d2737587b9f55b431d21c68ad5a791e</saml:NameID>
                            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                                <saml:SubjectConfirmationData NotOnOrAfter="2024-05-20T17:10:55Z"
                                                              Recipient="http://localhost:8080/uaa/saml/SSO/alias/cloudfoundry-saml-login"
                                                              InResponseTo="ARQd92de0f-2c29-44ef-96ba-ea5c0e5f8a79" /></saml:SubjectConfirmation>
                        </saml:Subject>
                        <saml:Conditions NotBefore="2024-05-20T17:05:25Z"
                                         NotOnOrAfter="2024-05-20T17:10:55Z">
                            <saml:AudienceRestriction>
                                <saml:Audience>cloudfoundry-saml-login</saml:Audience>
                            </saml:AudienceRestriction>
                        </saml:Conditions>
                        <saml:AuthnStatement AuthnInstant="2024-05-20T17:05:55Z"
                                             SessionNotOnOrAfter="2024-05-21T01:05:55Z"
                                             SessionIndex="_41e03754f5cfa23572848dc11ff82f66ba72673d89">
                            <saml:AuthnContext>
                                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
                            </saml:AuthnContext>
                        </saml:AuthnStatement>
                        <saml:AttributeStatement>
                            <saml:Attribute Name="uid"
                                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                                <saml:AttributeValue xsi:type="xs:string">marissa@test.org</saml:AttributeValue>
                            </saml:Attribute>
                            <saml:Attribute Name="eduPersonAffiliation"
                                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                                <saml:AttributeValue xsi:type="xs:string">member</saml:AttributeValue>
                                <saml:AttributeValue xsi:type="xs:string">marissa</saml:AttributeValue>
                            </saml:Attribute>
                            <saml:Attribute Name="emailAddress"
                                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                                <saml:AttributeValue xsi:type="xs:string">marissa@test.org</saml:AttributeValue>
                            </saml:Attribute>
                        </saml:AttributeStatement>
                    </saml:Assertion>
                </samlp:Response>
                """;

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @BeforeEach
    void createSamlRelationship(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning,
            @Autowired JdbcScimUserProvisioning jdbcScimUserProvisioning
    ) throws Exception {
        this.jdbcIdentityProviderProvisioning = jdbcIdentityProviderProvisioning;
        generator = new RandomValueStringGenerator();
        UaaClientDetails adminClient = new UaaClientDetails("admin", "", "", "client_credentials", "uaa.admin");
        adminClient.setClientSecret("adminsecret");
        spZone = createZone("uaa-acting-as-saml-proxy-zone-", adminClient);
        idpZone = createZone("uaa-acting-as-saml-idp-zone-", adminClient);
        spZoneEntityId = spZone.getSubdomain() + ".cloudfoundry-saml-login";
        createUser(jdbcScimUserProvisioning, idpZone);
    }

    @BeforeEach
    void installTestLogger() {
        testLogger = new InterceptingLogger();
        originalAuditServiceLogger = loggingAuditService.getLogger();
        loggingAuditService.setLogger(testLogger);
        Properties esapiProps = new Properties();
        esapiProps.put("ESAPI.Logger", "org.owasp.esapi.logging.slf4j.Slf4JLogFactory");
        esapiProps.put("ESAPI.Encoder", "org.owasp.esapi.reference.DefaultEncoder");
        esapiProps.put("Logger.LogEncodingRequired", Boolean.FALSE.toString());
        esapiProps.put("Logger.UserInfo", Boolean.TRUE.toString());
        esapiProps.put("Logger.ClientInfo", Boolean.TRUE.toString());
        esapiProps.put("Logger.ApplicationName", "uaa");
        esapiProps.put("Logger.LogApplicationName", Boolean.FALSE.toString());
        esapiProps.put("Logger.LogServerIP", Boolean.FALSE.toString());
        ESAPI.override(new DefaultSecurityConfiguration(esapiProps));
    }

    @AfterEach
    void putBackOriginalLogger() {
        loggingAuditService.setLogger(originalAuditServiceLogger);
    }

    @Test
    void sendAuthnRequestToIdpRedirectBindingMode() throws Exception {
        MvcResult mvcResult = mockMvc.perform(
                        get("/uaa/saml2/authenticate/%s".formatted("testsaml-redirect-binding"))
                                .contextPath("/uaa")
                                .header(HOST, "localhost:8080")
                )
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String samlRequestUrl = mvcResult.getResponse().getRedirectedUrl();
        Map<String, String[]> parameterMap = UaaUrlUtils.getParameterMap(samlRequestUrl);
        assertThat("SAMLRequest is missing", parameterMap.get("SAMLRequest"), notNullValue());
        assertThat("SigAlg is missing", parameterMap.get("SigAlg"), notNullValue());
        assertThat("Signature is missing", parameterMap.get("Signature"), notNullValue());
        assertThat("RelayState is missing", parameterMap.get("RelayState"), notNullValue());
        assertThat(parameterMap.get("RelayState")[0], equalTo("testsaml-redirect-binding"));
    }

    @Test
    void sendAuthnRequestToIdpPostBindingMode() throws Exception {
        mockMvc.perform(
                        get("/uaa/saml2/authenticate/%s".formatted("testsaml-post-binding"))
                                .contextPath("/uaa")
                                .header(HOST, "localhost:8080")
                )
                .andDo(print())
                .andExpectAll(
                        status().isOk(),
                        content().string(containsString("name=\"SAMLRequest\"")),
                        content().string(containsString("name=\"RelayState\"")),
                        content().string(containsString("value=\"testsaml-post-binding\"")))
                .andReturn();
    }

    @Test
    void receiveAuthnResponseFromIdpToNewFormUrl() throws Exception {
        byte[] encodedSamlResponse = Base64.getEncoder().encode(RESPONSE_XML.getBytes(StandardCharsets.UTF_8));

        MvcResult mvcResult = mockMvc.perform(
                        post("/uaa/login/saml2/sso/%s".formatted("testsaml-redirect-binding"))
                                .contextPath("/uaa")
                                .header(HOST, "localhost:8080")
                                .param("SAMLResponse", new String(encodedSamlResponse, StandardCharsets.UTF_8))
                                .param("RelayState", "testsaml-post-binding")
                )
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String samlRedirectUrl = mvcResult.getResponse().getRedirectedUrl();
        assertThat(samlRedirectUrl, equalTo("/uaa/"));
    }

    @Test
    void receiveAuthnResponseFromIdpToLegacyAliasUrl() throws Exception {
        byte[] encodedSamlResponse = Base64.getEncoder().encode(RESPONSE_XML.getBytes(StandardCharsets.UTF_8));

        MvcResult mvcResult = mockMvc.perform(
                        post("/uaa/saml/SSO/alias/%s".formatted("cloudfoundry-saml-login"))
                                .contextPath("/uaa")
                                .header(HOST, "localhost:8080")
                                .param("SAMLResponse", new String(encodedSamlResponse, StandardCharsets.UTF_8))
                                .param("RelayState", "testsaml-post-binding")
                )
                .andDo(print())
                .andExpect(status().is2xxSuccessful())
                .andReturn();

        String samlRedirectUrl = mvcResult.getResponse().getForwardedUrl();
        assertThat(samlRedirectUrl, equalTo("/login/saml2/sso/testsaml-post-binding"));
    }

    private ResultActions postSamlResponse(
            final String xml,
            final String queryString,
            final String content,
            final String xVcapRequestId
    ) throws Exception {
        return mockMvc.perform(
                post("/uaa/saml/SSO/alias/" + spZoneEntityId + queryString)
                        .contextPath("/uaa")
                        .header(HOST, spZone.getSubdomain() + ".localhost:8080")
                        .header(CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .header(X_VCAP_REQUEST_ID_HEADER, xVcapRequestId)
                        .content(content)
                        .param("SAMLResponse", xml)
        );
    }

    @Nested
    @DefaultTestContext
    class WithCustomLogAppender {
        private List<LogEvent> logEvents;
        private AbstractAppender appender;
        private Level originalLevel;

        @BeforeEach
        void setupLogger() throws Exception {
            logEvents = new ArrayList<>();
            appender = new AbstractAppender("", null, null) {
                @Override
                public void append(LogEvent event) {
                    if (SamlResponseLoggerBinding.class.getName().equals(event.getLoggerName())) {
                        logEvents.add(event);
                    }
                }
            };
            appender.start();

            LoggerContext context = (LoggerContext) LogManager.getContext(false);
            originalLevel = context.getRootLogger().getLevel();
            Configurator.setRootLevel(DEBUG);
            context.getRootLogger().addAppender(appender);

            createIdp();
        }

        @AfterEach
        void removeAppender() {
            LoggerContext context = (LoggerContext) LogManager.getContext(false);
            context.getRootLogger().removeAppender(appender);
            Configurator.setRootLevel(originalLevel);
        }

        @Test
        @Disabled("SAML test fails")
        void malformedSamlRequestLogsQueryStringAndContentMetadata() throws Exception {
            postSamlResponse(null, "?bogus=query", "someKey=someVal&otherKey=otherVal&emptyKey=", "vcap_request_id_abc123");

            assertThatMessageWasLogged(logEvents, WARN, "Malformed SAML response. More details at log level DEBUG.");
            assertThatMessageWasLogged(logEvents, DEBUG, "Method: POST, Params (name/size): (bogus/5) (emptyKey/0) (SAMLResponse/0) (someKey/7) (otherKey/8), Content-type: application/x-www-form-urlencoded, Request-size: 43, X-Vcap-Request-Id: vcap_request_id_abc123");
        }

        @Test
        @Disabled("SAML test fails")
        void malformedSamlRequestWithNoQueryStringAndNoContentMetadata() throws Exception {
            postSamlResponse(null, "", "", "");

            assertThatMessageWasLogged(logEvents, WARN, "Malformed SAML response. More details at log level DEBUG.");
            assertThatMessageWasLogged(logEvents, DEBUG, "Method: POST, Params (name/size): (SAMLResponse/0), Content-type: application/x-www-form-urlencoded, Request-size: 0, X-Vcap-Request-Id: ");
        }

        @Test
        @Disabled("SAML test fails")
        void malformedSamlRequestWithRepeatedParams() throws Exception {
            postSamlResponse(null, "?foo=a&foo=ab&foo=aaabbbccc", "", "");

            assertThatMessageWasLogged(logEvents, WARN, "Malformed SAML response. More details at log level DEBUG.");
            assertThatMessageWasLogged(logEvents, DEBUG, "Method: POST, Params (name/size): (foo/1) (foo/2) (foo/9) (SAMLResponse/0), Content-type: application/x-www-form-urlencoded, Request-size: 0, X-Vcap-Request-Id: ");
        }

        private void assertThatMessageWasLogged(
                final List<LogEvent> logEvents,
                final Level expectedLevel,
                final String expectedMessage
        ) {
            assertThat(logEvents, hasItem(new MatchesLogEvent(expectedLevel, expectedMessage)));
        }
    }

    private static class MatchesLogEvent extends BaseMatcher<LogEvent> {

        private final Level expectedLevel;
        private final String expectedMessage;

        public MatchesLogEvent(
                final Level expectedLevel,
                final String expectedMessage
        ) {
            this.expectedLevel = expectedLevel;
            this.expectedMessage = expectedMessage;
        }

        @Override
        public boolean matches(Object actual) {
            if (!(actual instanceof LogEvent)) {
                return false;
            }
            LogEvent logEvent = (LogEvent) actual;

            return expectedLevel.equals(logEvent.getLevel())
                    && expectedMessage.equals(logEvent.getMessage().getFormattedMessage());
        }

        @Override
        public void describeTo(Description description) {
            description.appendText(String.format("LogEvent with level of {%s} and message of {%s}", this.expectedLevel, this.expectedMessage));
        }
    }

    private String getSamlMetadata(String subdomain, String url) throws Exception {
        return mockMvc.perform(
                        get(url)
                                .header("Host", subdomain + ".localhost")
                )
                .andReturn().getResponse().getContentAsString();
    }

    private static void createUser(
            JdbcScimUserProvisioning jdbcScimUserProvisioning,
            IdentityZone identityZone
    ) {
        ScimUser user = new ScimUser(null, "marissa", "first", "last");
        user.setPrimaryEmail("test@test.org");
        jdbcScimUserProvisioning.createUser(user, "secret", identityZone.getId());
    }

    void createIdp() throws Exception {
        createIdp(null);
    }

    private void createIdp(Consumer<SamlIdentityProviderDefinition> additionalConfigCallback) throws Exception {
        idp = new IdentityProvider<>()
                .setType(OriginKeys.SAML)
                .setOriginKey(idpZone.getSubdomain())
                .setActive(true)
                .setName("SAML IDP for Mock Tests")
                .setIdentityZoneId(spZone.getId());
        SamlIdentityProviderDefinition idpDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(getSamlMetadata(idpZone.getSubdomain(), "/saml/idp/metadata"))
                .setIdpEntityAlias(idp.getOriginKey())
                .setLinkText(idp.getName())
                .setZoneId(spZone.getId());

        if (additionalConfigCallback != null) {
            additionalConfigCallback.accept(idpDefinition);
        }

        idp.setConfig(idpDefinition);
        idp = jdbcIdentityProviderProvisioning.create(idp, spZone.getId());
    }

    private IdentityZone createZone(String zoneIdPrefix, UaaClientDetails adminClient) throws Exception {
        return MockMvcUtils.createOtherIdentityZoneAndReturnResult(
                zoneIdPrefix + generator.generate(),
                mockMvc,
                webApplicationContext,
                adminClient, IdentityZoneHolder.getCurrentZoneId()
        ).getIdentityZone();
    }
}
