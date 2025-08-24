package org.cloudfoundry.identity.uaa.mock.saml;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
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
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.context.WebApplicationContext;
import org.xmlunit.assertj.XmlAssert;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.apache.logging.log4j.Level.DEBUG;
import static org.apache.logging.log4j.Level.WARN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.authentication.MalformedSamlResponseLogger.X_VCAP_REQUEST_ID_HEADER;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.responseWithAssertions;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.serializedResponse;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.xmlNamespaces;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2Utils.samlDecode;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2Utils.samlDecodeAndInflate;
import static org.hamcrest.Matchers.containsString;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_DIGEST_SHA256;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpHeaders.HOST;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class SamlAuthenticationMockMvcTests {
    private static final String SAML_REQUEST = "SAMLRequest";
    private static final String SAML_RESPONSE = "SAMLResponse";
    private static final String RELAY_STATE = "RelayState";
    private static final String SIG_ALG = "SigAlg";
    private static final String SIGNATURE = "Signature";

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

    private static void createUser(
            JdbcScimUserProvisioning jdbcScimUserProvisioning,
            IdentityZone identityZone
    ) {
        ScimUser user = new ScimUser(null, "marissa", "first", "last");
        user.setPrimaryEmail("test@test.org");
        jdbcScimUserProvisioning.createUser(user, "secret", identityZone.getId());
    }

    @BeforeEach
    void createSamlRelationship(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning,
            @Autowired JdbcScimUserProvisioning jdbcScimUserProvisioning
    ) throws Exception {
        this.jdbcIdentityProviderProvisioning = jdbcIdentityProviderProvisioning;
        generator = new RandomValueStringGenerator();
        UaaClientDetails adminClient = new UaaClientDetails("admin", "", "", "client_credentials", "uaa.admin");
        adminClient.setClientSecret("adminsecret");

        String spZoneSubdomain = "uaa-acting-as-saml-proxy-zone-" + generator.generate();
        spZone = createZoneWithSamlSpConfig(spZoneSubdomain, adminClient, true, true, spZoneSubdomain + "-entity-id");

        String idpZoneSubdomain = "uaa-acting-as-saml-idp-zone-" + generator.generate();
        idpZone = createZoneWithSamlSpConfig(idpZoneSubdomain, adminClient, true, true, idpZoneSubdomain + "-entity-id");

        spZoneEntityId = spZone.getSubdomain() + ".cloudfoundry-saml-login";
        createUser(jdbcScimUserProvisioning, idpZone);
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
        // In the redirect binding, the encoded SAMLRequest, RelayState,
        // SigAlg, Signature are all passed as query parameters
        assertThat(parameterMap.get(SAML_REQUEST)).as("SAMLRequest is missing").isNotNull();
        assertThat(parameterMap.get(SIG_ALG)[0]).as("SigAlg is missing").contains(ALGO_ID_SIGNATURE_RSA_SHA256);
        assertThat(parameterMap.get(SIGNATURE)).as("Signature is missing").isNotNull();
        assertThat(parameterMap.get(RELAY_STATE)).as("RelayState is missing").isNotNull();

        // Decode & Inflate the SAMLRequest and check the AssertionConsumerServiceURL
        String samlRequestXml = samlDecodeAndInflate(parameterMap.get(SAML_REQUEST)[0]);
        assertThat(samlRequestXml)
                .contains("<saml2p:AuthnRequest");

        XmlAssert xmlAssert = XmlAssert.assertThat(samlRequestXml)
                .withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/@AssertionConsumerServiceURL")
                .isEqualTo("http://localhost:8080/uaa/saml/SSO/alias/integration-saml-entity-id");
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/saml2:Issuer")
                .isEqualTo("integration-saml-entity-id"); // matches login.entityID
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/saml2p:NameIDPolicy/@Format")
                .isEqualTo("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"); // matches login.saml.nameID
    }

    @Test
    void sendAuthnRequestToIdpPostBindingMode() throws Exception {
        final String samlRequestMatch = "name=\"SAMLRequest\" value=\"";

        MvcResult mvcResult = mockMvc.perform(get("/uaa/saml2/authenticate/%s".formatted("testsaml-post-binding"))
                        .contextPath("/uaa")
                        .header(HOST, "localhost:8080")
                )
                .andDo(print())
                .andExpectAll(
                        status().isOk(),
                        content().string(containsString("name=\"SAMLRequest\"")))
                .andReturn();

        // Decode the SAMLRequest and check the AssertionConsumerServiceURL
        String contentHtml = mvcResult.getResponse().getContentAsString();
        contentHtml = contentHtml.substring(contentHtml.indexOf(samlRequestMatch) + samlRequestMatch.length());
        contentHtml = contentHtml.substring(0, contentHtml.indexOf("\""));
        String samlRequestXml = new String(samlDecode(contentHtml), StandardCharsets.UTF_8);
        assertThat(samlRequestXml).contains("<saml2p:AuthnRequest");

        // In the post-binding, Signature is part of the SAML AuthnRequest
        XmlAssert xmlAssert = XmlAssert.assertThat(samlRequestXml)
                .withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("/saml2p:AuthnRequest/@AssertionConsumerServiceURL")
                .isEqualTo("http://localhost:8080/uaa/saml/SSO/alias/integration-saml-entity-id");
        xmlAssert.valueByXPath("/saml2p:AuthnRequest/saml2:Issuer")
                .isEqualTo("integration-saml-entity-id"); // matches login.entityID
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/saml2p:NameIDPolicy/@Format")
                .isEqualTo("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"); // matches login.saml.nameID
        xmlAssert.nodesByXPath("/saml2p:AuthnRequest/ds:Signature").exist();
        xmlAssert.valueByXPath("/saml2p:AuthnRequest/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm")
                .isEqualTo(ALGO_ID_SIGNATURE_RSA_SHA256);
        xmlAssert.valueByXPath("/saml2p:AuthnRequest/ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm")
                .isEqualTo(ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        xmlAssert.valueByXPath("/saml2p:AuthnRequest/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm")
                .isEqualTo(ALGO_ID_DIGEST_SHA256);
        xmlAssert.valueByXPath("/saml2p:AuthnRequest/ds:Signature/ds:SignatureValue").isNotEmpty();
        xmlAssert.valueByXPath("/saml2p:AuthnRequest/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue").isNotEmpty();
    }

    @Test
    void sendAuthnRequestFromNonDefaultZoneToIdpRedirectBindingMode() throws Exception {
        // create IDP in non-default zone
        createMockSamlIdpInSpZone("classpath:test-saml-idp-metadata-redirect-binding.xml", "testsaml-redirect-binding");

        // trigger saml login in the non-default zone
        MvcResult mvcResult = mockMvc.perform(get("/uaa/saml2/authenticate/%s".formatted("testsaml-redirect-binding"))
                        .contextPath("/uaa")
                        .header(HOST, "%s.localhost:8080".formatted(spZone.getSubdomain()))
                )
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String samlRequestUrl = mvcResult.getResponse().getRedirectedUrl();
        Map<String, String[]> parameterMap = UaaUrlUtils.getParameterMap(samlRequestUrl);
        assertThat(parameterMap.get(SAML_REQUEST)).as("SAMLRequest is missing").isNotNull();
        assertThat(parameterMap.get(SIG_ALG)).as("SigAlg is missing").isNotNull();
        assertThat(parameterMap.get(SIGNATURE)).as("Signature is missing").isNotNull();
        assertThat(parameterMap.get(RELAY_STATE)).as("RelayState is missing").isNotNull();

        // Decode & Inflate the SAMLRequest and check the AssertionConsumerServiceURL
        String samlRequestXml = samlDecodeAndInflate(parameterMap.get(SAML_REQUEST)[0]);
        XmlAssert xmlAssert = XmlAssert.assertThat(samlRequestXml).withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/@AssertionConsumerServiceURL")
                .isEqualTo("http://%1$s.localhost:8080/uaa/saml/SSO/alias/%1$s.integration-saml-entity-id".formatted(spZone.getSubdomain()));
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/saml2:Issuer")
                .isEqualTo(spZone.getConfig().getSamlConfig().getEntityID()); // should match zone config's samlConfig.entityID
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/saml2p:NameIDPolicy/@Format")
                .isEqualTo("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"); // matches login.saml.nameID
    }

    @Test
    void sendAuthnRequestFromNonDefaultZoneToIdpRedirectBindingMode_ZoneConfigSamlEntityIDNotSet() throws Exception {
        // create a new zone without zone saml entity ID not set
        UaaClientDetails adminClient = new UaaClientDetails("admin", "", "", "client_credentials", "uaa.admin");
        adminClient.setClientSecret("adminsecret");
        String spZoneSubdomain = "uaa-acting-as-saml-proxy-zone-" + generator.generate();
        spZone = createZoneWithSamlSpConfig(spZoneSubdomain, adminClient, true, true, null);

        // create IDP in non-default zone
        createMockSamlIdpInSpZone("classpath:test-saml-idp-metadata-redirect-binding.xml", "testsaml-redirect-binding");

        // trigger saml login in the non-default zone
        MvcResult mvcResult = mockMvc.perform(get("/uaa/saml2/authenticate/%s".formatted("testsaml-redirect-binding"))
                        .contextPath("/uaa")
                        .header(HOST, "%s.localhost:8080".formatted(spZone.getSubdomain()))
                )
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String samlRequestUrl = mvcResult.getResponse().getRedirectedUrl();
        Map<String, String[]> parameterMap = UaaUrlUtils.getParameterMap(samlRequestUrl);
        assertThat(parameterMap.get(SAML_REQUEST)).as("SAMLRequest is missing").isNotNull();
        assertThat(parameterMap.get(SIG_ALG)).as("SigAlg is missing").isNotNull();
        assertThat(parameterMap.get(SIGNATURE)).as("Signature is missing").isNotNull();
        assertThat(parameterMap.get(RELAY_STATE)).as("RelayState is missing").isNotNull();

        // Decode & Inflate the SAMLRequest and check the AssertionConsumerServiceURL
        String samlRequestXml = samlDecodeAndInflate(parameterMap.get(SAML_REQUEST)[0]);
        XmlAssert xmlAssert = XmlAssert.assertThat(samlRequestXml).withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/@AssertionConsumerServiceURL")
                .isEqualTo("http://%1$s.localhost:8080/uaa/saml/SSO/alias/%1$s.integration-saml-entity-id".formatted(spZone.getSubdomain()));
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/saml2:Issuer")
                .isEqualTo("%s.%s".formatted(spZone.getSubdomain(), "integration-saml-entity-id")); // should match zone config's samlConfig.entityID; if not set, fail over to zone-subdomain.uaa-wide-saml-entity-id
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/saml2p:NameIDPolicy/@Format")
                .isEqualTo("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"); // matches login.saml.nameID
    }

    @Test
    void sendAuthnRequestFromNonDefaultZoneToIdpPostBindingMode() throws Exception {
        // create IDP in non-default zone
        createMockSamlIdpInSpZone("classpath:test-saml-idp-metadata-post-binding.xml", "testsaml-post-binding");

        final String samlRequestMatch = "name=\"SAMLRequest\" value=\"";

        MvcResult mvcResult = mockMvc.perform(get("/uaa/saml2/authenticate/%s".formatted("testsaml-post-binding"))
                        .contextPath("/uaa")
                        .header(HOST, "%s.localhost:8080".formatted(spZone.getSubdomain()))
                )
                .andDo(print())
                .andExpectAll(
                        status().isOk(),
                        content().string(containsString("name=\"SAMLRequest\"")))
                .andReturn();

        // Decode the SAMLRequest and check the AssertionConsumerServiceURL
        String contentHtml = mvcResult.getResponse().getContentAsString();
        contentHtml = contentHtml.substring(contentHtml.indexOf(samlRequestMatch) + samlRequestMatch.length());
        contentHtml = contentHtml.substring(0, contentHtml.indexOf("\""));
        String samlRequestXml = new String(samlDecode(contentHtml), StandardCharsets.UTF_8);
        assertThat(samlRequestXml).contains("<saml2p:AuthnRequest");

        XmlAssert xmlAssert = XmlAssert.assertThat(samlRequestXml)
                .withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/@AssertionConsumerServiceURL")
                .isEqualTo("http://%1$s.localhost:8080/uaa/saml/SSO/alias/%1$s.integration-saml-entity-id".formatted(spZone.getSubdomain()));
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/saml2:Issuer")
                .isEqualTo(spZone.getConfig().getSamlConfig().getEntityID()); // should match zone config's samlConfig.entityID
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/saml2p:NameIDPolicy/@Format")
                .isEqualTo("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"); // matches login.saml.nameID
    }

    @Test
    void receiveAuthnResponseFromIdpToLegacyAliasUrl() throws Exception {

        String encodedSamlResponse = serializedResponse(responseWithAssertions());
        mockMvc.perform(post("/uaa/saml/SSO/alias/%s".formatted("integration-saml-entity-id"))
                        .contextPath("/uaa")
                        .header(HOST, "localhost:8080")
                        .param(SAML_RESPONSE, encodedSamlResponse)
                )
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                // expect redirect to the Uaa Home Page: /uaa/
                .andExpect(redirectedUrl("/uaa/"))
                .andReturn();
    }

    private ResultActions postSamlResponse(
            final String xml,
            final String queryString,
            final String content,
            final String xVcapRequestId) throws Exception {

        return mockMvc.perform(post("/uaa/saml/SSO/alias/%s%s".formatted(spZoneEntityId, queryString))
                .contextPath("/uaa")
                .header(HOST, spZone.getSubdomain() + ".localhost:8080")
                .header(CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .header(X_VCAP_REQUEST_ID_HEADER, xVcapRequestId)
                .content(content)
                .param(SAML_RESPONSE, xml)
        );
    }

    private String getSamlMetadata(String subdomain, String url) throws Exception {
        return mockMvc.perform(
                        get(url)
                                .header("Host", subdomain + ".localhost")
                )
                .andReturn().getResponse().getContentAsString();
    }

    void createIdp() throws Exception {
        createIdp(null);
    }

    private void createIdp(Consumer<SamlIdentityProviderDefinition> additionalConfigCallback) throws Exception {
        idp = new IdentityProvider<SamlIdentityProviderDefinition>()
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

    private void createMockSamlIdpInSpZone(String metadataLocation, String idpOriginKey) {
        idp = new IdentityProvider<SamlIdentityProviderDefinition>()
                .setType(OriginKeys.SAML)
                .setOriginKey(idpOriginKey)
                .setActive(true)
                .setName("SAML IDP for Mock Tests")
                .setIdentityZoneId(spZone.getId());
        SamlIdentityProviderDefinition idpDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadataLocation)
                .setIdpEntityAlias(idp.getOriginKey())
                .setLinkText(idp.getName())
                .setZoneId(spZone.getId());

        idp.setConfig(idpDefinition);
        idp = jdbcIdentityProviderProvisioning.create(idp, spZone.getId());
    }

    private IdentityZone createZoneWithSamlSpConfig(String zoneSubdomain, UaaClientDetails adminClient, Boolean samlRequestSigned, Boolean samlWantAssertionSigned, String samlZoneEntityID) throws Exception {
        IdentityZone identityZone = MultitenancyFixture.identityZone(zoneSubdomain, zoneSubdomain);
        identityZone.getConfig().getSamlConfig().setRequestSigned(samlRequestSigned);
        identityZone.getConfig().getSamlConfig().setWantAssertionSigned(samlWantAssertionSigned);
        identityZone.getConfig().getSamlConfig().setEntityID(samlZoneEntityID);
        return MockMvcUtils.createOtherIdentityZoneAndReturnResult(mockMvc, webApplicationContext, adminClient, identityZone, true, IdentityZoneHolder.getCurrentZoneId()).getIdentityZone();
    }

    @Nested
    @DefaultTestContext
    @TestPropertySource(properties = {"login.saml.signRequest = false"})
    class UnsignedConfigMockMvcTests {
        @Autowired
        private MockMvc mockMvc;

        @Test
        void unsignedAuthnRequestViaIdpRedirectBindingMode() throws Exception {
            MvcResult mvcResult = mockMvc.perform(get("/uaa/saml2/authenticate/%s".formatted("testsaml-redirect-binding"))
                            .contextPath("/uaa")
                            .header(HOST, "localhost:8080")
                    )
                    .andDo(print())
                    .andExpect(status().is3xxRedirection())
                    .andReturn();

            String samlRequestUrl = mvcResult.getResponse().getRedirectedUrl();
            Map<String, String[]> parameterMap = UaaUrlUtils.getParameterMap(samlRequestUrl);
            // In the redirect binding, the encoded SAMLRequest, RelayState,
            // SigAlg, Signature are all passed as query parameters
            assertThat(parameterMap.get(SAML_REQUEST)).as("SAMLRequest is missing").isNotNull();
            assertThat(parameterMap.get(SIG_ALG)).as("SigAlg exists, but SAMLRequest should not be signed").isNull();
            assertThat(parameterMap.get(SIGNATURE)).as("Signature exists, but SAMLRequest should not be signed").isNull();
        }

        @Test
        void unsignedAuthnRequestViaIdpPostBindingMode() throws Exception {
            final String samlRequestMatch = "name=\"SAMLRequest\" value=\"";

            MvcResult mvcResult = mockMvc.perform(get("/uaa/saml2/authenticate/%s".formatted("testsaml-post-binding"))
                            .contextPath("/uaa")
                            .header(HOST, "localhost:8080")
                    )
                    .andDo(print())
                    .andExpectAll(
                            status().isOk(),
                            content().string(containsString("name=\"SAMLRequest\"")))
                    .andReturn();

            // Decode the SAMLRequest and check the AssertionConsumerServiceURL
            String contentHtml = mvcResult.getResponse().getContentAsString();
            contentHtml = contentHtml.substring(contentHtml.indexOf(samlRequestMatch) + samlRequestMatch.length());
            contentHtml = contentHtml.substring(0, contentHtml.indexOf("\""));
            String samlRequestXml = new String(samlDecode(contentHtml), StandardCharsets.UTF_8);
            assertThat(samlRequestXml).contains("<saml2p:AuthnRequest");

            // In the post-binding, Signature is part of the SAML AuthnRequest
            XmlAssert xmlAssert = XmlAssert.assertThat(samlRequestXml)
                    .withNamespaceContext(xmlNamespaces());
            xmlAssert.valueByXPath("/saml2p:AuthnRequest/@AssertionConsumerServiceURL")
                    .isEqualTo("http://localhost:8080/uaa/saml/SSO/alias/integration-saml-entity-id");
            xmlAssert.valueByXPath("/saml2p:AuthnRequest/saml2:Issuer")
                    .isEqualTo("integration-saml-entity-id"); // matches login.entityID
            xmlAssert.nodesByXPath("/saml2p:AuthnRequest/ds:Signature").doNotExist();
        }
    }

    @Test
    void AuthnResponseFailsWithWithInvalidInResponseTo() throws Exception {

        Response response = responseWithAssertions();
        response.setInResponseTo("incorrect");
        String encodedSamlResponse = serializedResponse(response);
        mockMvc.perform(post("/uaa/saml/SSO/alias/%s".formatted("integration-saml-entity-id"))
                        .contextPath("/uaa")
                        .header(HOST, "localhost:8080")
                        .param(SAML_RESPONSE, encodedSamlResponse)
                        .param(RELAY_STATE, "testsaml-post-binding")
                )
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                // expect redirect to the Error Page: /uaa/saml_error, not the Uaa Home Page
                .andExpect(redirectedUrl("/uaa/saml_error"))
                .andReturn();
    }

    @Nested
    @DefaultTestContext
    @TestPropertySource(properties = "login.saml.disableInResponseToCheck=true")
    class InResponseToConfigMockMvcTests {
        @Autowired
        private MockMvc mockMvc;

        @Test
        void AuthnResponseSucceedsWithWithInvalidInResponseTo() throws Exception {

            Response response = responseWithAssertions("https://some.idp.test/saml/idp");
            response.setInResponseTo("incorrect");
            String encodedSamlResponse = serializedResponse(response);
            mockMvc.perform(post("/uaa/saml/SSO/alias/%s".formatted("integration-saml-entity-id"))
                            .contextPath("/uaa")
                            .header(HOST, "localhost:8080")
                            .param(SAML_RESPONSE, encodedSamlResponse)
                    )
                    .andDo(print())
                    .andExpect(status().is3xxRedirection())
                    // expect redirect to the Uaa Home Page: /uaa/, not error
                    .andExpect(redirectedUrl("/uaa/"))
                    .andReturn();
        }
    }

    @Nested
    @DefaultTestContext
    @TestPropertySource(properties = "login.saml.nameID=urn:oasis:names:tc:SAML:1.1:nameid-format:peaches")
    class NameIdConfigMockMvcTests {
        @Autowired
        private MockMvc mockMvc;

        @Test
        void sendAuthnRequestToIdpRedirectBindingMode() throws Exception {
            MvcResult mvcResult = mockMvc.perform(get("/uaa/saml2/authenticate/%s".formatted("testsaml-redirect-binding"))
                            .contextPath("/uaa")
                            .header(HOST, "localhost:8080")
                    )
                    .andDo(print())
                    .andExpect(status().is3xxRedirection())
                    .andReturn();

            String samlRequestUrl = mvcResult.getResponse().getRedirectedUrl();
            Map<String, String[]> parameterMap = UaaUrlUtils.getParameterMap(samlRequestUrl);

            // Decode & Inflate the SAMLRequest and check the AssertionConsumerServiceURL
            String samlRequestXml = samlDecodeAndInflate(parameterMap.get(SAML_REQUEST)[0]);
            assertThat(samlRequestXml).contains("<saml2p:AuthnRequest");

            XmlAssert xmlAssert = XmlAssert.assertThat(samlRequestXml)
                    .withNamespaceContext(xmlNamespaces());
            xmlAssert.valueByXPath("//saml2p:AuthnRequest/saml2p:NameIDPolicy/@Format")
                    .isEqualTo("urn:oasis:names:tc:SAML:1.1:nameid-format:peaches"); // matches login.saml.nameID
        }
    }

    @Nested
    class WithCustomLogAppender {
        private static final String LOGGER_NAME = "org.cloudfoundry.identity.uaa.authentication.SamlResponseLoggerBinding";
        private List<LogEvent> logEvents;
        private AbstractAppender appender;
        private Level originalLevel;

        @BeforeEach
        void setupLogger() throws Exception {
            logEvents = new ArrayList<>();
            appender = new AbstractAppender("", null, null) {
                @Override
                public void append(LogEvent event) {
                    if (LOGGER_NAME.equals(event.getLoggerName())) {
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
        void malformedSamlRequestLogsQueryStringAndContentMetadata() throws Exception {
            postSamlResponse(null, "?bogus=query", "someKey=someVal&otherKey=otherVal&emptyKey=", "vcap_request_id_abc123");

            assertThatMessageWasLogged(logEvents, WARN, "Malformed SAML response. More details at log level DEBUG.");
            assertThatMessageWasLogged(logEvents, DEBUG, "Method: POST, Params (name/size): (bogus/5) (emptyKey/0) (SAMLResponse/0) (someKey/7) (otherKey/8), Content-type: application/x-www-form-urlencoded, Request-size: 43, X-Vcap-Request-Id: vcap_request_id_abc123");
        }

        @Test
        void malformedSamlRequestWithNoQueryStringAndNoContentMetadata() throws Exception {
            postSamlResponse(null, "", "", "");

            assertThatMessageWasLogged(logEvents, WARN, "Malformed SAML response. More details at log level DEBUG.");
            assertThatMessageWasLogged(logEvents, DEBUG, "Method: POST, Params (name/size): (SAMLResponse/0), Content-type: application/x-www-form-urlencoded, Request-size: 0, X-Vcap-Request-Id: ");
        }

        @Test
        void malformedSamlRequestWithRepeatedParams() throws Exception {
            postSamlResponse(null, "?foo=a&foo=ab&foo=aaabbbccc", "", "");

            assertThatMessageWasLogged(logEvents, WARN, "Malformed SAML response. More details at log level DEBUG.");
            assertThatMessageWasLogged(logEvents, DEBUG, "Method: POST, Params (name/size): (foo/1) (foo/2) (foo/9) (SAMLResponse/0), Content-type: application/x-www-form-urlencoded, Request-size: 0, X-Vcap-Request-Id: ");
        }

        @Test
        void malformedSamlRequest() throws Exception {
            postSamlResponse("<a/>", "?foo=a", "", "");

            assertThatMessageWasLogged(logEvents, WARN, "Malformed SAML response. More details at log level DEBUG.");
            assertThatMessageWasLogged(logEvents, DEBUG, "Method: POST, Params (name/size): (foo/1) (SAMLResponse/4), Content-type: application/x-www-form-urlencoded, Request-size: 0, X-Vcap-Request-Id: ");
        }

        private void assertThatMessageWasLogged(
                final List<LogEvent> logEvents,
                final Level expectedLevel,
                final String expectedMessage) {

            assertThat(logEvents).filteredOn(l -> l.getLevel().equals(expectedLevel))
                    .isNotEmpty()
                    .first()
                    .returns(expectedMessage, l -> l.getMessage().getFormattedMessage());
        }
    }
}
