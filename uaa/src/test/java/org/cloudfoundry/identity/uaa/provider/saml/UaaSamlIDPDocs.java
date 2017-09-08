/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.restdocs.headers.HeaderDescriptor;
import org.springframework.restdocs.request.RequestDocumentation;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createUserInZone;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getUaaSecurityContext;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.updateIdentityZone;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.delete;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.put;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessRequest;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.BOOLEAN;
import static org.springframework.restdocs.payload.JsonFieldType.NUMBER;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class UaaSamlIDPDocs extends InjectedMockContextTest {

    private String adminToken;

    private RandomValueStringGenerator generator = new RandomValueStringGenerator(10);

    private String requestBody;
    private static final String ENABLE_IDP_INITIATED_SSO = "When set to true, default is false, the service provider supports IDP initiated SSO at the endpoint /saml/idp/initiate?sp=sp_entity_id";

    private Snippet pathParameters = pathParameters(
        parameterWithName("id").description("Unique ID of the service provider")
    );

    private Snippet requestFields = requestFields(
        fieldWithPath("name").type(STRING).attributes(key("constraints").value("Required")).description("Human readable name for the SAML SP."),
        fieldWithPath("entityId").type(STRING).attributes(key("constraints").value("Optional")).description("If provided, it should match the entityId in the SP metadata."),
        fieldWithPath("active").type(BOOLEAN).attributes(key("constraints").value("Optional")).description("Defaults to true"),
        fieldWithPath("config").type(STRING).attributes(key("constraints").value("Required")).description("Contains metaDataLocation and metadataTrustCheck fields as json fields."),
        fieldWithPath("config.metaDataLocation").type(STRING).attributes(key("constraints").value("Required")).description("The SAML SP Metadata - either an XML string or a URL that").optional(),
        fieldWithPath("config.attributeMappings.given_name").type(STRING).attributes(key("constraints").value("Optional")).description("Map given_name value within UAA to a specified assertion in the SAML response.").optional(),
        fieldWithPath("config.attributeMappings.family_name").type(STRING).attributes(key("constraints").value("Optional")).description("Map family_name value within UAA to a specified assertion in the SAML response").optional(),
        fieldWithPath("config.attributeMappings.phone_number").type(STRING).attributes(key("constraints").value("Optional")).description("Map phone_number value within UAA to a specified assertion in the SAML response.").optional(),
        fieldWithPath("config.metadataTrustCheck").type(BOOLEAN).attributes(key("constraints").value("Optional")).description("Determines whether UAA should validate the SAML SP metadata.").optional(),
        fieldWithPath("config.enableIdpInitiatedSso").type(BOOLEAN).description(ENABLE_IDP_INITIATED_SSO).attributes(key("constraints").value("Optional")).optional()
    );
    private Snippet responseFields = responseFields(
        fieldWithPath("id").type(STRING).description("Unique identifier for this provider - GUID generated by the UAA."),
        fieldWithPath("name").type(STRING).description("Human readable name for the SAML SP."),
        fieldWithPath("entityId").type(STRING).description("The entity id of the SAML SP."),
        fieldWithPath("active").type(BOOLEAN).description("Defaults to true."),
        fieldWithPath("created").type(NUMBER).description("UAA sets this to the UTC creation date."),
        fieldWithPath("identityZoneId").type(STRING).description("Set to the zone that this provider will be active in. Determined by either."),
        fieldWithPath("lastModified").type(NUMBER).description("UAA sets this to the UTC last date of modification."),
        fieldWithPath("version").type(NUMBER).description("Version of the identity provider data. Clients can use this."),
        fieldWithPath("config").type(STRING).description("Contains metaDataLocation and metadataTrustCheck fields as json fields."),
        fieldWithPath("config.metaDataLocation").type(STRING).description("The SAML SP Metadata - either an XML string or a URL that.").optional(),
        fieldWithPath("config.metadataTrustCheck").type(BOOLEAN).description("Determines whether UAA should validate the SAML SP metadata.").optional(),
        fieldWithPath("config.attributeMappings.given_name").type(STRING).description("Map given_name value within UAA to a specified assertion in the SAML response.").optional(),
        fieldWithPath("config.attributeMappings.family_name").type(STRING).description("Map family_name value within UAA to a specified assertion in the SAML response").optional(),
        fieldWithPath("config.attributeMappings.phone_number").type(STRING).description("Map phone_number value within UAA to a specified assertion in the SAML response.").optional(),
        fieldWithPath("config.enableIdpInitiatedSso").type(BOOLEAN).description(ENABLE_IDP_INITIATED_SSO).attributes(key("constraints").value("Optional")).optional()
    );

    private static final HeaderDescriptor IDENTITY_ZONE_ID_HEADER = headerWithName(IdentityZoneSwitchingFilter.HEADER).optional().description("If using a `zones.<zoneId>.admin scope/token, indicates what zone this request goes to by supplying a zone_id.");
    private static final HeaderDescriptor IDENTITY_ZONE_SUBDOMAIN_HEADER = headerWithName(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER).optional().description("If using a `zones.<zoneId>.admin scope/token, indicates what zone this request goes to by supplying a subdomain.");
    private String spEntityID;

    @Before
    public void setup() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "uaa.admin");
        String name = generator.generate();
        spEntityID = name + ".cloudfoundry-saml-login";
        requestBody = "{\n" +
            "  \"name\" : \"" + name + "\",\n" +
            "  \"entityId\" : \"" + spEntityID + "\",\n" +
            "  \"active\" : true,\n" +
            "  \"config\" : \"{\\\"enableIdpInitiatedSso\\\" : true,\\\"metaDataLocation\\\" : \\\"<?xml version=\\\\\\\"1.0\\\\\\\" encoding=\\\\\\\"UTF-8\\\\\\\"?><md:EntityDescriptor xmlns:md=\\\\\\\"urn:oasis:names:tc:SAML:2.0:metadata\\\\\\\" ID=\\\\\\\"" + name + ".cloudfoundry-saml-login\\\\\\\" entityID=\\\\\\\"" + name + ".cloudfoundry-saml-login\\\\\\\"><ds:Signature xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\\\\\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\\\\\"/><ds:SignatureMethod Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\\\\\\\"/><ds:Reference URI=\\\\\\\"#" + name + ".cloudfoundry-saml-login\\\\\\\"><ds:Transforms><ds:Transform Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\\\\\\\"/><ds:Transform Algorithm=\\\\\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\\\\\"/></ds:Transforms><ds:DigestMethod Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#sha1\\\\\\\"/><ds:DigestValue>zALgjEFJ7jJSwn2AOBH5H8CX93U=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Rp5XH8eT0ek/vlFGzHgIFOeESchOwSYZ9oh4JA9WqQ0jJtvNQ9IttY2QY9XK3n6TbbtPcEKVgljyTfwD5ymp+oMKfIYQC9JsN8mPADN5rjLFgC+xGceWLbcjoNsCJ7x2ZjyWRblSxoOU5qnzxEA3k3Bu+OkV+ZXcSbmgMWoQACg=</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:SPSSODescriptor AuthnRequestsSigned=\\\\\\\"true\\\\\\\" WantAssertionsSigned=\\\\\\\"true\\\\\\\" protocolSupportEnumeration=\\\\\\\"urn:oasis:names:tc:SAML:2.0:protocol\\\\\\\"><md:KeyDescriptor use=\\\\\\\"signing\\\\\\\"><ds:KeyInfo xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\\\\\\\"encryption\\\\\\\"><ds:KeyInfo xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SingleLogout/alias/" + name + ".cloudfoundry-saml-login\\\\\\\"/><md:SingleLogoutService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SingleLogout/alias/" + name + ".cloudfoundry-saml-login\\\\\\\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</md:NameIDFormat><md:AssertionConsumerService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SSO/alias/" + name + ".cloudfoundry-saml-login\\\\\\\" index=\\\\\\\"0\\\\\\\" isDefault=\\\\\\\"true\\\\\\\"/><md:AssertionConsumerService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SSO/alias/" + name + ".cloudfoundry-saml-login\\\\\\\" index=\\\\\\\"1\\\\\\\"/></md:SPSSODescriptor></md:EntityDescriptor>\\\"" +
            ",\\\"metadataTrustCheck\\\" : true " +
            ",\\\"attributeMappings\\\" : { \\\"given_name\\\" : \\\"firstname\\\", \\\"family_name\\\" : \\\"lastname\\\", \\\"phone_number\\\" : \\\"phone\\\" }" +
            "}\"" +
            "}";
    }

    @Test
    public void createServiceProvider() throws Exception {
        getMockMvc().perform(post("/saml/service-providers")
                                 .header("Authorization", "Bearer " + adminToken)
                                 .contentType(APPLICATION_JSON)
                                 .content(requestBody)
        ).andExpect(status().isCreated())
            .andDo(document("{ClassName}/{methodName}",
                            preprocessRequest(prettyPrint()),
                            preprocessResponse(prettyPrint()),
                            requestHeaders(
                                headerWithName("Authorization").description("Bearer token containing `sps.write`"),
                                IDENTITY_ZONE_ID_HEADER,
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                            ),
                            requestFields,
                            responseFields));
    }

    public IdentityZone createZone() throws Exception {
        String subdomain = new RandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext());
        return MockMvcUtils.updateIdentityZone(zone, getWebApplicationContext());
    }

    @Test
    public void document_idp_initiated_flow() throws Exception {
        IdentityZone zone = createZone();
        updateIdentityZone(zone, getWebApplicationContext());
        ScimUser marissa = new ScimUser(null, "marissa", "", "");
        marissa.setPassword("secret");
        marissa.setPrimaryEmail("marissa@test.org");
        marissa = createUserInZone(getMockMvc(), adminToken, marissa, "", zone.getId());

        getMockMvc().perform(post("/saml/service-providers")
                                 .header("Authorization", "Bearer " + adminToken)
                                 .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER, zone.getSubdomain())
                                 .contentType(APPLICATION_JSON)
                                 .content(requestBody)

        ).andExpect(status().isCreated());

        Snippet requestParameters = RequestDocumentation.requestParameters(
            parameterWithName("sp")
                .attributes(
                    key("type").value(STRING),
                    key("constraints").value("required")
                )
                .description("The entity ID of a configured and active the service provider.")

        );

        getMockMvc().perform(
            get("/saml/idp/initiate")
                .param("sp", spEntityID)
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain()+".localhost"))
                .with(securityContext(getUaaSecurityContext(marissa.getUserName(), getWebApplicationContext(), zone)))
        )
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("<input type=\"hidden\" name=\"SAMLResponse\" value=\"")))
            .andDo(document("{ClassName}/{methodName}",
                            preprocessRequest(prettyPrint()),
                            requestParameters));
    }

    @Test
    public void updateServiceProvider() throws Exception {
        MockHttpServletResponse response = getMockMvc().perform(post("/saml/service-providers")
                                                                    .header("Authorization", "Bearer " + adminToken)
                                                                    .contentType(APPLICATION_JSON)
                                                                    .content(requestBody)
        ).andReturn().getResponse();
        SamlServiceProvider samlServiceProvider = JsonUtils.readValue(response.getContentAsString(), SamlServiceProvider.class);

        getMockMvc().perform(put("/saml/service-providers/{id}", samlServiceProvider.getId())
                                 .header("Authorization", "Bearer " + adminToken)
                                 .contentType(APPLICATION_JSON)
                                 .content(requestBody)
        ).andExpect(status().isOk())
            .andDo(document("{ClassName}/{methodName}",
                            preprocessRequest(prettyPrint()),
                            preprocessResponse(prettyPrint()),
                            pathParameters,
                            requestHeaders(
                                headerWithName("Authorization").description("Bearer token containing `sps.write`"),
                                IDENTITY_ZONE_ID_HEADER,
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                            ),
                            requestFields,
                            responseFields));
    }

    @Test
    public void getServiceProvider() throws Exception {
        MockHttpServletResponse response = getMockMvc().perform(post("/saml/service-providers")
                                                                    .header("Authorization", "Bearer " + adminToken)
                                                                    .contentType(APPLICATION_JSON)
                                                                    .content(requestBody)
        ).andReturn().getResponse();
        SamlServiceProvider samlServiceProvider = JsonUtils.readValue(response.getContentAsString(), SamlServiceProvider.class);

        getMockMvc().perform(get("/saml/service-providers/{id}", samlServiceProvider.getId())
                                 .header("Authorization", "Bearer " + adminToken)
        ).andExpect(status().isOk())
            .andDo(document("{ClassName}/{methodName}",
                            preprocessResponse(prettyPrint()),
                            pathParameters,
                            requestHeaders(
                                headerWithName("Authorization").description("Bearer token containing `sps.read`"),
                                IDENTITY_ZONE_ID_HEADER,
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                            ),
                            responseFields));
    }

    @Test
    public void getAllServiceProviders() throws Exception {
        Snippet responseFields = responseFields(
            fieldWithPath("[].id").type(STRING).description("Unique identifier for this provider - GUID generated by the UAA."),
            fieldWithPath("[].name").type(STRING).description("Human readable name for the SAML SP."),
            fieldWithPath("[].entityId").type(STRING).description("The entity id of the SAML SP."),
            fieldWithPath("[].active").type(BOOLEAN).description("Defaults to true."),
            fieldWithPath("[].created").type(NUMBER).description("UAA sets this to the UTC creation date."),
            fieldWithPath("[].identityZoneId").type(STRING).description("Set to the zone that this provider will be active in. Determined by either."),
            fieldWithPath("[].lastModified").type(NUMBER).description("UAA sets this to the UTC last date of modification."),
            fieldWithPath("[].version").type(NUMBER).description("Version of the identity provider data. Clients can use this."),
            fieldWithPath("[].config").type(STRING).description("Contains metaDataLocation and metadataTrustCheck fields as json fields."),
            fieldWithPath("[].config.metaDataLocation").type(STRING).description("The SAML SP Metadata - either an XML string or a URL that.").optional(),
            fieldWithPath("[].config.metadataTrustCheck").type(BOOLEAN).description("Determines whether UAA should validate the SAML SP metadata.").optional()

        );

        getMockMvc().perform(post("/saml/service-providers")
                                 .header("Authorization", "Bearer " + adminToken)
                                 .contentType(APPLICATION_JSON)
                                 .content(requestBody)
        ).andReturn().getResponse();

        getMockMvc().perform(get("/saml/service-providers")
                                 .header("Authorization", "Bearer " + adminToken)
        ).andExpect(status().isOk())
            .andDo(document("{ClassName}/{methodName}",
                            preprocessResponse(prettyPrint()),
                            requestHeaders(
                                headerWithName("Authorization").description("Bearer token containing `sps.read`"),
                                IDENTITY_ZONE_ID_HEADER,
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                            ),
                            responseFields));
    }

    @Test
    public void deleteServiceProvider() throws Exception {
        MockHttpServletResponse createdResponse = getMockMvc().perform(MockMvcRequestBuilders.post("/saml/service-providers")
                                                                           .header("Authorization", "Bearer " + adminToken)
                                                                           .contentType(APPLICATION_JSON)
                                                                           .content(requestBody)
        ).andReturn().getResponse();
        SamlServiceProvider samlServiceProvider = JsonUtils.readValue(createdResponse.getContentAsString(), SamlServiceProvider.class);

        getMockMvc().perform(delete("/saml/service-providers/{id}", samlServiceProvider.getId())
                                 .header("Authorization", "Bearer " + adminToken)
                                 .accept(APPLICATION_JSON))
            .andExpect(status().isOk()).andDo(document("{ClassName}/{methodName}",
                                                       preprocessResponse(prettyPrint()),
                                                       pathParameters,
                                                       requestHeaders(
                                                           headerWithName("Authorization").description("Bearer token containing `sps.write`"),
                                                           IDENTITY_ZONE_ID_HEADER,
                                                           IDENTITY_ZONE_SUBDOMAIN_HEADER
                                                       ),
                                                       responseFields));

    }

}
