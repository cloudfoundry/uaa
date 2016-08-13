package org.cloudfoundry.identity.uaa.mock.zones;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

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
import static org.springframework.restdocs.payload.JsonFieldType.ARRAY;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class IdentityZoneEndpointDocs extends InjectedMockContextTest {

    private static final String ID_DESC = "Unique ID of the identity zone";
    private static final String SUBDOMAIN_DESC = "Unique subdomain for the running instance. May only contain legal characters for a subdomain name.";
    private static final String NAME_DESC = "Human-readable zone name";
    private static final String DESCRIPTION_DESC = "Description of the zone";
    private static final String VERSION_DESC = "Reserved for future use of E-Tag versioning";
    private static final String TOKEN_POLICY_DESC = "Various fields pertaining to the JWT access and refresh tokens.";
    private static final String ACTIVE_KEY_ID_DESC = "The ID for the key that is being used to sign tokens";
    private static final String KEYS_DESC = "Keys which will be used to sign the token";
    private static final String ACCESS_TOKEN_VALIDITY_DESC = "Time in seconds between when a access token is issued and when it expires. Defaults to global `accessTokenValidity`";
    private static final String REFRESH_TOKEN_VALIDITY_DESC = "Time in seconds between when a refresh token is issued and when it expires. Defaults to global `refreshTokenValidity`";
    private static final String ASSERTION_SIGNED_DESC = "If `true`, the SAML provider will sign all assertions";
    private static final String WANT_ASSERTION_SIGNED_DESC = "Exposed SAML metadata property. If `true`, all assertions received by the SAML provider must be signed. Defaults to `true`.";
    private static final String REQUEST_SIGNED_DESC = "Exposed SAML metadata property. If `true`, the service provider will sign all outgoing authentication requests. Defaults to `true`.";
    private static final String WANT_AUTHN_REQUEST_SIGNED_DESC = "If `true`, the authentication request from the partner service provider must be signed.";
    private static final String ASSERTION_TIME_TO_LIVE_SECONDS_DESC = "The lifetime of a SAML assertion in seconds. Defaults to 600.";
    private static final String CERTIFICATE_DESC = "Exposed SAML metadata property. The certificate used to sign all communications.";
    private static final String PRIVATE_KEY_DESC = "Exposed SAML metadata property. The SAML provider's private key.";
    private static final String PRIVATE_KEY_PASSWORD_DESC = "Exposed SAML metadata property. The SAML provider's private key password. Reserved for future use.";
    private static final String REDIRECT_URL_DESC = "Logout redirect url";
    private static final String REDIRECT_PARAMETER_NAME_DESC = "Changes the name of the redirect parameter";
    private static final String DISABLE_REDIRECT_PARAMETER_DESC = "Whether or not to allow the redirect parameter on logout";
    private static final String WHITELIST_DESC = "List of allowed whitelist redirects";
    private static final String SELF_SERVICE_LINKS_ENABLED_DESC = "Whether or not users are allowed to sign up or reset their passwords via the UI";
    private static final String SIGNUP_DESC = "Where users are directed upon clicking the account creation link";
    private static final String PASSWD_DESC = "Where users are directed upon clicking the password reset link";
    private static final String PROMPTS_DESC = "List of fields that users are prompted for to login. Defaults to username, password, and passcode.";
    private static final String PROMPTS_NAME_DESC = "Name of field";
    private static final String PROMPTS_TYPE_DESC = "What kind of field this is (e.g. text or password)";
    private static final String PROMPTS_TEXT_DESC = "Actual text displayed on prompt for field";
    private static final String IDP_DISCOVERY_ENABLED_FLAG = "IDP Discovery should be set to true if you have configured more than one identity provider for UAA. The discovery relies on email domain being set for each additional provider";
    private static final String BRANDING_COMPANY_NAME_DESC = "This name is used on the UAA Pages and in account management related communication in UAA";
    private static final String BRANDING_PRODUCT_LOGO_DESC = "This is a base64 encoded PNG image which will be used as the logo on all UAA pages like Login, Sign Up etc.";
    private static final String BRANDING_SQUARE_LOGO_DESC = "This is a base64 encoded PNG image which will be used as the favicon for the UAA pages";
    private static final String BRANDING_FOOTER_LEGAL_TEXT_DESC = "This text appears on the footer of all UAA pages";
    private static final String BRANDING_FOOTER_LINKS_DESC = "These links appear on the footer of all UAA pages. You may choose to add multiple urls for things like Support, Terms of Service etc.";

    private TestClient testClient;

    @Before
    public void setUp() throws Exception {
        if (testClient == null) {
            testClient = new TestClient(getMockMvc());
        }
    }

    @Test
    public void createIdentityZone() throws Exception {
        String identityClientWriteToken = testClient.getClientCredentialsOAuthAccessToken(
            "identity",
            "identitysecret",
            "zones.write");

        String id = "twiglet-create";
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(StringUtils.hasText(id) ? id : new RandomValueStringGenerator().generate());
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        Map<String, String> keys = new HashMap<>();
        keys.put("exampleKeyId", "s1gNiNg.K3y/t3XT");
        identityZone.getConfig().getTokenPolicy().setKeys(keys);
        IdentityZoneConfiguration brandingConfig = setBranding(identityZone.getConfig());
        identityZone.setConfig(brandingConfig);

        FieldDescriptor[] fieldDescriptors = {
            fieldWithPath("id").description(ID_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("subdomain").description(SUBDOMAIN_DESC).attributes(key("constraints").value("Required")),
            fieldWithPath("name").description(NAME_DESC).attributes(key("constraints").value("Required")),
            fieldWithPath("description").description(DESCRIPTION_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("version").description(VERSION_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.tokenPolicy").description(TOKEN_POLICY_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.activeKeyId").type(STRING).description(ACTIVE_KEY_ID_DESC).attributes(key("constraints").value("Required if `config.tokenPolicy.keys` are set")),
            fieldWithPath("config.tokenPolicy.keys").description(KEYS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.accessTokenValidity").description(ACCESS_TOKEN_VALIDITY_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.refreshTokenValidity").description(REFRESH_TOKEN_VALIDITY_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.samlConfig.assertionSigned").description(ASSERTION_SIGNED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.wantAssertionSigned").description(WANT_ASSERTION_SIGNED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.requestSigned").description(REQUEST_SIGNED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.wantAuthnRequestSigned").description(WANT_AUTHN_REQUEST_SIGNED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.assertionTimeToLiveSeconds").description(ASSERTION_TIME_TO_LIVE_SECONDS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.certificate").type(STRING).description(CERTIFICATE_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.privateKey").type(STRING).description(PRIVATE_KEY_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.privateKeyPassword").type(STRING).description(PRIVATE_KEY_PASSWORD_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.links.logout.redirectUrl").description(REDIRECT_URL_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.redirectParameterName").description(REDIRECT_PARAMETER_NAME_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.disableRedirectParameter").description(DISABLE_REDIRECT_PARAMETER_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.whitelist").type(ARRAY).description(WHITELIST_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.selfServiceLinksEnabled").description(SELF_SERVICE_LINKS_ENABLED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.signup").description(SIGNUP_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.passwd").description(PASSWD_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.prompts[]").type(ARRAY).description(PROMPTS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].name").description(PROMPTS_NAME_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].type").description(PROMPTS_TYPE_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].text").description(PROMPTS_TEXT_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.idpDiscoveryEnabled").description(IDP_DISCOVERY_ENABLED_FLAG).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.branding.companyName").description(BRANDING_COMPANY_NAME_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.branding.productLogo").description(BRANDING_PRODUCT_LOGO_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.branding.squareLogo").description(BRANDING_SQUARE_LOGO_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.branding.footerLegalText").description(BRANDING_FOOTER_LEGAL_TEXT_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.branding.footerLinks").description(BRANDING_FOOTER_LINKS_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("created").ignored(),
            fieldWithPath("last_modified").ignored()
        };

        getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientWriteToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone)))
            .andExpect(status().is(HttpStatus.CREATED.value()))
            .andDo(document("{ClassName}/{methodName}",
                  preprocessRequest(prettyPrint()),
                  preprocessResponse(prettyPrint()),
                  requestHeaders(
                    headerWithName("Authorization").description("Bearer token containing `zones.write` or `zones.<zone id>.admin`")
                  ),
                  requestFields(fieldDescriptors),
                getResponseFields()
            ));
    }

    @Test
    public void getIdentityZone() throws Exception {
        String id = "twiglet-get";
        createIdentityZoneHelper(id);

        String identityClientReadToken = testClient.getClientCredentialsOAuthAccessToken(
            "identity",
            "identitysecret",
            "zones.read");

        getMockMvc().perform(
            get("/identity-zones/{id}", id)
                .header("Authorization", "Bearer " + identityClientReadToken))
            .andExpect(status().is(HttpStatus.OK.value()))
            .andDo(document("{ClassName}/{methodName}",
                preprocessResponse(prettyPrint()),
                pathParameters(
                    parameterWithName("id").description("Unique ID of the identity zone to retrieve")
                ),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token containing `zones.read` or `zones.<zone id>.admin` or `zones.<zone id>.read`")
                ),
                getResponseFields()
            ));
    }

    @Test
    public void getAllIdentityZones() throws Exception {
        String id1 = "twiglet-get-1";
        String id2 = "twiglet-get-2";

        createIdentityZoneHelper(id1);
        createIdentityZoneHelper(id2);

        String identityClientReadToken = testClient.getClientCredentialsOAuthAccessToken(
            "identity",
            "identitysecret",
            "zones.read");

        Snippet responseFields = responseFields(
            fieldWithPath("[].id").description(ID_DESC),
            fieldWithPath("[].subdomain").description(SUBDOMAIN_DESC),
            fieldWithPath("[].name").description(NAME_DESC),
            fieldWithPath("[].description").description(DESCRIPTION_DESC),
            fieldWithPath("[].version").description(VERSION_DESC),

            fieldWithPath("[].config.tokenPolicy").description(TOKEN_POLICY_DESC),
            fieldWithPath("[].config.tokenPolicy.activeKeyId").type(STRING).description(ACTIVE_KEY_ID_DESC),
            fieldWithPath("[].config.tokenPolicy.keys").description(KEYS_DESC),
            fieldWithPath("[].config.tokenPolicy.accessTokenValidity").description(ACCESS_TOKEN_VALIDITY_DESC),
            fieldWithPath("[].config.tokenPolicy.refreshTokenValidity").description(REFRESH_TOKEN_VALIDITY_DESC),

            fieldWithPath("[].config.samlConfig.assertionSigned").description(ASSERTION_SIGNED_DESC),
            fieldWithPath("[].config.samlConfig.wantAssertionSigned").description(WANT_ASSERTION_SIGNED_DESC),
            fieldWithPath("[].config.samlConfig.requestSigned").description(REQUEST_SIGNED_DESC),
            fieldWithPath("[].config.samlConfig.wantAuthnRequestSigned").description(WANT_AUTHN_REQUEST_SIGNED_DESC),
            fieldWithPath("[].config.samlConfig.assertionTimeToLiveSeconds").description(ASSERTION_TIME_TO_LIVE_SECONDS_DESC),
            fieldWithPath("[].config.samlConfig.certificate").type(STRING).description(CERTIFICATE_DESC),
            fieldWithPath("[].config.samlConfig.privateKey").type(STRING).description(PRIVATE_KEY_DESC),
            fieldWithPath("[].config.samlConfig.privateKeyPassword").type(STRING).description(PRIVATE_KEY_PASSWORD_DESC),

            fieldWithPath("[].config.links.logout.redirectUrl").description(REDIRECT_URL_DESC),
            fieldWithPath("[].config.links.logout.redirectParameterName").description(REDIRECT_PARAMETER_NAME_DESC),
            fieldWithPath("[].config.links.logout.disableRedirectParameter").description(DISABLE_REDIRECT_PARAMETER_DESC),
            fieldWithPath("[].config.links.logout.whitelist").type(ARRAY).description(WHITELIST_DESC),
            fieldWithPath("[].config.links.selfService.selfServiceLinksEnabled").description(SELF_SERVICE_LINKS_ENABLED_DESC),
            fieldWithPath("[].config.links.selfService.signup").description(SIGNUP_DESC),
            fieldWithPath("[].config.links.selfService.passwd").description(PASSWD_DESC),

            fieldWithPath("[].config.prompts[]").type(ARRAY).description(PROMPTS_DESC),
            fieldWithPath("[].config.prompts[].name").description(PROMPTS_DESC),
            fieldWithPath("[].config.prompts[].type").description(PROMPTS_TYPE_DESC),
            fieldWithPath("[].config.prompts[].text").description(PROMPTS_TEXT_DESC),

            fieldWithPath("[].config.idpDiscoveryEnabled").description(IDP_DISCOVERY_ENABLED_FLAG),

            fieldWithPath("[].config.branding.companyName").description(BRANDING_COMPANY_NAME_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.branding.productLogo").description(BRANDING_PRODUCT_LOGO_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.branding.squareLogo").description(BRANDING_SQUARE_LOGO_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.branding.footerLegalText").description(BRANDING_FOOTER_LEGAL_TEXT_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.branding.footerLinks").description(BRANDING_FOOTER_LINKS_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("[].created").ignored(),
            fieldWithPath("[].last_modified").ignored()
        );

        getMockMvc().perform(
            get("/identity-zones")
                .header("Authorization", "Bearer " + identityClientReadToken))
            .andExpect(status().is(HttpStatus.OK.value()))
            .andDo(document("{ClassName}/{methodName}",
                preprocessResponse(prettyPrint()),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token containing `zones.read` or `zones.<zone id>.admin`")
                ),
                responseFields
            ));
    }

    @Test
    public void updateIdentityZone() throws Exception {
        String identityClientWriteToken = testClient.getClientCredentialsOAuthAccessToken(
            "identity",
            "identitysecret",
            "zones.write");

        String id = "twiglet-update";
        createIdentityZoneHelper(id);

        IdentityZone updatedIdentityZone = new IdentityZone();
        updatedIdentityZone.setSubdomain(StringUtils.hasText(id) ? id : new RandomValueStringGenerator().generate());
        updatedIdentityZone.setName("The Updated Twiglet Zone");
        updatedIdentityZone.setDescription("Like the Twilight Zone but not tastier.");
        Map<String, String> keys = new HashMap<>();
        keys.put("updatedKeyId", "upD4t3d.s1gNiNg.K3y/t3XT");
        updatedIdentityZone.getConfig().getTokenPolicy().setKeys(keys);
        IdentityZoneConfiguration brandingConfig = setBranding(updatedIdentityZone.getConfig());
        updatedIdentityZone.setConfig(brandingConfig);

        Snippet requestFields = requestFields(
            fieldWithPath("subdomain").description(SUBDOMAIN_DESC).attributes(key("constraints").value("Required")),
            fieldWithPath("name").description(NAME_DESC).attributes(key("constraints").value("Required")),
            fieldWithPath("description").description(DESCRIPTION_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("version").description(VERSION_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.tokenPolicy").description(TOKEN_POLICY_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.activeKeyId").type(STRING).description(ACTIVE_KEY_ID_DESC).attributes(key("constraints").value("Required if `config.tokenPolicy.keys` are set")),
            fieldWithPath("config.tokenPolicy.keys").description(KEYS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.accessTokenValidity").description(ACCESS_TOKEN_VALIDITY_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.refreshTokenValidity").description(REFRESH_TOKEN_VALIDITY_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.samlConfig.assertionSigned").description(ASSERTION_SIGNED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.wantAssertionSigned").description(WANT_ASSERTION_SIGNED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.requestSigned").description(REQUEST_SIGNED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.wantAuthnRequestSigned").description(WANT_AUTHN_REQUEST_SIGNED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.assertionTimeToLiveSeconds").description(ASSERTION_TIME_TO_LIVE_SECONDS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.certificate").type(STRING).description(CERTIFICATE_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.privateKey").type(STRING).description(PRIVATE_KEY_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.privateKeyPassword").type(STRING).description(PRIVATE_KEY_PASSWORD_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.links.logout.redirectUrl").description(REDIRECT_URL_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.redirectParameterName").description(REDIRECT_PARAMETER_NAME_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.disableRedirectParameter").description(DISABLE_REDIRECT_PARAMETER_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.whitelist").type(ARRAY).description(WHITELIST_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.selfServiceLinksEnabled").description(SELF_SERVICE_LINKS_ENABLED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.signup").description(SIGNUP_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.passwd").description(PASSWD_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.prompts[]").type(ARRAY).description(PROMPTS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].name").description(PROMPTS_NAME_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].type").description(PROMPTS_TYPE_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].text").description(PROMPTS_TEXT_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.idpDiscoveryEnabled").description(IDP_DISCOVERY_ENABLED_FLAG).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.branding.companyName").description(BRANDING_COMPANY_NAME_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.branding.productLogo").description(BRANDING_PRODUCT_LOGO_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.branding.squareLogo").description(BRANDING_SQUARE_LOGO_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.branding.footerLegalText").description(BRANDING_FOOTER_LEGAL_TEXT_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.branding.footerLinks").description(BRANDING_FOOTER_LINKS_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("created").ignored(),
            fieldWithPath("last_modified").ignored()
        );

        getMockMvc().perform(
            put("/identity-zones/{id}", id)
                .header("Authorization", "Bearer " + identityClientWriteToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(updatedIdentityZone)))
            .andExpect(status().is(HttpStatus.OK.value()))
            .andDo(document("{ClassName}/{methodName}",
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint()),
                pathParameters(
                    parameterWithName("id").description("Unique ID of the identity zone to update")
                ),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token containing `zones.write` or `zones.<zone id>.admin`")
                ),
                requestFields,
                getResponseFields()
            ));
    }

    @Test
    public void deleteIdentityZone() throws Exception {
        String id = "twiglet-delete";
        createIdentityZoneHelper(id);

        String identityClientWriteToken = testClient.getClientCredentialsOAuthAccessToken(
            "identity",
            "identitysecret",
            "zones.write");

        getMockMvc().perform(
            delete("/identity-zones/{id}", id)
                .header("Authorization", "Bearer " + identityClientWriteToken)
                .contentType(APPLICATION_JSON))
            .andExpect(status().is(HttpStatus.OK.value()))
            .andDo(document("{ClassName}/{methodName}",
                preprocessResponse(prettyPrint()),
                pathParameters(
                    parameterWithName("id").description("Unique ID of the identity zone to delete")
                ),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token containing `zones.write`")
                ),
                getResponseFields()
            ));
    }

    private void createIdentityZoneHelper(String id) throws Exception {
        String identityClientWriteToken = testClient.getClientCredentialsOAuthAccessToken(
            "identity",
            "identitysecret",
            "zones.write");

        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(StringUtils.hasText(id) ? id : new RandomValueStringGenerator().generate());
        identityZone.setName("The Twiglet Zone");

        IdentityZoneConfiguration brandingConfig = setBranding(identityZone.getConfig());
        identityZone.setConfig(brandingConfig);


        getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientWriteToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone)))
            .andExpect(status().is(HttpStatus.CREATED.value()));
    }

    private Snippet getResponseFields() {
        return responseFields(
            fieldWithPath("id").description(ID_DESC),
            fieldWithPath("subdomain").description(SUBDOMAIN_DESC),
            fieldWithPath("name").description(NAME_DESC),
            fieldWithPath("description").type(STRING).description(DESCRIPTION_DESC).optional(),
            fieldWithPath("version").description(VERSION_DESC),

            fieldWithPath("config.tokenPolicy").description(TOKEN_POLICY_DESC),
            fieldWithPath("config.tokenPolicy.activeKeyId").type(STRING).description(ACTIVE_KEY_ID_DESC),
            fieldWithPath("config.tokenPolicy.keys").description(KEYS_DESC),
            fieldWithPath("config.tokenPolicy.accessTokenValidity").description(ACCESS_TOKEN_VALIDITY_DESC),
            fieldWithPath("config.tokenPolicy.refreshTokenValidity").description(REFRESH_TOKEN_VALIDITY_DESC),

            fieldWithPath("config.samlConfig.assertionSigned").description(ASSERTION_SIGNED_DESC),
            fieldWithPath("config.samlConfig.wantAssertionSigned").description(WANT_ASSERTION_SIGNED_DESC),
            fieldWithPath("config.samlConfig.requestSigned").description(REQUEST_SIGNED_DESC),
            fieldWithPath("config.samlConfig.wantAuthnRequestSigned").description(WANT_AUTHN_REQUEST_SIGNED_DESC),
            fieldWithPath("config.samlConfig.assertionTimeToLiveSeconds").description(ASSERTION_TIME_TO_LIVE_SECONDS_DESC),
            fieldWithPath("config.samlConfig.certificate").type(STRING).description(CERTIFICATE_DESC),
            fieldWithPath("config.samlConfig.privateKey").type(STRING).description(PRIVATE_KEY_DESC),
            fieldWithPath("config.samlConfig.privateKeyPassword").type(STRING).description(PRIVATE_KEY_PASSWORD_DESC),

            fieldWithPath("config.links.logout.redirectUrl").description(REDIRECT_URL_DESC),
            fieldWithPath("config.links.logout.redirectParameterName").description(REDIRECT_PARAMETER_NAME_DESC),
            fieldWithPath("config.links.logout.disableRedirectParameter").description(DISABLE_REDIRECT_PARAMETER_DESC),
            fieldWithPath("config.links.logout.whitelist").type(ARRAY).description(WHITELIST_DESC),
            fieldWithPath("config.links.selfService.selfServiceLinksEnabled").description(SELF_SERVICE_LINKS_ENABLED_DESC),
            fieldWithPath("config.links.selfService.signup").description(SIGNUP_DESC),
            fieldWithPath("config.links.selfService.passwd").description(PASSWD_DESC),

            fieldWithPath("config.prompts[]").type(ARRAY).description(PROMPTS_DESC),
            fieldWithPath("config.prompts[].name").description(PROMPTS_NAME_DESC),
            fieldWithPath("config.prompts[].type").description(PROMPTS_TYPE_DESC),
            fieldWithPath("config.prompts[].text").description(PROMPTS_TEXT_DESC),

            fieldWithPath("config.idpDiscoveryEnabled").description(IDP_DISCOVERY_ENABLED_FLAG),
            fieldWithPath("config.branding.companyName").description(BRANDING_COMPANY_NAME_DESC),
            fieldWithPath("config.branding.productLogo").description(BRANDING_PRODUCT_LOGO_DESC),
            fieldWithPath("config.branding.squareLogo").description(BRANDING_SQUARE_LOGO_DESC),
            fieldWithPath("config.branding.footerLegalText").description(BRANDING_FOOTER_LEGAL_TEXT_DESC),
            fieldWithPath("config.branding.footerLinks").description(BRANDING_FOOTER_LINKS_DESC),

            fieldWithPath("created").ignored(),
            fieldWithPath("last_modified").ignored()
        );
    }

    private IdentityZoneConfiguration setBranding(IdentityZoneConfiguration config){
        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName("Test Company");
        branding.setProductLogo("VGVzdFByb2R1Y3RMb2dv");
        branding.setSquareLogo("VGVzdFNxdWFyZUxvZ28=");
        branding.setFooterLegalText("Test footer legal text");
        branding.setFooterLinks(new HashMap<>());
        config.setBranding(branding);
        return config;
    }
}
