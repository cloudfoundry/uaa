package org.cloudfoundry.identity.uaa.mock.zones;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
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
import static org.springframework.restdocs.payload.JsonFieldType.*;
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
    private static final String LOCKOUT_PERIOD_SECONDS_DESC = "Number of seconds to lock out an account when lockoutAfterFailures failures is exceeded (defaults to 300).";
    private static final String LOCKOUT_AFTER_FAILURES_DESC = "Number of allowed failures before account is locked (defaults to 5).";
    private static final String LOCKOUT_COUNT_FAILURES_WITHIN_DESC = "Number of seconds in which lockoutAfterFailures failures must occur in order for account to be locked (defaults to 3600).";
    private static final String TOKEN_POLICY_DESC = "Various fields pertaining to the JWT access and refresh tokens.";
    private static final String ACTIVE_KEY_ID_DESC = "The ID for the key that is being used to sign tokens";
    private static final String KEYS_UPDATE_DESC = "Keys which will be used to sign the token. If null value is specified for keys, then existing value will be retained.";
    private static final String KEYS_DESC = "Keys which will be used to sign the token";
    private static final String ACCESS_TOKEN_VALIDITY_DESC = "Time in seconds between when a access token is issued and when it expires. Defaults to global `accessTokenValidity`";
    private static final String REFRESH_TOKEN_VALIDITY_DESC = "Time in seconds between when a refresh token is issued and when it expires. Defaults to global `refreshTokenValidity`";
    private static final String REFRESH_TOKEN_FORMAT = "The format for the refresh token. Allowed values are `jwt`, `opaque`. Defaults to `jwt`.";
    private static final String REFRESH_TOKEN_UNIQUE = "If true, uaa will only issue one refresh token per client_id/user_id combination. Defaults to `false`.";
    private static final String JWT_REVOCABLE_DESC = "Set to true if JWT tokens should be stored in the token store, and thus made individually revocable. Opaque tokens are always stored and revocable.";
    private static final String ASSERTION_SIGNED_DESC = "If `true`, the SAML provider will sign all assertions";
    private static final String WANT_ASSERTION_SIGNED_DESC = "Exposed SAML metadata property. If `true`, all assertions received by the SAML provider must be signed. Defaults to `true`.";
    private static final String REQUEST_SIGNED_DESC = "Exposed SAML metadata property. If `true`, the service provider will sign all outgoing authentication requests. Defaults to `true`.";
    private static final String WANT_AUTHN_REQUEST_SIGNED_DESC = "If `true`, the authentication request from the partner service provider must be signed.";
    private static final String ASSERTION_TIME_TO_LIVE_SECONDS_DESC = "The lifetime of a SAML assertion in seconds. Defaults to 600.";
    private static final String CERTIFICATE_DESC = "Exposed SAML metadata property. The certificate used to verify the authenticity all communications.";
    private static final String PRIVATE_KEY_DESC = "Exposed SAML metadata property. The SAML provider's private key.";
    private static final String PRIVATE_KEY_PASSWORD_DESC = "Exposed SAML metadata property. The SAML provider's private key password. Reserved for future use.";
    private static final String REDIRECT_URL_DESC = "Logout redirect url";
    private static final String HOMEREDIRECT_URL_DESC = "Overrides the UAA home page and issues a redirect to this URL when the browser requests `/` and `/home`.";
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
    private static final String ACCOUNT_CHOOSER_ENABLED_FLAG = "This flag is required to enable account choosing functionality for IDP discovery page.";
    private static final String BRANDING_COMPANY_NAME_DESC = "This name is used on the UAA Pages and in account management related communication in UAA";
    private static final String BRANDING_PRODUCT_LOGO_DESC = "This is a base64Url encoded PNG image which will be used as the logo on all UAA pages like Login, Sign Up etc.";
    private static final String BRANDING_SQUARE_LOGO_DESC = "This is a base64 encoded PNG image which will be used as the favicon for the UAA pages";
    private static final String BRANDING_FOOTER_LEGAL_TEXT_DESC = "This text appears on the footer of all UAA pages";
    private static final String BRANDING_FOOTER_LINKS_DESC = "These links (Map<String,String>) appear on the footer of all UAA pages. You may choose to add multiple urls for things like Support, Terms of Service etc.";

    private static final String CORS_XHR_ORIGINS_DESC = "`Access-Control-Allow-Origin header`. Indicates whether a resource can be shared based by returning the value of the Origin request header, \"*\", or \"null\" in the response.";
    private static final String CORS_XHR_ORIGIN_PATTERNS_DESC = "Indicates whether a resource can be shared based by returning the value of the Origin patterns.";
    private static final String CORS_XHR_URI_DESC = "The list of allowed URIs.";
    private static final String CORS_XHR_URI_PATTERNS_DESC = "The list of allowed URI patterns.";
    private static final String CORS_XHR_HEADERS_DESC = "`Access-Control-Allow-Headers` header. Indicates which header field names can be used during the actual response";
    private static final String CORS_XHR_METHODS_DESC = "`Access-Control-Allow-Methods` header. Indicates which method will be used in the actual request as part of the preflight request.";
    private static final String CORS_XHR_CREDENTIALS_DESC = "`Access-Control-Allow-Credentials` header. Indicates whether the response to request can be exposed when the omit credentials flag is unset. When part of the response to a preflight request it indicates that the actual request can include user credentials..";
    private static final String CORS_XHR_MAXAGE_DESC = "`Access-Control-Max-Age` header. Indicates how long the results of a preflight request can be cached in a preflight result cache";

    private static final String SERVICE_PROVIDER_KEY =
        "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIIBOwIBAAJBAJv8ZpB5hEK7qxP9K3v43hUS5fGT4waKe7ix4Z4mu5UBv+cw7WSF\n" +
        "At0Vaag0sAbsPzU8Hhsrj/qPABvfB8asUwcCAwEAAQJAG0r3ezH35WFG1tGGaUOr\n" +
        "QA61cyaII53ZdgCR1IU8bx7AUevmkFtBf+aqMWusWVOWJvGu2r5VpHVAIl8nF6DS\n" +
        "kQIhAMjEJ3zVYa2/Mo4ey+iU9J9Vd+WoyXDQD4EEtwmyG1PpAiEAxuZlvhDIbbce\n" +
        "7o5BvOhnCZ2N7kYb1ZC57g3F+cbJyW8CIQCbsDGHBto2qJyFxbAO7uQ8Y0UVHa0J\n" +
        "BO/g900SAcJbcQIgRtEljIShOB8pDjrsQPxmI1BLhnjD1EhRSubwhDw5AFUCIQCN\n" +
        "A24pDtdOHydwtSB5+zFqFLfmVZplQM/g5kb4so70Yw==\n" +
        "-----END RSA PRIVATE KEY-----\n";

    private static final String SERVICE_PROVIDER_KEY_PASSWORD = "password";

    private static final String SERVICE_PROVIDER_CERTIFICATE =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIICEjCCAXsCAg36MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG\n" +
        "A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE\n" +
        "MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl\n" +
        "YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw\n" +
        "ODIyMDUyNjU0WhcNMTcwODIxMDUyNjU0WjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE\n" +
        "CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs\n" +
        "ZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAm/xmkHmEQrurE/0re/jeFRLl\n" +
        "8ZPjBop7uLHhnia7lQG/5zDtZIUC3RVpqDSwBuw/NTweGyuP+o8AG98HxqxTBwID\n" +
        "AQABMA0GCSqGSIb3DQEBBQUAA4GBABS2TLuBeTPmcaTaUW/LCB2NYOy8GMdzR1mx\n" +
        "8iBIu2H6/E2tiY3RIevV2OW61qY2/XRQg7YPxx3ffeUugX9F4J/iPnnu1zAxxyBy\n" +
        "2VguKv4SWjRFoRkIfIlHX0qVviMhSlNy2ioFLy7JcPZb+v3ftDGywUqcBiVDoea0\n" +
        "Hn+GmxZA\n" +
        "-----END CERTIFICATE-----\n";

    public static final String SAML_ACTIVE_KEY_ID_DESC = "The ID of the key that should be used for signing metadata and assertions.";

    @Before
    public void setUp() throws Exception {
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
        SamlConfig samlConfig = new SamlConfig();
        samlConfig.setCertificate(SERVICE_PROVIDER_CERTIFICATE);
        samlConfig.setPrivateKey(SERVICE_PROVIDER_KEY);
        samlConfig.setPrivateKeyPassword(SERVICE_PROVIDER_KEY_PASSWORD);
        identityZone.getConfig().setSamlConfig(samlConfig);
        IdentityZoneConfiguration brandingConfig = setBranding(identityZone.getConfig());
        identityZone.setConfig(brandingConfig);

        FieldDescriptor[] fieldDescriptors = {
            fieldWithPath("id").description(ID_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("subdomain").description(SUBDOMAIN_DESC).attributes(key("constraints").value("Required")),
            fieldWithPath("name").description(NAME_DESC).attributes(key("constraints").value("Required")),
            fieldWithPath("description").description(DESCRIPTION_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("version").description(VERSION_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.tokenPolicy").description(TOKEN_POLICY_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.activeKeyId").optional().type(STRING).description(ACTIVE_KEY_ID_DESC).attributes(key("constraints").value("Required if `config.tokenPolicy.keys` are set")),
            fieldWithPath("config.tokenPolicy.keys.*.*").description(KEYS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.accessTokenValidity").description(ACCESS_TOKEN_VALIDITY_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.refreshTokenValidity").description(REFRESH_TOKEN_VALIDITY_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.jwtRevocable").type(BOOLEAN).description(JWT_REVOCABLE_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.refreshTokenUnique").type(BOOLEAN).description(REFRESH_TOKEN_UNIQUE).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.refreshTokenFormat").type(STRING).description(REFRESH_TOKEN_FORMAT).attributes(key("constraints").value("Optional")),


            fieldWithPath("config.samlConfig.assertionSigned").description(ASSERTION_SIGNED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.wantAssertionSigned").description(WANT_ASSERTION_SIGNED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.requestSigned").description(REQUEST_SIGNED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.wantAuthnRequestSigned").description(WANT_AUTHN_REQUEST_SIGNED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.assertionTimeToLiveSeconds").description(ASSERTION_TIME_TO_LIVE_SECONDS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.certificate").type(STRING).description(CERTIFICATE_DESC).attributes(key("constraints").value("Deprecated")),
            fieldWithPath("config.samlConfig.privateKey").type(STRING).description(PRIVATE_KEY_DESC).attributes(key("constraints").value("Deprecated")),
            fieldWithPath("config.samlConfig.privateKeyPassword").type(STRING).description(PRIVATE_KEY_PASSWORD_DESC).attributes(key("constraints").value("Deprecated")),
            fieldWithPath("config.samlConfig.activeKeyId").type(STRING).description(SAML_ACTIVE_KEY_ID_DESC).attributes(key("constraints").value("Required if a list of keys defined in `keys` map")),
            fieldWithPath("config.samlConfig.keys.*.key").type(STRING).description(PRIVATE_KEY_DESC).attributes(key("constraints").value("Optional. Can only be used in conjunction with `keys.<key-id>.passphrase` and `keys.<key-id>.certificate`")),
            fieldWithPath("config.samlConfig.keys.*.passphrase").type(STRING).description(PRIVATE_KEY_PASSWORD_DESC).attributes(key("constraints").value("Optional. Can only be used in conjunction with `keys.<key-id>.key` and `keys.<key-id>.certificate`")),
            fieldWithPath("config.samlConfig.keys.*.certificate").type(STRING).description(CERTIFICATE_DESC).attributes(key("constraints").value("Optional. Can only be used in conjunction with `keys.<key-id>.key` and `keys.<key-id>.passphrase`")),



            fieldWithPath("config.links.logout.redirectUrl").description(REDIRECT_URL_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.homeRedirect").description(HOMEREDIRECT_URL_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.redirectParameterName").description(REDIRECT_PARAMETER_NAME_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.disableRedirectParameter").description(DISABLE_REDIRECT_PARAMETER_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.whitelist").optional().type(ARRAY).description(WHITELIST_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.selfServiceLinksEnabled").description(SELF_SERVICE_LINKS_ENABLED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.signup").description(SIGNUP_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.passwd").description(PASSWD_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.prompts[]").type(ARRAY).description(PROMPTS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].name").description(PROMPTS_NAME_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].type").description(PROMPTS_TYPE_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].text").description(PROMPTS_TEXT_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.idpDiscoveryEnabled").description(IDP_DISCOVERY_ENABLED_FLAG).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.accountChooserEnabled").description(ACCOUNT_CHOOSER_ENABLED_FLAG).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.branding.companyName").description(BRANDING_COMPANY_NAME_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.branding.productLogo").description(BRANDING_PRODUCT_LOGO_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.branding.squareLogo").description(BRANDING_SQUARE_LOGO_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.branding.footerLegalText").description(BRANDING_FOOTER_LEGAL_TEXT_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.branding.footerLinks.*").description(BRANDING_FOOTER_LINKS_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedOrigins").description(CORS_XHR_ORIGINS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedOriginPatterns").description(CORS_XHR_ORIGIN_PATTERNS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedUris").description(CORS_XHR_URI_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedUriPatterns").description(CORS_XHR_URI_PATTERNS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedHeaders").description(CORS_XHR_HEADERS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedMethods").description(CORS_XHR_METHODS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedCredentials").description(CORS_XHR_CREDENTIALS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.xhrConfiguration.maxAge").description(CORS_XHR_MAXAGE_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedOrigins").description(CORS_XHR_ORIGINS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedOriginPatterns").description(CORS_XHR_ORIGIN_PATTERNS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedUris").description(CORS_XHR_URI_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedUriPatterns").description(CORS_XHR_URI_PATTERNS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedHeaders").description(CORS_XHR_HEADERS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedMethods").description(CORS_XHR_METHODS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedCredentials").description(CORS_XHR_CREDENTIALS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.defaultConfiguration.maxAge").description(CORS_XHR_MAXAGE_DESC).attributes(key("constraints").value("Optional")),


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
                    headerWithName("Authorization").description("Bearer token containing `zones.read` or `zones.write` or `zones.<zone id>.admin` or `zones.<zone id>.read`")
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

            fieldWithPath("[].config.tokenPolicy.activeKeyId").optional().type(STRING).description(ACTIVE_KEY_ID_DESC),
            fieldWithPath("[].config.tokenPolicy.accessTokenValidity").description(ACCESS_TOKEN_VALIDITY_DESC),
            fieldWithPath("[].config.tokenPolicy.refreshTokenValidity").description(REFRESH_TOKEN_VALIDITY_DESC),
            fieldWithPath("[].config.tokenPolicy.jwtRevocable").type(BOOLEAN).description(JWT_REVOCABLE_DESC),
            fieldWithPath("[].config.tokenPolicy.refreshTokenUnique").type(BOOLEAN).description(REFRESH_TOKEN_UNIQUE).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.tokenPolicy.refreshTokenFormat").type(STRING).description(REFRESH_TOKEN_FORMAT).attributes(key("constraints").value("Optional")),

            fieldWithPath("[].config.samlConfig.assertionSigned").description(ASSERTION_SIGNED_DESC),
            fieldWithPath("[].config.samlConfig.wantAssertionSigned").description(WANT_ASSERTION_SIGNED_DESC),
            fieldWithPath("[].config.samlConfig.requestSigned").description(REQUEST_SIGNED_DESC),
            fieldWithPath("[].config.samlConfig.wantAuthnRequestSigned").description(WANT_AUTHN_REQUEST_SIGNED_DESC),
            fieldWithPath("[].config.samlConfig.assertionTimeToLiveSeconds").description(ASSERTION_TIME_TO_LIVE_SECONDS_DESC),
            fieldWithPath("[].config.samlConfig.certificate").type(STRING).description(CERTIFICATE_DESC).attributes(key("constraints").value("Deprecated")),

            fieldWithPath("[].config.samlConfig.activeKeyId").type(STRING).description(SAML_ACTIVE_KEY_ID_DESC),
            fieldWithPath("[].config.samlConfig.keys").ignored().type(OBJECT).description(CERTIFICATE_DESC),
            fieldWithPath("[].config.samlConfig.keys.*").type(OBJECT).description(CERTIFICATE_DESC),
            fieldWithPath("[].config.samlConfig.keys.*.certificate").type(STRING).description(CERTIFICATE_DESC),

            fieldWithPath("[].config.links.logout.redirectUrl").description(REDIRECT_URL_DESC),
            fieldWithPath("[].config.links.homeRedirect").description(HOMEREDIRECT_URL_DESC),
            fieldWithPath("[].config.links.logout.redirectParameterName").description(REDIRECT_PARAMETER_NAME_DESC),
            fieldWithPath("[].config.links.logout.disableRedirectParameter").description(DISABLE_REDIRECT_PARAMETER_DESC),
            fieldWithPath("[].config.links.logout.whitelist").optional().type(ARRAY).description(WHITELIST_DESC),
            fieldWithPath("[].config.links.selfService.selfServiceLinksEnabled").description(SELF_SERVICE_LINKS_ENABLED_DESC),
            fieldWithPath("[].config.links.selfService.signup").description(SIGNUP_DESC),
            fieldWithPath("[].config.links.selfService.passwd").description(PASSWD_DESC),

            fieldWithPath("[].config.branding.companyName").description(BRANDING_COMPANY_NAME_DESC),
            fieldWithPath("[].config.branding.productLogo").description(BRANDING_PRODUCT_LOGO_DESC),
            fieldWithPath("[].config.branding.squareLogo").description(BRANDING_SQUARE_LOGO_DESC),
            fieldWithPath("[].config.branding.footerLegalText").description(BRANDING_FOOTER_LEGAL_TEXT_DESC),
            fieldWithPath("[].config.branding.footerLinks").description(BRANDING_FOOTER_LINKS_DESC),


            fieldWithPath("[].config.prompts[]").type(OBJECT).description(PROMPTS_DESC),
            fieldWithPath("[].config.prompts[].name").description(PROMPTS_DESC),
            fieldWithPath("[].config.prompts[].type").description(PROMPTS_TYPE_DESC),
            fieldWithPath("[].config.prompts[].text").description(PROMPTS_TEXT_DESC),

            fieldWithPath("[].config.idpDiscoveryEnabled").description(IDP_DISCOVERY_ENABLED_FLAG),
            fieldWithPath("[].config.accountChooserEnabled").description(ACCOUNT_CHOOSER_ENABLED_FLAG),

            fieldWithPath("[].config.branding.companyName").description(BRANDING_COMPANY_NAME_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.branding.productLogo").description(BRANDING_PRODUCT_LOGO_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.branding.squareLogo").description(BRANDING_SQUARE_LOGO_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.branding.footerLegalText").description(BRANDING_FOOTER_LEGAL_TEXT_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.branding.footerLinks.*").description(BRANDING_FOOTER_LINKS_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("[].config.corsPolicy.xhrConfiguration.allowedOrigins").description(CORS_XHR_ORIGINS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.corsPolicy.xhrConfiguration.allowedOriginPatterns").description(CORS_XHR_ORIGIN_PATTERNS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.corsPolicy.xhrConfiguration.allowedUris").description(CORS_XHR_URI_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.corsPolicy.xhrConfiguration.allowedUriPatterns").description(CORS_XHR_URI_PATTERNS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.corsPolicy.xhrConfiguration.allowedHeaders").description(CORS_XHR_HEADERS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.corsPolicy.xhrConfiguration.allowedMethods").description(CORS_XHR_METHODS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.corsPolicy.xhrConfiguration.allowedCredentials").description(CORS_XHR_CREDENTIALS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.corsPolicy.xhrConfiguration.maxAge").description(CORS_XHR_MAXAGE_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("[].config.corsPolicy.defaultConfiguration.allowedOrigins").description(CORS_XHR_ORIGINS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.corsPolicy.defaultConfiguration.allowedOriginPatterns").description(CORS_XHR_ORIGIN_PATTERNS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.corsPolicy.defaultConfiguration.allowedUris").description(CORS_XHR_URI_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.corsPolicy.defaultConfiguration.allowedUriPatterns").description(CORS_XHR_URI_PATTERNS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.corsPolicy.defaultConfiguration.allowedHeaders").description(CORS_XHR_HEADERS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.corsPolicy.defaultConfiguration.allowedMethods").description(CORS_XHR_METHODS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.corsPolicy.defaultConfiguration.allowedCredentials").description(CORS_XHR_CREDENTIALS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("[].config.corsPolicy.defaultConfiguration.maxAge").description(CORS_XHR_MAXAGE_DESC).attributes(key("constraints").value("Optional")),

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
        SamlConfig samlConfig = new SamlConfig();
        samlConfig.setPrivateKey(SERVICE_PROVIDER_KEY);
        samlConfig.setPrivateKeyPassword(SERVICE_PROVIDER_KEY_PASSWORD);
        samlConfig.setCertificate(SERVICE_PROVIDER_CERTIFICATE);
        updatedIdentityZone.getConfig().setSamlConfig(samlConfig);
        IdentityZoneConfiguration brandingConfig = setBranding(updatedIdentityZone.getConfig());
        updatedIdentityZone.setConfig(brandingConfig);

        Snippet requestFields = requestFields(
            fieldWithPath("subdomain").description(SUBDOMAIN_DESC).attributes(key("constraints").value("Required")),
            fieldWithPath("name").description(NAME_DESC).attributes(key("constraints").value("Required")),
            fieldWithPath("description").description(DESCRIPTION_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("version").description(VERSION_DESC).attributes(key("constraints").value("Optional")),


            fieldWithPath("config.tokenPolicy.activeKeyId").optional().type(STRING).description(ACTIVE_KEY_ID_DESC).attributes(key("constraints").value("Required if `config.tokenPolicy.keys` are set")),
            fieldWithPath("config.tokenPolicy.keys.*.*").description(KEYS_UPDATE_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.accessTokenValidity").description(ACCESS_TOKEN_VALIDITY_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.refreshTokenValidity").description(REFRESH_TOKEN_VALIDITY_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.jwtRevocable").type(BOOLEAN).description(JWT_REVOCABLE_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.refreshTokenUnique").type(BOOLEAN).description(REFRESH_TOKEN_UNIQUE).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.refreshTokenFormat").type(STRING).description(REFRESH_TOKEN_FORMAT).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.samlConfig.assertionSigned").description(ASSERTION_SIGNED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.wantAssertionSigned").description(WANT_ASSERTION_SIGNED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.requestSigned").description(REQUEST_SIGNED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.wantAuthnRequestSigned").description(WANT_AUTHN_REQUEST_SIGNED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.assertionTimeToLiveSeconds").description(ASSERTION_TIME_TO_LIVE_SECONDS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.certificate").type(STRING).description(CERTIFICATE_DESC).attributes(key("constraints").value("Deprecated")),
            fieldWithPath("config.samlConfig.privateKey").type(STRING).description(PRIVATE_KEY_DESC).attributes(key("constraints").value("Deprecated")),
            fieldWithPath("config.samlConfig.privateKeyPassword").type(STRING).description(PRIVATE_KEY_PASSWORD_DESC).attributes(key("constraints").value("Deprecated")),
            fieldWithPath("config.samlConfig.activeKeyId").type(STRING).description(SAML_ACTIVE_KEY_ID_DESC).attributes(key("constraints").value("Required if a list of keys defined in `keys` map")),
            fieldWithPath("config.samlConfig.keys.*.key").type(STRING).description(PRIVATE_KEY_DESC).attributes(key("constraints").value("Optional. Can only be used in conjunction with `keys.<key-id>.passphrase` and `keys.<key-id>.certificate`")),
            fieldWithPath("config.samlConfig.keys.*.passphrase").type(STRING).description(PRIVATE_KEY_PASSWORD_DESC).attributes(key("constraints").value("Optional. Can only be used in conjunction with `keys.<key-id>.key` and `keys.<key-id>.certificate`")),
            fieldWithPath("config.samlConfig.keys.*.certificate").type(STRING).description(CERTIFICATE_DESC).attributes(key("constraints").value("Optional. Can only be used in conjunction with `keys.<key-id>.key` and `keys.<key-id>.passphrase`")),

            fieldWithPath("config.links.logout.redirectUrl").description(REDIRECT_URL_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.homeRedirect").description(HOMEREDIRECT_URL_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.redirectParameterName").description(REDIRECT_PARAMETER_NAME_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.disableRedirectParameter").description(DISABLE_REDIRECT_PARAMETER_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.whitelist").optional().type(ARRAY).description(WHITELIST_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.selfServiceLinksEnabled").description(SELF_SERVICE_LINKS_ENABLED_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.signup").description(SIGNUP_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.passwd").description(PASSWD_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.prompts[]").type(ARRAY).description(PROMPTS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].name").description(PROMPTS_NAME_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].type").description(PROMPTS_TYPE_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].text").description(PROMPTS_TEXT_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.idpDiscoveryEnabled").description(IDP_DISCOVERY_ENABLED_FLAG).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.accountChooserEnabled").description(ACCOUNT_CHOOSER_ENABLED_FLAG).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.branding.companyName").description(BRANDING_COMPANY_NAME_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.branding.productLogo").description(BRANDING_PRODUCT_LOGO_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.branding.squareLogo").description(BRANDING_SQUARE_LOGO_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.branding.footerLegalText").description(BRANDING_FOOTER_LEGAL_TEXT_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.branding.footerLinks.*").description(BRANDING_FOOTER_LINKS_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedOrigins").description(CORS_XHR_ORIGINS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedOriginPatterns").description(CORS_XHR_ORIGIN_PATTERNS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedUris").description(CORS_XHR_URI_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedUriPatterns").description(CORS_XHR_URI_PATTERNS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedHeaders").description(CORS_XHR_HEADERS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedMethods").description(CORS_XHR_METHODS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedCredentials").description(CORS_XHR_CREDENTIALS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.xhrConfiguration.maxAge").description(CORS_XHR_MAXAGE_DESC).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedOrigins").description(CORS_XHR_ORIGINS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedOriginPatterns").description(CORS_XHR_ORIGIN_PATTERNS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedUris").description(CORS_XHR_URI_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedUriPatterns").description(CORS_XHR_URI_PATTERNS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedHeaders").description(CORS_XHR_HEADERS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedMethods").description(CORS_XHR_METHODS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedCredentials").description(CORS_XHR_CREDENTIALS_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.corsPolicy.defaultConfiguration.maxAge").description(CORS_XHR_MAXAGE_DESC).attributes(key("constraints").value("Optional")),

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
        SamlConfig samlConfig = new SamlConfig();
        samlConfig.setCertificate(SERVICE_PROVIDER_CERTIFICATE);
        samlConfig.setPrivateKey(SERVICE_PROVIDER_KEY);
        samlConfig.setPrivateKeyPassword(SERVICE_PROVIDER_KEY_PASSWORD);
        identityZone.getConfig().setSamlConfig(samlConfig);
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

            fieldWithPath("config.tokenPolicy.activeKeyId").optional().type(STRING).description(ACTIVE_KEY_ID_DESC),
            fieldWithPath("config.tokenPolicy.accessTokenValidity").description(ACCESS_TOKEN_VALIDITY_DESC),
            fieldWithPath("config.tokenPolicy.refreshTokenValidity").description(REFRESH_TOKEN_VALIDITY_DESC),
            fieldWithPath("config.tokenPolicy.jwtRevocable").type(BOOLEAN).description(JWT_REVOCABLE_DESC).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.refreshTokenUnique").type(BOOLEAN).description(REFRESH_TOKEN_UNIQUE).attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.refreshTokenFormat").type(STRING).description(REFRESH_TOKEN_FORMAT).attributes(key("constraints").value("Optional")),

            fieldWithPath("config.samlConfig.assertionSigned").description(ASSERTION_SIGNED_DESC),
            fieldWithPath("config.samlConfig.wantAssertionSigned").description(WANT_ASSERTION_SIGNED_DESC),
            fieldWithPath("config.samlConfig.requestSigned").description(REQUEST_SIGNED_DESC),
            fieldWithPath("config.samlConfig.wantAuthnRequestSigned").description(WANT_AUTHN_REQUEST_SIGNED_DESC),
            fieldWithPath("config.samlConfig.assertionTimeToLiveSeconds").description(ASSERTION_TIME_TO_LIVE_SECONDS_DESC),
            fieldWithPath("config.samlConfig.certificate").type(STRING).description(CERTIFICATE_DESC).attributes(key("constraints").value("Deprecated")),
            fieldWithPath("config.samlConfig.activeKeyId").optional().type(STRING).description(SAML_ACTIVE_KEY_ID_DESC),
            fieldWithPath("config.samlConfig.keys.*.certificate").type(STRING).description(CERTIFICATE_DESC),

            fieldWithPath("config.links.logout.redirectUrl").description(REDIRECT_URL_DESC),
            fieldWithPath("config.links.homeRedirect").description(HOMEREDIRECT_URL_DESC),
            fieldWithPath("config.links.logout.redirectParameterName").description(REDIRECT_PARAMETER_NAME_DESC),
            fieldWithPath("config.links.logout.disableRedirectParameter").description(DISABLE_REDIRECT_PARAMETER_DESC),
            fieldWithPath("config.links.logout.whitelist").optional().type(ARRAY).description(WHITELIST_DESC),
            fieldWithPath("config.links.selfService.selfServiceLinksEnabled").description(SELF_SERVICE_LINKS_ENABLED_DESC),
            fieldWithPath("config.links.selfService.signup").description(SIGNUP_DESC),
            fieldWithPath("config.links.selfService.passwd").description(PASSWD_DESC),

            fieldWithPath("config.prompts[]").type(ARRAY).description(PROMPTS_DESC),
            fieldWithPath("config.prompts[].name").description(PROMPTS_NAME_DESC),
            fieldWithPath("config.prompts[].type").description(PROMPTS_TYPE_DESC),
            fieldWithPath("config.prompts[].text").description(PROMPTS_TEXT_DESC),

            fieldWithPath("config.idpDiscoveryEnabled").description(IDP_DISCOVERY_ENABLED_FLAG),
            fieldWithPath("config.accountChooserEnabled").description(ACCOUNT_CHOOSER_ENABLED_FLAG),
            fieldWithPath("config.branding.companyName").description(BRANDING_COMPANY_NAME_DESC),
            fieldWithPath("config.branding.productLogo").description(BRANDING_PRODUCT_LOGO_DESC),
            fieldWithPath("config.branding.squareLogo").description(BRANDING_SQUARE_LOGO_DESC),
            fieldWithPath("config.branding.footerLegalText").description(BRANDING_FOOTER_LEGAL_TEXT_DESC),
            fieldWithPath("config.branding.footerLinks.*").description(BRANDING_FOOTER_LINKS_DESC),

            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedOrigins").description(CORS_XHR_ORIGINS_DESC),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedOriginPatterns").description(CORS_XHR_ORIGIN_PATTERNS_DESC),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedUris").description(CORS_XHR_URI_DESC),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedUriPatterns").description(CORS_XHR_URI_PATTERNS_DESC),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedHeaders").description(CORS_XHR_HEADERS_DESC),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedMethods").description(CORS_XHR_METHODS_DESC),
            fieldWithPath("config.corsPolicy.defaultConfiguration.allowedCredentials").description(CORS_XHR_CREDENTIALS_DESC),
            fieldWithPath("config.corsPolicy.defaultConfiguration.maxAge").description(CORS_XHR_MAXAGE_DESC),

            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedOrigins").description(CORS_XHR_ORIGINS_DESC),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedOriginPatterns").description(CORS_XHR_ORIGIN_PATTERNS_DESC),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedUris").description(CORS_XHR_URI_DESC),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedUriPatterns").description(CORS_XHR_URI_PATTERNS_DESC),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedHeaders").description(CORS_XHR_HEADERS_DESC),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedMethods").description(CORS_XHR_METHODS_DESC),
            fieldWithPath("config.corsPolicy.xhrConfiguration.allowedCredentials").description(CORS_XHR_CREDENTIALS_DESC),
            fieldWithPath("config.corsPolicy.xhrConfiguration.maxAge").description(CORS_XHR_MAXAGE_DESC),

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
        HashMap<String, String> footerLinks = new HashMap<>();
        footerLinks.put("Support", "http://support.example.com");
        branding.setFooterLinks(footerLinks);
        config.setBranding(branding);
        config.getLinks().setHomeRedirect("http://my.hosted.homepage.com/");
        return config;
    }
}
