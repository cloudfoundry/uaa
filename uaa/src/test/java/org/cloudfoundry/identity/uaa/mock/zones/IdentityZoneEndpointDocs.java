package org.cloudfoundry.identity.uaa.mock.zones;

import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.mock.EndpointDocs;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation.Banner;
import org.cloudfoundry.identity.uaa.zone.Consent;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.restdocs.headers.HeaderDescriptor;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.util.StringUtils;

import java.util.Collections;
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
import static org.springframework.restdocs.payload.JsonFieldType.BOOLEAN;
import static org.springframework.restdocs.payload.JsonFieldType.NUMBER;
import static org.springframework.restdocs.payload.JsonFieldType.OBJECT;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.JsonFieldType.VARIES;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class IdentityZoneEndpointDocs extends EndpointDocs {
    private static final String ID_DESC = "Unique ID of the identity zone";
    private static final String SUBDOMAIN_DESC = "Unique subdomain for the running instance. May only contain legal characters for a subdomain name.";
    private static final String NAME_DESC = "Human-readable zone name";
    private static final String DESCRIPTION_DESC = "Description of the zone";
    private static final String VERSION_DESC = "Reserved for future use of E-Tag versioning";
    private static final String ACTIVE_DESC = "Indicates whether the identity zone is active. Defaults to true.";
    private static final String TOKEN_POLICY_DESC = "Various fields pertaining to the JWT access and refresh tokens.";
    private static final String ACTIVE_KEY_ID_DESC = "The ID for the key that is being used to sign tokens";
    private static final String KEYS_UPDATE_DESC = "Keys which will be used to sign the token. If null value is specified for keys, then existing value will be retained.";
    private static final String KEYS_DESC = "Keys which will be used to sign the token";
    private static final String KEYS_ALG_DESC = "Algorithm parameter according to [RFC7518](https://tools.ietf.org/html/rfc7518#section-3.1)";
    private static final String KEYS_CERT_DESC = "PEM encoded X.509 to be used in x5c, e.g. [RFC7517](https://tools.ietf.org/html/rfc7517#section-4.7)";
    private static final String ACCESS_TOKEN_VALIDITY_DESC = "Time in seconds between when a access token is issued and when it expires. Defaults to global `accessTokenValidity`";
    private static final String REFRESH_TOKEN_VALIDITY_DESC = "Time in seconds between when a refresh token is issued and when it expires. Defaults to global `refreshTokenValidity`";
    private static final String REFRESH_TOKEN_FORMAT = "The format for the refresh token. Allowed values are `jwt`, `opaque`. Defaults to `opaque`.";
    private static final String REFRESH_TOKEN_UNIQUE = "If true, uaa will only issue one refresh token per client_id/user_id combination. Defaults to `false`.";
    private static final String REFRESH_TOKEN_ROTATE = "If true, uaa will issue a new refresh token value in grant type refresh_token. Defaults to `false`.";
    private static final String JWT_REVOCABLE_DESC = "Set to true if JWT tokens should be stored in the token store, and thus made individually revocable. Opaque tokens are always stored and revocable.";
    private static final String ENTITY_ID_DESC = "Unique ID of the SAML2 entity";
    private static final String WANT_ASSERTION_SIGNED_DESC = "Exposed SAML metadata property. If `true`, all assertions received by the SAML provider must be signed. Defaults to `true`.";
    private static final String REQUEST_SIGNED_DESC = "Exposed SAML metadata property. If `true`, the service provider will sign all outgoing authentication requests. Defaults to `true`.";
    private static final String SAML_DISABLE_IN_RESPONSE_TO_DESC = "If `true`, this zone will not validate the `InResponseToField` part of an incoming IDP assertion. Please see https://docs.spring.io/spring-security-saml/docs/current/reference/html/chapter-troubleshooting.html";
    private static final String CERTIFICATE_DESC = "Exposed SAML metadata property. The certificate used to verify the authenticity all communications.";
    private static final String PRIVATE_KEY_DESC = "Exposed SAML metadata property. The SAML provider's private key.";
    private static final String PRIVATE_KEY_PASSWORD_DESC = "Exposed SAML metadata property. The SAML provider's private key password. Reserved for future use.";
    private static final String REDIRECT_URL_DESC = "Logout redirect url";
    private static final String HOMEREDIRECT_URL_DESC = "Overrides the UAA home page and issues a redirect to this URL when the browser requests `/` and `/home`.";
    private static final String REDIRECT_PARAMETER_NAME_DESC = "Changes the name of the redirect parameter";
    private static final String DISABLE_REDIRECT_PARAMETER_DESC = "Deprecated, no longer affects zone behavior. Whether or not to allow the redirect parameter on logout";
    private static final String WHITELIST_DESC = "List of allowed whitelist redirects";
    private static final String SELF_SERVICE_LINKS_ENABLED_DESC = "Whether or not users are allowed to sign up or reset their passwords via the UI";
    private static final String SIGNUP_DESC = "Where users are directed upon clicking the account creation link";
    private static final String PASSWD_DESC = "Where users are directed upon clicking the password reset link";
    private static final String PROMPTS_DESC = "List of fields that users are prompted for to login. Defaults to username, password, and passcode.";
    private static final String PROMPTS_NAME_DESC = "Name of field";
    private static final String PROMPTS_TYPE_DESC = "What kind of field this is (e.g. text or password)";
    private static final String PROMPTS_TEXT_DESC = "Actual text displayed on prompt for field";
    private static final String IDP_DISCOVERY_ENABLED_FLAG = "IDP Discovery should be set to true if you have configured more than one identity provider for UAA. The discovery relies on email domain being set for each additional provider";
    private static final String ACCOUNT_CHOOSER_ENABLED_FLAG = "This flag enables the account choosing functionality. If idpDiscoveryEnabled is set to true in the config the IDP is chosen by discovery. Otherwise, the user can enter the IDP by providing the origin.";
    private static final String BRANDING_COMPANY_NAME_DESC = "This name is used on the UAA Pages and in account management related communication in UAA";
    private static final String BRANDING_PRODUCT_LOGO_DESC = "This is a base64Url encoded PNG image which will be used as the logo on all UAA pages like Login, Sign Up etc.";
    private static final String BRANDING_SQUARE_LOGO_DESC = "This is a base64 encoded PNG image which will be used as the favicon for the UAA pages";
    private static final String BRANDING_FOOTER_LEGAL_TEXT_DESC = "This text appears on the footer of all UAA pages";
    private static final String BRANDING_FOOTER_LINKS_DESC = "These links (Map<String,String>) appear on the footer of all UAA pages. You may choose to add multiple urls for things like Support, Terms of Service etc.";

    private static final String BRANDING_BANNER_TEXT_DESC = "This is text displayed in a banner at the top of the UAA login page";
    private static final String BRANDING_BANNER_LOGO_DESC = "This is base64 encoded PNG data displayed in a banner at the top of the UAA login page, overrides banner text";
    private static final String BRANDING_BANNER_LINK_DESC = "The UAA login banner will be a link pointing to this url";
    private static final String BRANDING_BANNER_TEXT_COLOR_DESC = "Hexadecimal color code for banner text color, does not allow color names";
    private static final String BRANDING_BANNER_BACKGROUND_COLOR_DESC = "Hexadecimal color code for banner background color, does not allow color names";

    private static final String BRANDING_CONSENT_TEXT_DESC = "If set, a checkbox on the registration and invitation pages will appear with the phrase `I agree to` followed by this text. The checkbox must be selected before the user can continue.";
    private static final String BRANDING_CONSENT_LINK_DESC = "If `config.branding.consent.text` is set, the text after `I agree to` will be hyperlinked to this location.";

    private static final String CORS_XHR_ORIGINS_DESC = "`Access-Control-Allow-Origin header`. Indicates whether a resource can be shared based by returning the value of the Origin request header, \"*\", or \"null\" in the response.";
    private static final String CORS_XHR_ORIGIN_PATTERNS_DESC = "Indicates whether a resource can be shared based by returning the value of the Origin patterns.";
    private static final String CORS_XHR_URI_DESC = "The list of allowed URIs.";
    private static final String CORS_XHR_URI_PATTERNS_DESC = "The list of allowed URI patterns.";
    private static final String CORS_XHR_HEADERS_DESC = "`Access-Control-Allow-Headers` header. Indicates which header field names can be used during the actual response";
    private static final String CORS_XHR_METHODS_DESC = "`Access-Control-Allow-Methods` header. Indicates which method will be used in the actual request as part of the preflight request.";
    private static final String CORS_XHR_CREDENTIALS_DESC = "`Access-Control-Allow-Credentials` header. Indicates whether the response to request can be exposed when the omit credentials flag is unset. When part of the response to a preflight request it indicates that the actual request can include user credentials..";
    private static final String CORS_XHR_MAXAGE_DESC = "`Access-Control-Max-Age` header. Indicates how long the results of a preflight request can be cached in a preflight result cache";
    private static final String SECRET_POLICY_MIN_LENGTH = "Minimum number of characters required for secret to be considered valid (defaults to 0).";
    private static final String SECRET_POLICY_MAX_LENGTH = "Maximum number of characters required for secret to be considered valid (defaults to 255).";
    private static final String SECRET_POLICY_UPPERCASE = "Minimum number of uppercase characters required for secret to be considered valid (defaults to 0).";
    private static final String SECRET_POLICY_LOWERCASE = "Minimum number of lowercase characters required for secret to be considered valid (defaults to 0).";
    private static final String SECRET_POLICY_DIGIT = "Minimum number of digits required for secret to be considered valid (defaults to 0).";
    private static final String SECRET_POLICY_SPECIAL_CHAR = "Minimum number of special characters required for secret to be considered valid (defaults to 0).";
    private static final String USER_CONFIG_USER_LIMIT_DESCRIPTION = "Number of users in the zone. If more than 0, it limits the amount of users in the zone. (defaults to -1, no limit).";
    private static final String USER_CONFIG_USER_LIMIT_CONSTRAINT = "Optional number, default -1, no limit.";
    private static final String USER_CONFIG_CHECK_ORIGIN_ENABLED = "Flag for switching on the check if origin is valid when creating or updating users (defaults to false)";
    private static final String USER_CONFIG_ALLOW_ORIGIN_LOOP = "Flag for switching off the loop over all origins in a zone (defaults to true)";

    private static final String SERVICE_PROVIDER_KEY =
            """
                    -----BEGIN RSA PRIVATE KEY-----
                    MIIBOwIBAAJBAJv8ZpB5hEK7qxP9K3v43hUS5fGT4waKe7ix4Z4mu5UBv+cw7WSF
                    At0Vaag0sAbsPzU8Hhsrj/qPABvfB8asUwcCAwEAAQJAG0r3ezH35WFG1tGGaUOr
                    QA61cyaII53ZdgCR1IU8bx7AUevmkFtBf+aqMWusWVOWJvGu2r5VpHVAIl8nF6DS
                    kQIhAMjEJ3zVYa2/Mo4ey+iU9J9Vd+WoyXDQD4EEtwmyG1PpAiEAxuZlvhDIbbce
                    7o5BvOhnCZ2N7kYb1ZC57g3F+cbJyW8CIQCbsDGHBto2qJyFxbAO7uQ8Y0UVHa0J
                    BO/g900SAcJbcQIgRtEljIShOB8pDjrsQPxmI1BLhnjD1EhRSubwhDw5AFUCIQCN
                    A24pDtdOHydwtSB5+zFqFLfmVZplQM/g5kb4so70Yw==
                    -----END RSA PRIVATE KEY-----
                    """;

    private static final String SERVICE_PROVIDER_KEY_PASSWORD = "password";

    private static final String SERVICE_PROVIDER_CERTIFICATE =
            """
                    -----BEGIN CERTIFICATE-----
                    MIICEjCCAXsCAg36MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
                    A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
                    MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
                    YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
                    ODIyMDUyNjU0WhcNMTcwODIxMDUyNjU0WjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
                    CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
                    ZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAm/xmkHmEQrurE/0re/jeFRLl
                    8ZPjBop7uLHhnia7lQG/5zDtZIUC3RVpqDSwBuw/NTweGyuP+o8AG98HxqxTBwID
                    AQABMA0GCSqGSIb3DQEBBQUAA4GBABS2TLuBeTPmcaTaUW/LCB2NYOy8GMdzR1mx
                    8iBIu2H6/E2tiY3RIevV2OW61qY2/XRQg7YPxx3ffeUugX9F4J/iPnnu1zAxxyBy
                    2VguKv4SWjRFoRkIfIlHX0qVviMhSlNy2ioFLy7JcPZb+v3ftDGywUqcBiVDoea0
                    Hn+GmxZA
                    -----END CERTIFICATE-----
                    """;

    private static final String SAML_ACTIVE_KEY_ID_DESC = "The ID of the key that should be used for signing metadata and assertions.";
    private static final String DEFAULT_ZONE_GROUPS_DESC = "Default groups each user in the zone inherits.";
    private static final String ALLOWED_ZONE_GROUPS_DESC = "Allowed groups in the zone. Defaults to null (all groups allowed)";
    private static final String SERVICE_PROVIDER_ID = "cloudfoundry-saml-login";
    private static final String ZONE_ISSUER_DESC = "Issuer of this zone. Must be a valid URL.";
    private static final String DEFAULT_IDP_DESC = "This value can be set to the origin key of an identity provider. If set, the user will be directed to this identity provider automatically if no other identity provider is discovered or selected via login_hint.";
    private static final String DEFAULT_ISSUER_URI = "http://localhost:8080/uaa";

    private static final HeaderDescriptor IDENTITY_ZONE_ID_HEADER = headerWithName(IdentityZoneSwitchingFilter.HEADER).description("May include this header to administer another zone if using `zones.<zoneId>.admin` or `uaa.admin` scope against the default UAA zone.").optional();
    private static final HeaderDescriptor IDENTITY_ZONE_SUBDOMAIN_HEADER = headerWithName(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER).optional().description("If using a `zones.<zoneId>.admin` scope/token, indicates what Identity Zone this request goes to by supplying a subdomain.");

    @BeforeEach
    void setUp() {
        Map<String, SystemDeletable> deleteMe = webApplicationContext.getBeansOfType(SystemDeletable.class);
        webApplicationContext.getBean(JdbcIdentityZoneProvisioning.class)
                .retrieveAll()
                .stream()
                .filter(zone -> !IdentityZone.getUaaZoneId().equals(zone.getId()))
                .forEach(zone -> deleteMe.values().forEach(deletable -> deletable.deleteByIdentityZone(zone.getId())));
    }

    @Test
    void createIdentityZone() throws Exception {
        String identityClientWriteToken = testClient.getClientCredentialsOAuthAccessToken(
                "identity",
                "identitysecret",
                "zones.write");

        String id = "twiglet-create";
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(StringUtils.hasText(id) ? id : new AlphanumericRandomValueStringGenerator().generate());
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        Map<String, String> keys = new HashMap<>();
        keys.put("exampleKeyId", "s1gNiNg.K3y/t3XT");
        identityZone.getConfig().getTokenPolicy().setKeys(keys);
        SamlConfig samlConfig = new SamlConfig();
        samlConfig.setCertificate(SERVICE_PROVIDER_CERTIFICATE);
        samlConfig.setPrivateKey(SERVICE_PROVIDER_KEY);
        samlConfig.setPrivateKeyPassword(SERVICE_PROVIDER_KEY_PASSWORD);
        samlConfig.setEntityID(SERVICE_PROVIDER_ID);
        identityZone.getConfig().setIssuer(DEFAULT_ISSUER_URI);
        identityZone.getConfig().setSamlConfig(samlConfig);
        TokenPolicy tokenPolicy = new TokenPolicy(3600, 7200);
        tokenPolicy.setActiveKeyId("active-key-1");
        TokenPolicy.KeyInformation keyInformation = new TokenPolicy.KeyInformation();
        keyInformation.setSigningKey(SERVICE_PROVIDER_KEY);
        keyInformation.setSigningAlg("RS256");
        keyInformation.setSigningCert(SERVICE_PROVIDER_CERTIFICATE);
        tokenPolicy.setKeyInformation(Collections.singletonMap("active-key-1", keyInformation));
        identityZone.getConfig().setTokenPolicy(tokenPolicy);
        IdentityZoneConfiguration brandingConfig = setBranding(identityZone.getConfig());
        identityZone.setConfig(brandingConfig);
        identityZone.getConfig().setDefaultIdentityProvider("uaa");
        FieldDescriptor[] fieldDescriptors = {
                fieldWithPath("id").description(ID_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("subdomain").description(SUBDOMAIN_DESC).attributes(key("constraints").value("Required")),
                fieldWithPath("name").description(NAME_DESC).attributes(key("constraints").value("Required")),
                fieldWithPath("description").description(DESCRIPTION_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("version").description(VERSION_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("active").description(ACTIVE_DESC).attributes(key("constraints").value("Optional")),

                fieldWithPath("config.clientSecretPolicy.minLength").type(NUMBER).description(SECRET_POLICY_MIN_LENGTH).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("config.clientSecretPolicy.maxLength").type(NUMBER).description(SECRET_POLICY_MAX_LENGTH).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("config.clientSecretPolicy.requireUpperCaseCharacter").type(NUMBER).description(SECRET_POLICY_UPPERCASE).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("config.clientSecretPolicy.requireLowerCaseCharacter").type(NUMBER).description(SECRET_POLICY_LOWERCASE).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("config.clientSecretPolicy.requireDigit").type(NUMBER).description(SECRET_POLICY_DIGIT).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("config.clientSecretPolicy.requireSpecialCharacter").type(NUMBER).description(SECRET_POLICY_SPECIAL_CHAR).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),

                fieldWithPath("config.tokenPolicy").description(TOKEN_POLICY_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.tokenPolicy.activeKeyId").optional().type(STRING).description(ACTIVE_KEY_ID_DESC).attributes(key("constraints").value("Required if `config.tokenPolicy.keys` are set")),
                fieldWithPath("config.tokenPolicy.keys.*.signingKey").type(STRING).description(KEYS_DESC).attributes(key("constraints").value("Key to be used for signing")),
                fieldWithPath("config.tokenPolicy.keys.*.signingAlg").description(KEYS_ALG_DESC).attributes(key("constraints").value("Optional. Can only be used in conjunction with `keys.<key-id>.signingKey` and `keys.<key-id>.signingCert`")),
                fieldWithPath("config.tokenPolicy.keys.*.signingCert").description(KEYS_CERT_DESC).attributes(key("constraints").value("Optional. Can only be used in conjunction with `keys.<key-id>.signingKey` and `keys.<key-id>.signingCert`")),
                fieldWithPath("config.tokenPolicy.accessTokenValidity").description(ACCESS_TOKEN_VALIDITY_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.tokenPolicy.refreshTokenValidity").description(REFRESH_TOKEN_VALIDITY_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.tokenPolicy.jwtRevocable").type(BOOLEAN).description(JWT_REVOCABLE_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.tokenPolicy.refreshTokenUnique").type(BOOLEAN).description(REFRESH_TOKEN_UNIQUE).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.tokenPolicy.refreshTokenRotate").type(BOOLEAN).description(REFRESH_TOKEN_ROTATE).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.tokenPolicy.refreshTokenFormat").type(STRING).description(REFRESH_TOKEN_FORMAT).attributes(key("constraints").value("Optional")),

                fieldWithPath("config.samlConfig.disableInResponseToCheck").description(SAML_DISABLE_IN_RESPONSE_TO_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.samlConfig.wantAssertionSigned").description(WANT_ASSERTION_SIGNED_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.samlConfig.requestSigned").description(REQUEST_SIGNED_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.samlConfig.entityID").type(STRING).description(ENTITY_ID_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.samlConfig.certificate").type(STRING).description(CERTIFICATE_DESC).attributes(key("constraints").value("Deprecated")),
                fieldWithPath("config.samlConfig.privateKey").type(STRING).description(PRIVATE_KEY_DESC).attributes(key("constraints").value("Deprecated")),
                fieldWithPath("config.samlConfig.privateKeyPassword").type(STRING).description(PRIVATE_KEY_PASSWORD_DESC).attributes(key("constraints").value("Deprecated")),
                fieldWithPath("config.samlConfig.activeKeyId").type(STRING).description(SAML_ACTIVE_KEY_ID_DESC).attributes(key("constraints").value("Required if a list of keys defined in `keys` map")),
                fieldWithPath("config.samlConfig.keys.*.key").type(STRING).description(PRIVATE_KEY_DESC).attributes(key("constraints").value("Optional. Can only be used in conjunction with `keys.<key-id>.passphrase` and `keys.<key-id>.certificate`")),
                fieldWithPath("config.samlConfig.keys.*.passphrase").type(STRING).description(PRIVATE_KEY_PASSWORD_DESC).attributes(key("constraints").value("Optional. Can only be used in conjunction with `keys.<key-id>.key` and `keys.<key-id>.certificate`")),
                fieldWithPath("config.samlConfig.keys.*.certificate").type(STRING).description(CERTIFICATE_DESC).attributes(key("constraints").value("Optional. Can only be used in conjunction with `keys.<key-id>.key` and `keys.<key-id>.passphrase`")),
                fieldWithPath("config.samlConfig.entityID").type(STRING).description(ENTITY_ID_DESC).attributes(key("constraints").value("Optional")),

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
                fieldWithPath("config.issuer").description(ZONE_ISSUER_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.defaultIdentityProvider").type(STRING).description(DEFAULT_IDP_DESC).optional().attributes(key("constraints").value("Optional")),

                fieldWithPath("config.branding.companyName").description(BRANDING_COMPANY_NAME_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.branding.productLogo").description(BRANDING_PRODUCT_LOGO_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.branding.squareLogo").description(BRANDING_SQUARE_LOGO_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.branding.footerLegalText").description(BRANDING_FOOTER_LEGAL_TEXT_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.branding.footerLinks.*").description(BRANDING_FOOTER_LINKS_DESC).attributes(key("constraints").value("Optional")),

                fieldWithPath("config.branding.banner.text").description(BRANDING_BANNER_TEXT_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.branding.banner.logo").description(BRANDING_BANNER_LOGO_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.branding.banner.link").description(BRANDING_BANNER_LINK_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.branding.banner.textColor").description(BRANDING_BANNER_TEXT_COLOR_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.branding.banner.backgroundColor").description(BRANDING_BANNER_BACKGROUND_COLOR_DESC).attributes(key("constraints").value("Optional")),

                fieldWithPath("config.branding.consent.text").description(BRANDING_CONSENT_TEXT_DESC).attributes(key("constraints").value("Optional. Must be set if configuring consent.")),
                fieldWithPath("config.branding.consent.link").description(BRANDING_CONSENT_LINK_DESC).attributes(key("constraints").value("Optional. Can be null if configuring consent.")),

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

                fieldWithPath("config.userConfig.defaultGroups").description(DEFAULT_ZONE_GROUPS_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.userConfig.allowedGroups").description(ALLOWED_ZONE_GROUPS_DESC).attributes(key("constraints").value("Optional")).optional().type(ARRAY),
                fieldWithPath("config.userConfig.maxUsers").description(USER_CONFIG_USER_LIMIT_DESCRIPTION).attributes(key("constraints").value(USER_CONFIG_USER_LIMIT_CONSTRAINT)).optional().type(NUMBER),
                fieldWithPath("config.userConfig.checkOriginEnabled").description(USER_CONFIG_CHECK_ORIGIN_ENABLED).attributes(key("constraints").value("Optional")).optional().type(BOOLEAN),
                fieldWithPath("config.userConfig.allowOriginLoop").description(USER_CONFIG_ALLOW_ORIGIN_LOOP).attributes(key("constraints").value("Optional")).optional().type(BOOLEAN),

                fieldWithPath("created").ignored(),
                fieldWithPath("last_modified").ignored()
        };

        mockMvc.perform(
                post("/identity-zones")
                        .header("Authorization", "Bearer " + identityClientWriteToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().is(HttpStatus.CREATED.value()))
                .andDo(document("{ClassName}/{methodName}",
                        preprocessRequest(prettyPrint()),
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName("Authorization").description("Bearer token containing `zones.write` or `uaa.admin`")
                        ),
                        requestFields(fieldDescriptors),
                        getResponseFields()
                ));
    }

    @Test
    void getIdentityZone() throws Exception {
        String id = "twiglet-get";
        createIdentityZoneHelper(id);

        String identityClientReadToken = testClient.getClientCredentialsOAuthAccessToken(
                "identity",
                "identitysecret",
                "zones.read");

        mockMvc.perform(
                get("/identity-zones/{id}", id)
                        .header("Authorization", "Bearer " + identityClientReadToken))
                .andExpect(status().is(HttpStatus.OK.value()))
                .andDo(document("{ClassName}/{methodName}",
                        preprocessResponse(prettyPrint()),
                        pathParameters(
                                parameterWithName("id").description("Unique ID of the identity zone to retrieve")
                        ),
                        requestHeaders(
                                headerWithName("Authorization").description("Bearer token containing `zones.read` or `zones.write` or `uaa.admin`. If you use the zone-switching header, bear token containing `zones.<zone id>.admin` or `zones.<zone id>.read` can be used."),
                                IDENTITY_ZONE_ID_HEADER,
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                        ),
                        getResponseFields()
                ));
    }

    @Test
    void getAllIdentityZones() throws Exception {
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
                fieldWithPath("[].description").optional().description(DESCRIPTION_DESC),
                fieldWithPath("[].version").description(VERSION_DESC),
                fieldWithPath("[].active").description(ACTIVE_DESC).attributes(key("constraints").value("Optional")),

                fieldWithPath("[].config.tokenPolicy.activeKeyId").optional().type(VARIES).description(ACTIVE_KEY_ID_DESC),
                fieldWithPath("[].config.tokenPolicy.accessTokenValidity").description(ACCESS_TOKEN_VALIDITY_DESC),
                fieldWithPath("[].config.tokenPolicy.refreshTokenValidity").description(REFRESH_TOKEN_VALIDITY_DESC),
                fieldWithPath("[].config.tokenPolicy.jwtRevocable").type(BOOLEAN).description(JWT_REVOCABLE_DESC),
                fieldWithPath("[].config.tokenPolicy.refreshTokenUnique").type(BOOLEAN).description(REFRESH_TOKEN_UNIQUE).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.tokenPolicy.refreshTokenRotate").type(BOOLEAN).description(REFRESH_TOKEN_ROTATE).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.tokenPolicy.refreshTokenFormat").type(STRING).description(REFRESH_TOKEN_FORMAT).attributes(key("constraints").value("Optional")),

                fieldWithPath("[].config.clientSecretPolicy.minLength").type(NUMBER).description(SECRET_POLICY_MIN_LENGTH).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("[].config.clientSecretPolicy.maxLength").type(NUMBER).description(SECRET_POLICY_MAX_LENGTH).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("[].config.clientSecretPolicy.requireUpperCaseCharacter").type(NUMBER).description(SECRET_POLICY_UPPERCASE).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("[].config.clientSecretPolicy.requireLowerCaseCharacter").type(NUMBER).description(SECRET_POLICY_LOWERCASE).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("[].config.clientSecretPolicy.requireDigit").type(NUMBER).description(SECRET_POLICY_DIGIT).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("[].config.clientSecretPolicy.requireSpecialCharacter").type(NUMBER).description(SECRET_POLICY_SPECIAL_CHAR).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),

                fieldWithPath("[].config.samlConfig.disableInResponseToCheck").description(SAML_DISABLE_IN_RESPONSE_TO_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.samlConfig.wantAssertionSigned").description(WANT_ASSERTION_SIGNED_DESC),
                fieldWithPath("[].config.samlConfig.requestSigned").description(REQUEST_SIGNED_DESC),
                fieldWithPath("[].config.samlConfig.entityID").optional().type(STRING).description(ENTITY_ID_DESC),
                fieldWithPath("[].config.samlConfig.certificate").optional().type(STRING).description(CERTIFICATE_DESC).attributes(key("constraints").value("Deprecated")),

                fieldWithPath("[].config.samlConfig.activeKeyId").type(STRING).description(SAML_ACTIVE_KEY_ID_DESC),
                fieldWithPath("[].config.samlConfig.keys").ignored().type(OBJECT).description(CERTIFICATE_DESC),
                fieldWithPath("[].config.samlConfig.keys.*").type(OBJECT).description(CERTIFICATE_DESC),
                fieldWithPath("[].config.samlConfig.keys.*.certificate").type(STRING).description(CERTIFICATE_DESC),

                fieldWithPath("[].config.links.logout.redirectUrl").description(REDIRECT_URL_DESC),
                fieldWithPath("[].config.links.homeRedirect").optional().description(HOMEREDIRECT_URL_DESC),
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
                fieldWithPath("[].config.branding.footerLinks").optional().description(BRANDING_FOOTER_LINKS_DESC),

                fieldWithPath("[].config.branding.consent.text").optional().description(BRANDING_CONSENT_TEXT_DESC),
                fieldWithPath("[].config.branding.consent.link").optional().description(BRANDING_CONSENT_LINK_DESC),

                fieldWithPath("[].config.prompts[]").type(ARRAY).description(PROMPTS_DESC),
                fieldWithPath("[].config.prompts[].name").description(PROMPTS_DESC),
                fieldWithPath("[].config.prompts[].type").description(PROMPTS_TYPE_DESC),
                fieldWithPath("[].config.prompts[].text").description(PROMPTS_TEXT_DESC),

                fieldWithPath("[].config.idpDiscoveryEnabled").description(IDP_DISCOVERY_ENABLED_FLAG),
                fieldWithPath("[].config.accountChooserEnabled").description(ACCOUNT_CHOOSER_ENABLED_FLAG),
                fieldWithPath("[].config.issuer").optional().description(ZONE_ISSUER_DESC),

                fieldWithPath("[].config.branding.companyName").optional().description(BRANDING_COMPANY_NAME_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.branding.productLogo").optional().description(BRANDING_PRODUCT_LOGO_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.branding.squareLogo").optional().description(BRANDING_SQUARE_LOGO_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.branding.footerLegalText").optional().description(BRANDING_FOOTER_LEGAL_TEXT_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.branding.footerLinks.*").optional().description(BRANDING_FOOTER_LINKS_DESC).attributes(key("constraints").value("Optional")),

                fieldWithPath("[].config.branding.banner.text").optional().description(BRANDING_BANNER_TEXT_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.branding.banner.logo").optional().description(BRANDING_BANNER_LOGO_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.branding.banner.link").optional().description(BRANDING_BANNER_LINK_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.branding.banner.textColor").optional().description(BRANDING_BANNER_TEXT_COLOR_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.branding.banner.backgroundColor").optional().description(BRANDING_BANNER_BACKGROUND_COLOR_DESC).attributes(key("constraints").value("Optional")),

                fieldWithPath("[].config.corsPolicy.xhrConfiguration.allowedOrigins").optional().description(CORS_XHR_ORIGINS_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.corsPolicy.xhrConfiguration.allowedOriginPatterns").optional().description(CORS_XHR_ORIGIN_PATTERNS_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.corsPolicy.xhrConfiguration.allowedUris").optional().description(CORS_XHR_URI_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.corsPolicy.xhrConfiguration.allowedUriPatterns").optional().description(CORS_XHR_URI_PATTERNS_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.corsPolicy.xhrConfiguration.allowedHeaders").optional().description(CORS_XHR_HEADERS_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.corsPolicy.xhrConfiguration.allowedMethods").optional().description(CORS_XHR_METHODS_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.corsPolicy.xhrConfiguration.allowedCredentials").optional().description(CORS_XHR_CREDENTIALS_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.corsPolicy.xhrConfiguration.maxAge").optional().description(CORS_XHR_MAXAGE_DESC).attributes(key("constraints").value("Optional")),

                fieldWithPath("[].config.corsPolicy.defaultConfiguration.allowedOrigins").optional().description(CORS_XHR_ORIGINS_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.corsPolicy.defaultConfiguration.allowedOriginPatterns").optional().description(CORS_XHR_ORIGIN_PATTERNS_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.corsPolicy.defaultConfiguration.allowedUris").optional().description(CORS_XHR_URI_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.corsPolicy.defaultConfiguration.allowedUriPatterns").optional().description(CORS_XHR_URI_PATTERNS_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.corsPolicy.defaultConfiguration.allowedHeaders").optional().description(CORS_XHR_HEADERS_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.corsPolicy.defaultConfiguration.allowedMethods").optional().description(CORS_XHR_METHODS_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.corsPolicy.defaultConfiguration.allowedCredentials").optional().description(CORS_XHR_CREDENTIALS_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.corsPolicy.defaultConfiguration.maxAge").optional().description(CORS_XHR_MAXAGE_DESC).attributes(key("constraints").value("Optional")),

                fieldWithPath("[].config.userConfig.defaultGroups").description(DEFAULT_ZONE_GROUPS_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("[].config.userConfig.allowedGroups").description(ALLOWED_ZONE_GROUPS_DESC).attributes(key("constraints").value("Optional")).optional().type(ARRAY),
                fieldWithPath("[].config.userConfig.maxUsers").description(USER_CONFIG_USER_LIMIT_DESCRIPTION).attributes(key("constraints").value(USER_CONFIG_USER_LIMIT_CONSTRAINT)).optional().type(NUMBER),
                fieldWithPath("[].config.userConfig.checkOriginEnabled").description(USER_CONFIG_CHECK_ORIGIN_ENABLED).attributes(key("constraints").value("optional")).optional().type(BOOLEAN),
                fieldWithPath("[].config.userConfig.allowOriginLoop").description(USER_CONFIG_ALLOW_ORIGIN_LOOP).attributes(key("constraints").value("Optional")).optional().type(BOOLEAN),

                fieldWithPath("[].created").ignored(),
                fieldWithPath("[].last_modified").ignored()
        );

        mockMvc.perform(
                get("/identity-zones")
                        .header("Authorization", "Bearer " + identityClientReadToken))
                .andExpect(status().is(HttpStatus.OK.value()))
                .andDo(print())
                .andDo(document("{ClassName}/{methodName}",
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName("Authorization").description("Bearer token containing `zones.read` or `zones.write` or `uaa.admin`. If you use the zone-switching header, bear token containing `zones.<zone id>.admin` can be used."),
                                IDENTITY_ZONE_ID_HEADER,
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                        ),
                        responseFields
                ));
    }

    @Test
    void updateIdentityZone() throws Exception {
        String identityClientWriteToken = testClient.getClientCredentialsOAuthAccessToken(
                "identity",
                "identitysecret",
                "zones.write");

        String id = "twiglet-update";
        createIdentityZoneHelper(id);

        IdentityZone updatedIdentityZone = new IdentityZone();
        updatedIdentityZone.setSubdomain(StringUtils.hasText(id) ? id : new AlphanumericRandomValueStringGenerator().generate());
        updatedIdentityZone.setName("The Updated Twiglet Zone");
        updatedIdentityZone.setDescription("Like the Twilight Zone but not tastier.");
        TokenPolicy.KeyInformation keyInformation = new TokenPolicy.KeyInformation();
        keyInformation.setSigningKey("upD4t3d.s1gNiNg.K3y/t3XT");
        keyInformation.setSigningAlg("HS256");
        updatedIdentityZone.getConfig().getTokenPolicy().setActiveKeyId("updatedKeyId");
        updatedIdentityZone.getConfig().getTokenPolicy().setKeyInformation(Collections.singletonMap("updatedKeyId", keyInformation));
        SamlConfig samlConfig = new SamlConfig();
        samlConfig.setPrivateKey(SERVICE_PROVIDER_KEY);
        samlConfig.setPrivateKeyPassword(SERVICE_PROVIDER_KEY_PASSWORD);
        samlConfig.setCertificate(SERVICE_PROVIDER_CERTIFICATE);
        samlConfig.setEntityID(SERVICE_PROVIDER_ID);
        updatedIdentityZone.getConfig().setIssuer(DEFAULT_ISSUER_URI);
        updatedIdentityZone.getConfig().setSamlConfig(samlConfig);
        IdentityZoneConfiguration brandingConfig = setBranding(updatedIdentityZone.getConfig());
        updatedIdentityZone.setConfig(brandingConfig);

        Snippet requestFields = requestFields(
                fieldWithPath("subdomain").description(SUBDOMAIN_DESC).attributes(key("constraints").value("Required")),
                fieldWithPath("name").description(NAME_DESC).attributes(key("constraints").value("Required")),
                fieldWithPath("description").description(DESCRIPTION_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("version").description(VERSION_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("active").description(ACTIVE_DESC).attributes(key("constraints").value("Optional")),

                fieldWithPath("config.tokenPolicy.activeKeyId").optional().type(STRING).description(ACTIVE_KEY_ID_DESC).attributes(key("constraints").value("Required if `config.tokenPolicy.keys` are set")),
                fieldWithPath("config.tokenPolicy.keys.*.signingKey").type(STRING).description(KEYS_UPDATE_DESC).attributes(key("constraints").value("Key to be used for signing")),
                fieldWithPath("config.tokenPolicy.keys.*.signingAlg").description(KEYS_ALG_DESC).attributes(key("constraints").value("Optional. Can only be used in conjunction with `keys.<key-id>.signingKey` and `keys.<key-id>.signingCert`")),
                fieldWithPath("config.tokenPolicy.keys.*.signingCert").description(KEYS_CERT_DESC).attributes(key("constraints").value("Optional. Can only be used in conjunction with `keys.<key-id>.signingKey` and `keys.<key-id>.signingCert`")),
                fieldWithPath("config.tokenPolicy.accessTokenValidity").description(ACCESS_TOKEN_VALIDITY_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.tokenPolicy.refreshTokenValidity").description(REFRESH_TOKEN_VALIDITY_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.tokenPolicy.jwtRevocable").type(BOOLEAN).description(JWT_REVOCABLE_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.tokenPolicy.refreshTokenUnique").type(BOOLEAN).description(REFRESH_TOKEN_UNIQUE).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.tokenPolicy.refreshTokenRotate").type(BOOLEAN).description(REFRESH_TOKEN_ROTATE).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.tokenPolicy.refreshTokenFormat").type(STRING).description(REFRESH_TOKEN_FORMAT).attributes(key("constraints").value("Optional")),

                fieldWithPath("config.clientSecretPolicy.minLength").type(NUMBER).description(SECRET_POLICY_MIN_LENGTH).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("config.clientSecretPolicy.maxLength").type(NUMBER).description(SECRET_POLICY_MAX_LENGTH).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("config.clientSecretPolicy.requireUpperCaseCharacter").type(NUMBER).description(SECRET_POLICY_UPPERCASE).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("config.clientSecretPolicy.requireLowerCaseCharacter").type(NUMBER).description(SECRET_POLICY_LOWERCASE).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("config.clientSecretPolicy.requireDigit").type(NUMBER).description(SECRET_POLICY_DIGIT).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("config.clientSecretPolicy.requireSpecialCharacter").type(NUMBER).description(SECRET_POLICY_SPECIAL_CHAR).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),

                fieldWithPath("config.samlConfig.disableInResponseToCheck").description(SAML_DISABLE_IN_RESPONSE_TO_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.samlConfig.wantAssertionSigned").description(WANT_ASSERTION_SIGNED_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.samlConfig.requestSigned").description(REQUEST_SIGNED_DESC).attributes(key("constraints").value("Optional")),

                fieldWithPath("config.samlConfig.entityID").description(ENTITY_ID_DESC).attributes(key("constraints").value("Optional")),
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
                fieldWithPath("config.issuer").description(ZONE_ISSUER_DESC).attributes(key("constraints").value("Optional")),

                fieldWithPath("config.branding.companyName").description(BRANDING_COMPANY_NAME_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.branding.productLogo").description(BRANDING_PRODUCT_LOGO_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.branding.squareLogo").description(BRANDING_SQUARE_LOGO_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.branding.footerLegalText").description(BRANDING_FOOTER_LEGAL_TEXT_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.branding.footerLinks.*").description(BRANDING_FOOTER_LINKS_DESC).attributes(key("constraints").value("Optional")),

                fieldWithPath("config.branding.banner.text").description(BRANDING_BANNER_TEXT_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.branding.banner.logo").description(BRANDING_BANNER_LOGO_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.branding.banner.link").description(BRANDING_BANNER_LINK_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.branding.banner.textColor").description(BRANDING_BANNER_TEXT_COLOR_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.branding.banner.backgroundColor").description(BRANDING_BANNER_BACKGROUND_COLOR_DESC).attributes(key("constraints").value("Optional")),

                fieldWithPath("config.branding.consent.text").description(BRANDING_CONSENT_TEXT_DESC).attributes(key("constraints").value("Optional. Must be set if configuring consent.")),
                fieldWithPath("config.branding.consent.link").description(BRANDING_CONSENT_LINK_DESC).attributes(key("constraints").value("Optional. Can be null if configuring consent.")),

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

                fieldWithPath("config.userConfig.defaultGroups").description(DEFAULT_ZONE_GROUPS_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.userConfig.allowedGroups").description(ALLOWED_ZONE_GROUPS_DESC).attributes(key("constraints").value("Optional")).optional().type(ARRAY),
                fieldWithPath("config.userConfig.maxUsers").description(USER_CONFIG_USER_LIMIT_DESCRIPTION).attributes(key("constraints").value(USER_CONFIG_USER_LIMIT_CONSTRAINT)).optional().type(NUMBER),
                fieldWithPath("config.userConfig.checkOriginEnabled").description(USER_CONFIG_CHECK_ORIGIN_ENABLED).attributes(key("constraints").value("Optional")).optional().type(BOOLEAN),
                fieldWithPath("config.userConfig.allowOriginLoop").description(USER_CONFIG_ALLOW_ORIGIN_LOOP).attributes(key("constraints").value("Optional")).optional().type(BOOLEAN),

                fieldWithPath("created").ignored(),
                fieldWithPath("last_modified").ignored()
        );

        mockMvc.perform(
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
                                headerWithName("Authorization").description("Bearer token containing `zones.write` or `uaa.admin`. If you use the zone-switching header, bear token containing `zones.<zone id>.admin` can be used."),
                                IDENTITY_ZONE_ID_HEADER,
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                        ),
                        requestFields,
                        getResponseFields()
                ));
    }

    @Test
    void deleteIdentityZone() throws Exception {
        String id = "twiglet-delete";
        createIdentityZoneHelper(id);

        String identityClientWriteToken = testClient.getClientCredentialsOAuthAccessToken(
                "identity",
                "identitysecret",
                "zones.write");

        mockMvc.perform(
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
                                headerWithName("Authorization").description("Bearer token containing `zones.write` or `uaa.admin`. If you use the zone-switching header, bear token containing `zones.<zone id>.admin` can be used."),
                                IDENTITY_ZONE_ID_HEADER,
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
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
        samlConfig.setEntityID(SERVICE_PROVIDER_ID);
        identityZone.getConfig().setSamlConfig(samlConfig);
        identityZone.getConfig().setIssuer(DEFAULT_ISSUER_URI);

        TokenPolicy tokenPolicy = new TokenPolicy(3600, 7200);
        tokenPolicy.setActiveKeyId("active-key-1");
        tokenPolicy.setKeys(new HashMap<>(Collections.singletonMap("active-key-1", "key")));
        identityZone.getConfig().setTokenPolicy(tokenPolicy);

        identityZone.setId(id);
        identityZone.setSubdomain(StringUtils.hasText(id) ? id : new AlphanumericRandomValueStringGenerator().generate());
        identityZone.setName("The Twiglet Zone");

        IdentityZoneConfiguration brandingConfig = setBranding(identityZone.getConfig());
        identityZone.setConfig(brandingConfig);

        mockMvc.perform(
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
                fieldWithPath("active").description(ACTIVE_DESC).attributes(key("constraints").value("Optional")),

                fieldWithPath("config.tokenPolicy.activeKeyId").optional().type(STRING).description(ACTIVE_KEY_ID_DESC),
                fieldWithPath("config.tokenPolicy.accessTokenValidity").description(ACCESS_TOKEN_VALIDITY_DESC),
                fieldWithPath("config.tokenPolicy.refreshTokenValidity").description(REFRESH_TOKEN_VALIDITY_DESC),
                fieldWithPath("config.tokenPolicy.jwtRevocable").type(BOOLEAN).description(JWT_REVOCABLE_DESC).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.tokenPolicy.refreshTokenUnique").type(BOOLEAN).description(REFRESH_TOKEN_UNIQUE).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.tokenPolicy.refreshTokenRotate").type(BOOLEAN).description(REFRESH_TOKEN_ROTATE).attributes(key("constraints").value("Optional")),
                fieldWithPath("config.tokenPolicy.refreshTokenFormat").type(STRING).description(REFRESH_TOKEN_FORMAT).attributes(key("constraints").value("Optional")),

                fieldWithPath("config.clientSecretPolicy.minLength").type(NUMBER).description(SECRET_POLICY_MIN_LENGTH).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("config.clientSecretPolicy.maxLength").type(NUMBER).description(SECRET_POLICY_MAX_LENGTH).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("config.clientSecretPolicy.requireUpperCaseCharacter").type(NUMBER).description(SECRET_POLICY_UPPERCASE).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("config.clientSecretPolicy.requireLowerCaseCharacter").type(NUMBER).description(SECRET_POLICY_LOWERCASE).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("config.clientSecretPolicy.requireDigit").type(NUMBER).description(SECRET_POLICY_DIGIT).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),
                fieldWithPath("config.clientSecretPolicy.requireSpecialCharacter").type(NUMBER).description(SECRET_POLICY_SPECIAL_CHAR).attributes(key("constraints").value("Required when `clientSecretPolicy` in the config is not null")),

                fieldWithPath("config.samlConfig.disableInResponseToCheck").description(SAML_DISABLE_IN_RESPONSE_TO_DESC),
                fieldWithPath("config.samlConfig.wantAssertionSigned").description(WANT_ASSERTION_SIGNED_DESC),
                fieldWithPath("config.samlConfig.requestSigned").description(REQUEST_SIGNED_DESC),

                fieldWithPath("config.samlConfig.entityID").type(STRING).description(ENTITY_ID_DESC),
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

                fieldWithPath("config.defaultIdentityProvider").type(STRING).description(DEFAULT_IDP_DESC).optional().attributes(key("constraints").value("Optional")),
                fieldWithPath("config.idpDiscoveryEnabled").description(IDP_DISCOVERY_ENABLED_FLAG),
                fieldWithPath("config.accountChooserEnabled").description(ACCOUNT_CHOOSER_ENABLED_FLAG),
                fieldWithPath("config.issuer").description(ZONE_ISSUER_DESC),
                fieldWithPath("config.branding.companyName").description(BRANDING_COMPANY_NAME_DESC),
                fieldWithPath("config.branding.productLogo").description(BRANDING_PRODUCT_LOGO_DESC),
                fieldWithPath("config.branding.squareLogo").description(BRANDING_SQUARE_LOGO_DESC),
                fieldWithPath("config.branding.footerLegalText").description(BRANDING_FOOTER_LEGAL_TEXT_DESC),
                fieldWithPath("config.branding.footerLinks.*").description(BRANDING_FOOTER_LINKS_DESC),

                fieldWithPath("config.branding.banner.text").description(BRANDING_BANNER_TEXT_DESC),
                fieldWithPath("config.branding.banner.logo").description(BRANDING_BANNER_LOGO_DESC),
                fieldWithPath("config.branding.banner.link").description(BRANDING_BANNER_LINK_DESC),
                fieldWithPath("config.branding.banner.textColor").description(BRANDING_BANNER_TEXT_COLOR_DESC),
                fieldWithPath("config.branding.banner.backgroundColor").description(BRANDING_BANNER_BACKGROUND_COLOR_DESC),

                fieldWithPath("config.branding.consent.text").description(BRANDING_CONSENT_TEXT_DESC),
                fieldWithPath("config.branding.consent.link").description(BRANDING_CONSENT_LINK_DESC),

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

                fieldWithPath("config.userConfig.defaultGroups").description(DEFAULT_ZONE_GROUPS_DESC),
                fieldWithPath("config.userConfig.allowedGroups").description(ALLOWED_ZONE_GROUPS_DESC).optional().type(ARRAY),
                fieldWithPath("config.userConfig.maxUsers").description(USER_CONFIG_USER_LIMIT_DESCRIPTION),
                fieldWithPath("config.userConfig.checkOriginEnabled").description(USER_CONFIG_CHECK_ORIGIN_ENABLED).optional().type(BOOLEAN),
                fieldWithPath("config.userConfig.allowOriginLoop").description(USER_CONFIG_ALLOW_ORIGIN_LOOP).attributes(key("constraints").value("Optional")).optional().type(BOOLEAN),

                fieldWithPath("created").ignored(),
                fieldWithPath("last_modified").ignored()
        );
    }

    private IdentityZoneConfiguration setBranding(IdentityZoneConfiguration config) {
        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName("Test Company");
        branding.setProductLogo("VGVzdFByb2R1Y3RMb2dv");
        branding.setSquareLogo("VGVzdFNxdWFyZUxvZ28=");
        branding.setFooterLegalText("Test footer legal text");

        HashMap<String, String> footerLinks = new HashMap<>();
        footerLinks.put("Support", "http://support.example.com");
        branding.setFooterLinks(footerLinks);

        Banner banner = new Banner();
        banner.setText("Announcement");
        banner.setLink("http://announce.example.com");
        banner.setLogo("VGVzdFByb2R1Y3RMb2dv");
        banner.setTextColor("#000000");
        banner.setBackgroundColor("#89cff0");
        branding.setBanner(banner);

        branding.setConsent(new Consent("Some Policy", "http://policy.example.com"));

        config.setBranding(branding);
        config.getLinks().setHomeRedirect("http://my.hosted.homepage.com/");
        return config;
    }
}
