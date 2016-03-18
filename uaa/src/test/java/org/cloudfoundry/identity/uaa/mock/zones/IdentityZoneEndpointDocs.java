package org.cloudfoundry.identity.uaa.mock.zones;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
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

        FieldDescriptor[] fieldDescriptors = {
            fieldWithPath("id").description("unique ID of the identity zone").attributes(key("constraints").value("Required")),
            fieldWithPath("subdomain").description("Unique subdomain for the running instance. May only contain legal characters for a subdomain name.").attributes(key("constraints").value("Required")),
            fieldWithPath("name").description("human-readable zone name").attributes(key("constraints").value("Required")),
            fieldWithPath("description").description("description of the zone").attributes(key("constraints").value("Optional")),
            fieldWithPath("version").description("reserved for future use of E-Tag versioning").attributes(key("constraints").value("Optional")),

            fieldWithPath("config.tokenPolicy").description("Various fields pertaining to the JWT access and refresh tokens.").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.activeKeyId").type(STRING).description("the ID for the key that is being used to sign tokens").attributes(key("constraints").value("Required if `config.tokenPolicy.keys` are set")),
            fieldWithPath("config.tokenPolicy.keys").description("keys which will be used to sign the token").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.accessTokenValidity").description("time in seconds between when a access token is issued and when it expires").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.refreshTokenValidity").description("time in seconds between when a refresh token is issued and when it expires").attributes(key("constraints").value("Optional")),

            fieldWithPath("config.samlConfig.assertionSigned").description("If `true`, the service provider will sign all assertions").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.wantAssertionSigned").description("Exposed SAML metadata property. If `true`, all assertions received by the SAML provider must be signed. Defaults to `true`.").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.requestSigned").description("Exposed SAML metadata property. If `true`, the service provider will sign all outgoing authentication requests. Defaults to `true`.").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.wantAuthnRequestSigned").description("").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.assertionTimeToLiveSeconds").description("").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.certificate").type(STRING).description("Exposed SAML metadata property. The certificate used to sign all communications.").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.privateKey").type(STRING).description("Exposed SAML metadata property. The SAML provider's private key.").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.privateKeyPassword").type(STRING).description("Exposed SAML metadata property. The SAML provider's private key password. Reserved for future use.").attributes(key("constraints").value("Optional")),

            fieldWithPath("config.links.logout.redirectUrl").description("logout redirect url").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.redirectParameterName").description("").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.disableRedirectParameter").description("").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.whitelist").type(ARRAY).description("list of allowed whitelist redirects").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.selfServiceLinksEnabled").description("whether or not users are allowed to sign up or reset their passwords via the UI").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.signup").description("where users are directed upon clicking the account creation link").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.passwd").description("where users are directed upon clicking the password reset link").attributes(key("constraints").value("Optional")),

            fieldWithPath("config.prompts[]").type(ARRAY).description("List of fields that users are prompted for to login. Defaults to username, password, and passcode.").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].name").description("name of field").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].type").description("what kind of field this is (e.g. text or password)").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].text").description("actual text displayed on prompt for field").attributes(key("constraints").value("Optional")),

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
                    headerWithName("Authorization").description("bearer token containing `zones.write` or `zones.<zone id>.admin`")
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
                    parameterWithName("id").description("unique ID of the identity zone to retrieve")
                ),
                requestHeaders(
                    headerWithName("Authorization").description("bearer token containing `zones.read` or `zones.<zone id>.admin` or `zones.<zone id>.read`")
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
            fieldWithPath("[].id").description("unique ID of the identity zone"),
            fieldWithPath("[].subdomain").description("Unique subdomain for the running instance. May only contain legal characters for a subdomain name."),
            fieldWithPath("[].name").description("human-readable zone name"),
            fieldWithPath("[].description").description("description of the zone"),
            fieldWithPath("[].version").description("reserved for future use of E-Tag versioning"),

            fieldWithPath("[].config.tokenPolicy").description("Various fields pertaining to the JWT access and refresh tokens."),
            fieldWithPath("[].config.tokenPolicy.activeKeyId").type(STRING).description("the ID for the key that is being used to sign tokens"),
            fieldWithPath("[].config.tokenPolicy.keys").description("keys which will be used to sign the token"),
            fieldWithPath("[].config.tokenPolicy.accessTokenValidity").description("time in seconds between when a access token is issued and when it expires"),
            fieldWithPath("[].config.tokenPolicy.refreshTokenValidity").description("time in seconds between when a refresh token is issued and when it expires"),

            fieldWithPath("[].config.samlConfig.assertionSigned").description("If `true`, the service provider will sign all assertions"),
            fieldWithPath("[].config.samlConfig.wantAssertionSigned").description("Exposed SAML metadata property. If `true`, all assertions received by the SAML provider must be signed. Defaults to `true`."),
            fieldWithPath("[].config.samlConfig.requestSigned").description("Exposed SAML metadata property. If `true`, the service provider will sign all outgoing authentication requests. Defaults to `true`."),
            fieldWithPath("[].config.samlConfig.wantAuthnRequestSigned").description(""),
            fieldWithPath("[].config.samlConfig.assertionTimeToLiveSeconds").description(""),
            fieldWithPath("[].config.samlConfig.certificate").type(STRING).description("Exposed SAML metadata property. The certificate used to sign all communications."),
            fieldWithPath("[].config.samlConfig.privateKey").type(STRING).description("Exposed SAML metadata property. The SAML provider's private key."),
            fieldWithPath("[].config.samlConfig.privateKeyPassword").type(STRING).description("Exposed SAML metadata property. The SAML provider's private key password. Reserved for future use."),

            fieldWithPath("[].config.links.logout.redirectUrl").description("logout redirect url"),
            fieldWithPath("[].config.links.logout.redirectParameterName").description(""),
            fieldWithPath("[].config.links.logout.disableRedirectParameter").description(""),
            fieldWithPath("[].config.links.logout.whitelist").type(ARRAY).description("list of allowed whitelist redirects"),
            fieldWithPath("[].config.links.selfService.selfServiceLinksEnabled").description("whether or not users are allowed to sign up or reset their passwords via the UI"),
            fieldWithPath("[].config.links.selfService.signup").description("where users are directed upon clicking the account creation link"),
            fieldWithPath("[].config.links.selfService.passwd").description("where users are directed upon clicking the password reset link"),

            fieldWithPath("[].config.prompts[]").type(ARRAY).description("List of fields that users are prompted for to login. Defaults to username, password, and passcode."),
            fieldWithPath("[].config.prompts[].name").description("name of field"),
            fieldWithPath("[].config.prompts[].type").description("what kind of field this is (e.g. text or password)"),
            fieldWithPath("[].config.prompts[].text").description("actual text displayed on prompt for field"),

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
                    headerWithName("Authorization").description("bearer token containing `zones.read` or `zones.<zone id>.admin`")
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

        Snippet requestFields = requestFields(
            fieldWithPath("subdomain").description("Unique subdomain for the running instance. May only contain legal characters for a subdomain name.").attributes(key("constraints").value("Required")),
            fieldWithPath("name").description("human-readable zone name").attributes(key("constraints").value("Required")),
            fieldWithPath("description").description("description of the zone").attributes(key("constraints").value("Optional")),
            fieldWithPath("version").description("reserved for future use of E-Tag versioning").attributes(key("constraints").value("Optional")),

            fieldWithPath("config.tokenPolicy").description("Various fields pertaining to the JWT access and refresh tokens.").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.activeKeyId").type(STRING).description("the ID for the key that is being used to sign tokens").attributes(key("constraints").value("Required if `config.tokenPolicy.keys` are set")),
            fieldWithPath("config.tokenPolicy.keys").description("keys which will be used to sign the token").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.accessTokenValidity").description("time in seconds between when a access token is issued and when it expires").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.tokenPolicy.refreshTokenValidity").description("time in seconds between when a refresh token is issued and when it expires").attributes(key("constraints").value("Optional")),

            fieldWithPath("config.samlConfig.assertionSigned").description("If `true`, the service provider will sign all assertions").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.wantAssertionSigned").description("Exposed SAML metadata property. If `true`, all assertions received by the SAML provider must be signed. Defaults to `true`.").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.requestSigned").description("Exposed SAML metadata property. If `true`, the service provider will sign all outgoing authentication requests. Defaults to `true`.").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.wantAuthnRequestSigned").description("").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.assertionTimeToLiveSeconds").description("").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.certificate").type(STRING).description("Exposed SAML metadata property. The certificate used to sign all communications.").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.privateKey").type(STRING).description("Exposed SAML metadata property. The SAML provider's private key.").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.samlConfig.privateKeyPassword").type(STRING).description("Exposed SAML metadata property. The SAML provider's private key password. Reserved for future use.").attributes(key("constraints").value("Optional")),

            fieldWithPath("config.links.logout.redirectUrl").description("logout redirect url").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.redirectParameterName").description("").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.disableRedirectParameter").description("").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.logout.whitelist").type(ARRAY).description("list of allowed whitelist redirects").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.selfServiceLinksEnabled").description("whether or not users are allowed to sign up or reset their passwords via the UI").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.signup").description("where users are directed upon clicking the account creation link").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.links.selfService.passwd").description("where users are directed upon clicking the password reset link").attributes(key("constraints").value("Optional")),

            fieldWithPath("config.prompts[]").type(ARRAY).description("List of fields that users are prompted for to login. Defaults to username, password, and passcode.").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].name").description("name of field").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].type").description("what kind of field this is (e.g. text or password)").attributes(key("constraints").value("Optional")),
            fieldWithPath("config.prompts[].text").description("actual text displayed on prompt for field").attributes(key("constraints").value("Optional")),

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
                    parameterWithName("id").description("unique ID of the identity zone to update")
                ),
                requestHeaders(
                    headerWithName("Authorization").description("bearer token containing `zones.write` or `zones.<zone id>.admin`")
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
                    parameterWithName("id").description("unique ID of the identity zone to delete")
                ),
                requestHeaders(
                    headerWithName("Authorization").description("bearer token containing `zones.write`")
                ),
                getResponseFields()
            ));
    }

    private void createIdentityZoneHelper(String id) throws Exception {
        String identityClientWriteToken = testClient.getClientCredentialsOAuthAccessToken(
            "identity",
            "identitysecret",
            "zones.write");

        Map<String, String> identityZone = new HashMap<>();
        identityZone.put("id", id);
        identityZone.put("subdomain", StringUtils.hasText(id) ? id : new RandomValueStringGenerator().generate());
        identityZone.put("name", "The Twiglet Zone");

        getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientWriteToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone)))
            .andExpect(status().is(HttpStatus.CREATED.value()));
    }

    private Snippet getResponseFields() {
        return responseFields(
            fieldWithPath("id").description("unique ID of the identity zone"),
            fieldWithPath("subdomain").description("Unique subdomain for the running instance. May only contain legal characters for a subdomain name."),
            fieldWithPath("name").description("human-readable zone name"),
            fieldWithPath("description").type(STRING).description("description of the zone").optional(),
            fieldWithPath("version").description("reserved for future use of E-Tag versioning"),

            fieldWithPath("config.tokenPolicy").description("Various fields pertaining to the JWT access and refresh tokens."),
            fieldWithPath("config.tokenPolicy.activeKeyId").type(STRING).description("the ID for the key that is being used to sign tokens"),
            fieldWithPath("config.tokenPolicy.keys").description("keys which will be used to sign the token"),
            fieldWithPath("config.tokenPolicy.accessTokenValidity").description("time in seconds between when a access token is issued and when it expires"),
            fieldWithPath("config.tokenPolicy.refreshTokenValidity").description("time in seconds between when a refresh token is issued and when it expires"),

            fieldWithPath("config.samlConfig.assertionSigned").description("If `true`, the service provider will sign all assertions"),
            fieldWithPath("config.samlConfig.wantAssertionSigned").description("Exposed SAML metadata property. If `true`, all assertions received by the SAML provider must be signed. Defaults to `true`."),
            fieldWithPath("config.samlConfig.requestSigned").description("Exposed SAML metadata property. If `true`, the service provider will sign all outgoing authentication requests. Defaults to `true`."),
            fieldWithPath("config.samlConfig.wantAuthnRequestSigned").description(""),
            fieldWithPath("config.samlConfig.assertionTimeToLiveSeconds").description(""),
            fieldWithPath("config.samlConfig.certificate").type(STRING).description("Exposed SAML metadata property. The certificate used to sign all communications."),
            fieldWithPath("config.samlConfig.privateKey").type(STRING).description("Exposed SAML metadata property. The SAML provider's private key."),
            fieldWithPath("config.samlConfig.privateKeyPassword").type(STRING).description("Exposed SAML metadata property. The SAML provider's private key password. Reserved for future use."),

            fieldWithPath("config.links.logout.redirectUrl").description("logout redirect url"),
            fieldWithPath("config.links.logout.redirectParameterName").description(""),
            fieldWithPath("config.links.logout.disableRedirectParameter").description(""),
            fieldWithPath("config.links.logout.whitelist").type(ARRAY).description("list of allowed whitelist redirects"),
            fieldWithPath("config.links.selfService.selfServiceLinksEnabled").description("whether or not users are allowed to sign up or reset their passwords via the UI"),
            fieldWithPath("config.links.selfService.signup").description("where users are directed upon clicking the account creation link"),
            fieldWithPath("config.links.selfService.passwd").description("where users are directed upon clicking the password reset link"),

            fieldWithPath("config.prompts[]").type(ARRAY).description("List of fields that users are prompted for to login. Defaults to username, password, and passcode."),
            fieldWithPath("config.prompts[].name").description("name of field"),
            fieldWithPath("config.prompts[].type").description("what kind of field this is (e.g. text or password)"),
            fieldWithPath("config.prompts[].text").description("actual text displayed on prompt for field"),

            fieldWithPath("created").ignored(),
            fieldWithPath("last_modified").ignored()
        );
    }
}
