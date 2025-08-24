package org.cloudfoundry.identity.uaa.mock.clients;

import org.apache.commons.lang3.ArrayUtils;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtChangeRequest;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.restdocs.headers.HeaderDescriptor;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.test.web.servlet.ResultActions;

import java.util.*;

import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.*;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.*;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.serializeExcludingProperties;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.writeValueAsString;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.*;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.*;
import static org.springframework.restdocs.payload.JsonFieldType.*;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.request.RequestDocumentation.queryParameters;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class ClientAdminEndpointDocs extends AdminClientCreator {
    private String clientAdminToken;

    private static final FieldDescriptor clientSecretField = fieldWithPath("client_secret").constrained("Required if the client allows `authorization_code` or `client_credentials` grant type").type(STRING).description("A secret string used for authenticating as this client.");
    private static final FieldDescriptor secondaryClientSecretField = fieldWithPath("secondary_client_secret").optional(null).type(STRING).description("An optional, secondary secret string used for authenticating as this client to support secret rotation.");
    private static final FieldDescriptor actionField = fieldWithPath("action").constrained("Always required.").description("Set to `secret` to change client secret, `delete` to delete the client or `add` to add the client");
    private static final HeaderDescriptor authorizationHeader = headerWithName("Authorization").description("Bearer token containing `clients.write`, `clients.admin` or `zones.{zone.id}.admin`");
    private static final HeaderDescriptor IDENTITY_ZONE_ID_HEADER = headerWithName(IdentityZoneSwitchingFilter.HEADER).optional().description("If using a `zones.<zoneId>.admin` scope/token, indicates what zone this request goes to by supplying a zone_id.");
    private static final HeaderDescriptor IDENTITY_ZONE_SUBDOMAIN_HEADER = headerWithName(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER).optional().description("If using a `zones.<zoneId>.admin` scope/token, indicates what zone this request goes to by supplying a subdomain.");

    private static final FieldDescriptor lastModifiedField = fieldWithPath("lastModified").optional(null).description("Epoch (milliseconds) of the moment the client information was last altered");
    private static final String clientIdDescription = "Client identifier, unique within identity zone";

    private static final FieldDescriptor[] idempotentFields = new FieldDescriptor[]{
            fieldWithPath("client_id").required().description(clientIdDescription),
            fieldWithPath("authorized_grant_types").optional(null).description("List of grant types that can be used to obtain a token with this client. Can include `authorization_code`, `password`, `implicit`, and/or `client_credentials`."),
            fieldWithPath("redirect_uri").optional(null).type(ARRAY).description("Allowed URI pattern for redirect during authorization. Wildcard patterns can be specified using the Ant-style pattern. Null/Empty value is forbidden."),
            fieldWithPath("scope").optional("uaa.none").type(ARRAY).description("Scopes allowed for the client"),
            fieldWithPath("resource_ids").optional(Collections.emptySet()).type(ARRAY).description("Resources the client is allowed access to"),
            fieldWithPath("authorities").optional("uaa.none").type(ARRAY).description("Scopes which the client is able to grant when creating a client"),
            fieldWithPath("autoapprove").optional(Collections.emptySet()).type(Arrays.asList(BOOLEAN, ARRAY)).description("Scopes that do not require user approval"),
            fieldWithPath("allowpublic").optional(false).type(BOOLEAN).description("If true, allow to omit client_secret for authorization_code flow in combination with PKCE"),
            fieldWithPath("access_token_validity").optional(null).type(NUMBER).description("time in seconds to access token expiration after it is issued"),
            fieldWithPath("refresh_token_validity").optional(null).type(NUMBER).description("time in seconds to refresh token expiration after it is issued"),
            fieldWithPath(ClientConstants.ALLOWED_PROVIDERS).optional(null).type(ARRAY).description("A list of origin keys (alias) for identity providers the client is limited to. Null implies any identity provider is allowed."),
            fieldWithPath(ClientConstants.CLIENT_NAME).optional(null).type(STRING).description("A human readable name for the client"),
            fieldWithPath(ClientConstants.TOKEN_SALT).optional(null).type(STRING).description("A random string used to generate the client's revokation key. Change this value to revoke all active tokens for the client"),
            fieldWithPath(ClientConstants.CREATED_WITH).optional(null).type(STRING).description("What scope the bearer token had when client was created"),
            fieldWithPath(ClientConstants.APPROVALS_DELETED).optional(null).type(BOOLEAN).description("Were the approvals deleted for the client, and an audit event sent"),
            fieldWithPath(ClientConstants.REQUIRED_USER_GROUPS).optional(null).type(ARRAY).description("A list of group names. If a user doesn't belong to all the required groups, the user will not be authenticated and no tokens will be issued to this client for that user. If this field is not set, authentication and token issuance will proceed normally."),
    };

    private static final FieldDescriptor[] secretChangeFields = new FieldDescriptor[]{
            fieldWithPath("clientId").required().description(clientIdDescription),
            fieldWithPath("oldSecret").constrained("Optional if authenticated as an admin client. Required otherwise.").type(STRING).description("A valid client secret before updating"),
            fieldWithPath("secret").required().description("The new client secret"),
            fieldWithPath("changeMode").optional(UPDATE).type(STRING).description("If change mode is set to `" + ADD + "`, the new `secret` will be added to the existing one and if the change mode is set to `" + DELETE + "`, the old secret will be deleted to support secret rotation. Currently only two client secrets are supported at any given time.")
    };

    private static final FieldDescriptor[] clientJwtChangeFields = new FieldDescriptor[]{
            fieldWithPath("client_id").required().description(clientIdDescription),
            fieldWithPath("jwks").constrained("Optional only, if jwks_uri is used. Required otherwise. OIDC standard.").type(STRING).description("A valid JSON string according JSON Web Key Set standard, see [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517), e.g. content of /token_keys endpoint from UAA"),
            fieldWithPath("jwks_uri").constrained("Optional only, if jwks is used. Required otherwise. OIDC standard.").type(STRING).description("A valid URI to token keys endpoint. Must be compliant to jwks_uri from [OpenID Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)."),
            fieldWithPath("iss").constrained("Optional only, if OIDC standard is used. Required otherwise. OAuth2 standard.").type(STRING).description("OIDC compliant issuer URI, matching the retrieved OAuth2 compliant JWT (iss claim)."),
            fieldWithPath("sub").constrained("Optional only, if OIDC standard is used. Required otherwise. OAuth2 standard.").type(STRING).description("A subject string, matching the retrieved OAuth2 compliant JWT (sub claim)."),
            fieldWithPath("aud").constrained("Optional. Otherwise UAA token endpoint is expected. OAuth2 standard.").type(STRING).description("An audience for the retreived OAuth2 compliant JWT (part of aud claim array)."),
            fieldWithPath("kid").constrained("Optional only, if a single JWK should be deleted, else ignored. OIDC standard.").type(STRING).description("If change mode is set to `" + ClientJwtChangeRequest.ChangeMode.DELETE + "`, it specifies `the id of the key` that will be deleted. The kid parameter is only applicable when jwks configuration is used."),
            fieldWithPath("changeMode").optional(ClientJwtChangeRequest.ChangeMode.ADD).type(STRING).description("If change mode is set to `" + ClientJwtChangeRequest.ChangeMode.ADD + "`, a new entry of either `JWKS` or `iss/sub/aud` will be added to the existing configuration and if the change mode is set to `" + ClientJwtChangeRequest.ChangeMode.DELETE + "`, the old `JWKS` or `iss/sub/aud` will be deleted. The option `" + ClientJwtChangeRequest.ChangeMode.UPDATE + "` overwrites the existing trust setting and allows switching between `JWKS` and `JWKS_URI`.")
    };

    @BeforeEach
    void setup() throws Exception {
        clientAdminToken = testClient.getClientCredentialsOAuthAccessToken(
                "admin",
                "adminsecret",
                "uaa.admin clients.admin clients.secret");
    }

    @Test
    void createClient() throws Exception {
        Snippet requestFields = requestFields(
                (FieldDescriptor[]) ArrayUtils.addAll(idempotentFields,
                        new FieldDescriptor[]{clientSecretField, secondaryClientSecretField}
                ));

        Snippet responseFields = responseFields(
                (FieldDescriptor[]) ArrayUtils.addAll(idempotentFields,
                        new FieldDescriptor[]{
                                lastModifiedField
                        }
                ));

        ResultActions resultActions = createClientHelper();

        resultActions.andDo(document("{ClassName}/{methodName}",
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint()),
                requestHeaders(
                        authorizationHeader,
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                requestFields,
                responseFields
        ));
    }

    @Test
    void listClients() throws Exception {
        ClientDetails createdClientDetails = JsonUtils.readValue(createClientHelper().andReturn().getResponse().getContentAsString(), UaaClientDetails.class);

        ResultActions resultActions = mockMvc.perform(get("/oauth/clients")
                .header("Authorization", "Bearer " + clientAdminToken)
                .param("filter", "client_id eq \"%s\"".formatted(createdClientDetails.getClientId()))
                .param("sortBy", "client_id")
                .param("sortOrder", "descending")
                .param("startIndex", "1")
                .param("count", "10")
                .accept(APPLICATION_JSON));

        Snippet queryParameters = queryParameters(
                parameterWithName("filter").optional("client_id pr").type(STRING).description("SCIM filter for querying clients"),
                parameterWithName("sortBy").optional("client_id").type(STRING).description("Field to sort results by"),
                parameterWithName("sortOrder").optional("ascending").type(STRING).description("Sort results in `ascending` or `descending` order"),
                parameterWithName("startIndex").optional("1").type(NUMBER).description("Index of the first result on which to begin the page"),
                parameterWithName("count").optional("100").type(NUMBER).description("Number of results per page")
        );

        Snippet responseFields = responseFields(
                (FieldDescriptor[]) ArrayUtils.addAll(
                        subFields("resources[]", (FieldDescriptor[]) ArrayUtils.addAll(idempotentFields, new FieldDescriptor[]{lastModifiedField})),
                        new FieldDescriptor[]{
                                fieldWithPath("startIndex").description("Index of the first result on this page"),
                                fieldWithPath("itemsPerPage").description("Number of results per page"),
                                fieldWithPath("totalResults").description("Total number of results that matched the query"),
                                fieldWithPath("schemas").description("`[\"urn:scim:schemas:core:1.0\"]`")
                        }
                )
        );

        resultActions.andDo(document("{ClassName}/{methodName}",
                preprocessResponse(prettyPrint()),
                requestHeaders(
                        headerWithName("Authorization").description("Bearer token containing `clients.read`, `clients.admin` or `zones.{zone.id}.admin`"),
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                queryParameters,
                responseFields
        ));
    }

    @Test
    void retrieveClient() throws Exception {
        ClientDetails createdClientDetails = JsonUtils.readValue(createClientHelper().andReturn().getResponse().getContentAsString(), UaaClientDetails.class);

        ResultActions resultActions = mockMvc.perform(get("/oauth/clients/{client_id}", createdClientDetails.getClientId())
                .header("Authorization", "Bearer " + clientAdminToken)
                .accept(APPLICATION_JSON)
        );

        resultActions.andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()),
                pathParameters(
                        parameterWithName("client_id").required().description(clientIdDescription)
                ),
                requestHeaders(
                        headerWithName("Authorization").description("Bearer token containing `clients.read`, `clients.admin` or `zones.{zone.id}.admin`"),
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                responseFields(
                        (FieldDescriptor[]) ArrayUtils.addAll(idempotentFields,
                                new FieldDescriptor[]{
                                        lastModifiedField
                                }
                        )
                )
        ));
    }

    @Test
    void updateClient() throws Exception {
        ClientDetails createdClientDetails = JsonUtils.readValue(createClientHelper().andReturn().getResponse().getContentAsString(), UaaClientDetails.class);
        UaaClientDetails updatedClientDetails = new UaaClientDetails();
        updatedClientDetails.setClientId(createdClientDetails.getClientId());
        updatedClientDetails.setScope(Arrays.asList("clients.new", "clients.autoapprove"));
        updatedClientDetails.setAutoApproveScopes(Collections.singletonList("clients.autoapprove"));
        updatedClientDetails.setAuthorizedGrantTypes(createdClientDetails.getAuthorizedGrantTypes());
        updatedClientDetails.setRegisteredRedirectUri(Collections.singleton("http://redirect.url"));

        ResultActions resultActions = mockMvc.perform(put("/oauth/clients/{client_id}", createdClientDetails.getClientId())
                .header("Authorization", "Bearer " + clientAdminToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(writeValueAsString(updatedClientDetails)))
                .andExpect(status().isOk());

        Snippet requestFields = requestFields(idempotentFields);

        Snippet responseFields = responseFields((FieldDescriptor[]) ArrayUtils.addAll(idempotentFields,
                new FieldDescriptor[]{
                        lastModifiedField
                }
        )
        );

        resultActions.andDo(document("{ClassName}/{methodName}", preprocessRequest(prettyPrint()), preprocessResponse(prettyPrint()),
                pathParameters(
                        parameterWithName("client_id").required().description(clientIdDescription)
                ),
                requestHeaders(
                        authorizationHeader,
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                requestFields,
                responseFields)
        );
    }

    @Test
    void changeClientSecret() throws Exception {
        ClientDetails createdClientDetails = JsonUtils.readValue(createClientHelper().andReturn().getResponse().getContentAsString(), UaaClientDetails.class);

        ResultActions resultActions = mockMvc.perform(put("/oauth/clients/{client_id}/secret", createdClientDetails.getClientId())
                .header("Authorization", "Bearer " + clientAdminToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(writeValueAsString(map(
                        entry("clientId", createdClientDetails.getClientId()),
                        entry("secret", "new_secret")
                ))))
                .andExpect(status().isOk());

        resultActions.andDo(document("{ClassName}/{methodName}", preprocessRequest(prettyPrint()), preprocessResponse(prettyPrint()),
                pathParameters(
                        parameterWithName("client_id").required().description(clientIdDescription)
                ),
                requestHeaders(
                        authorizationHeader,
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                requestFields(secretChangeFields)
        )
        );
    }

    @Test
    void changeClientJwt() throws Exception {
        ClientDetails createdClientDetails = JsonUtils.readValue(createClientHelper().andReturn().getResponse().getContentAsString(), UaaClientDetails.class);

        ResultActions resultActions = mockMvc.perform(put("/oauth/clients/{client_id}/clientjwt", createdClientDetails.getClientId())
                .header("Authorization", "Bearer " + clientAdminToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(writeValueAsString(map(
                        entry("client_id", createdClientDetails.getClientId()),
                        entry("jwks_uri", "http://localhost:8080/uaa/token_keys")
                ))))
                .andExpect(status().isOk());

        resultActions.andDo(document("{ClassName}/{methodName}", preprocessRequest(prettyPrint()), preprocessResponse(prettyPrint()),
                pathParameters(
                        parameterWithName("client_id").required().description(clientIdDescription)
                ),
                requestHeaders(
                        headerWithName("Authorization").description("Bearer token containing `clients.trust`, `clients.admin` or `zones.{zone.id}.admin`"),
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                requestFields(clientJwtChangeFields)
        )
        );
    }

    @Test
    void deleteClient() throws Exception {
        ClientDetails createdClientDetails = JsonUtils.readValue(createClientHelper().andReturn().getResponse().getContentAsString(), UaaClientDetails.class);

        ResultActions resultActions = mockMvc.perform(delete("/oauth/clients/{client_id}", createdClientDetails.getClientId())
                .header("Authorization", "Bearer " + clientAdminToken)
                .accept(APPLICATION_JSON));

        resultActions.andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()),
                pathParameters(
                        parameterWithName("client_id").required().description(clientIdDescription)
                ),
                requestHeaders(
                        authorizationHeader,
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                responseFields((FieldDescriptor[]) ArrayUtils.addAll(idempotentFields,
                        new FieldDescriptor[]{
                                lastModifiedField
                        }
                )))
        );
    }

    @Test
    void clientTx() throws Exception {
        // CREATE

        List<String> scopes = Arrays.asList("clients.read", "clients.write");
        UaaClientDetails createdClientDetails1 = createBasicClientWithAdditionalInformation(scopes);
        UaaClientDetails createdClientDetails2 = createBasicClientWithAdditionalInformation(scopes);

        ResultActions createResultActions = mockMvc.perform(post("/oauth/clients/tx")
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(Arrays.asList(createdClientDetails1, createdClientDetails2)))
                .header("Authorization", "Bearer " + clientAdminToken)
                .accept(APPLICATION_JSON));

        FieldDescriptor[] fieldsNoSecret = subFields("[]", idempotentFields);
        FieldDescriptor[] fieldsWithSecret = (FieldDescriptor[]) ArrayUtils.addAll(
                fieldsNoSecret,
                subFields("[]", clientSecretField)
        );
        FieldDescriptor[] fieldsWithSecretAndAction = (FieldDescriptor[]) ArrayUtils.addAll(
                fieldsWithSecret,
                subFields("[]", actionField)
        );

        Snippet responseFields = responseFields((FieldDescriptor[]) ArrayUtils.addAll(
                fieldsNoSecret,
                subFields("[]", lastModifiedField)
        ));
        Snippet responseFieldsWithAction = responseFields((FieldDescriptor[]) ArrayUtils.addAll(
                fieldsNoSecret,
                subFields("[]", lastModifiedField, actionField)
        ));
        createResultActions
                .andExpect(status().isCreated())
                .andDo(document("{ClassName}/createClientTx", preprocessRequest(prettyPrint()), preprocessResponse(prettyPrint()),
                        requestHeaders(
                                authorizationHeader,
                                IDENTITY_ZONE_ID_HEADER,
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                        ),
                        requestFields(fieldsWithSecret),
                        responseFields
                )
                );

        //UPDATE

        createdClientDetails1.setRegisteredRedirectUri(Collections.singleton("http://updated.redirect.uri/"));
        createdClientDetails2.getAuthorities().add(new SimpleGrantedAuthority("new.authority"));

        ResultActions updateResultActions = mockMvc.perform(put("/oauth/clients/tx")
                .contentType(APPLICATION_JSON)
                .content("[" + serializeExcludingProperties(createdClientDetails1, "client_secret", "lastModified") + "," + serializeExcludingProperties(createdClientDetails2, "client_secret", "lastModified") + "]")
                .header("Authorization", "Bearer " + clientAdminToken)
                .accept(APPLICATION_JSON));

        updateResultActions
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/updateClientTx", preprocessRequest(prettyPrint()), preprocessResponse(prettyPrint()),
                        requestHeaders(
                                authorizationHeader,
                                IDENTITY_ZONE_ID_HEADER,
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                        ),
                        requestFields(fieldsNoSecret),
                        responseFields
                )
                );

        // CHANGE SECRET

        Map<String, Object> client1SecretChange = map(
                entry("clientId", createdClientDetails1.getClientId()),
                entry("secret", "new_secret")
        );

        Map<String, Object> client2SecretChange = map(
                entry("clientId", createdClientDetails2.getClientId()),
                entry("secret", "new_secret")
        );

        String content = JsonUtils.writeValueAsString(new Object[]{client1SecretChange, client2SecretChange});
        ResultActions secretResultActions = mockMvc.perform(post("/oauth/clients/tx/secret")
                .contentType(APPLICATION_JSON)
                .content(content)
                .header("Authorization", "Bearer " + clientAdminToken)
                .accept(APPLICATION_JSON));

        secretResultActions
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/secretClientTx", preprocessRequest(prettyPrint()), preprocessResponse(prettyPrint()),
                        requestHeaders(
                                authorizationHeader,
                                IDENTITY_ZONE_ID_HEADER,
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                        ),
                        requestFields(subFields("[]", secretChangeFields)),
                        responseFields((FieldDescriptor[]) ArrayUtils.addAll(
                                fieldsNoSecret,
                                subFields("[]",
                                        lastModifiedField,
                                        fieldWithPath("approvals_deleted").description("Indicates whether the approvals associated with the client were deleted as a result of this action")
                                )
                        ))
                )
                );

        // BATCH

        Map<String, Object> modify1 = map(
                entry("action", ClientDetailsModification.SECRET),
                entry("client_id", createdClientDetails1.getClientId()),
                entry("client_secret", "new_secret")
        );

        Map<String, Object> modify2 = map(
                entry("action", ClientDetailsModification.DELETE),
                entry("client_id", createdClientDetails2.getClientId())
        );

        UaaClientDetails createdClientDetails3 = createBasicClientWithAdditionalInformation(scopes);
        ClientDetailsModification modify3 = new ClientDetailsModification(createdClientDetails3);
        modify3.setAction(ClientDetailsModification.ADD);

        ResultActions modifyResultActions = mockMvc.perform(post("/oauth/clients/tx/modify")
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(new Object[]{modify1, modify2, modify3}))
                .header("Authorization", "Bearer " + clientAdminToken)
                .accept(APPLICATION_JSON));

        modifyResultActions
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/modifyClientTx", preprocessRequest(prettyPrint()), preprocessResponse(prettyPrint()),
                        requestHeaders(
                                authorizationHeader,
                                IDENTITY_ZONE_ID_HEADER,
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                        ),
                        requestFields(fieldsWithSecretAndAction),
                        responseFieldsWithAction
                )
                );

        //DELETE
        ResultActions deleteResultActions = mockMvc.perform(post("/oauth/clients/tx/delete")
                .contentType(APPLICATION_JSON)
                .content("[{\"client_id\":\"" + createdClientDetails1.getClientId() + "\"},{\"client_id\":\"" + createdClientDetails3.getClientId() + "\"}]")
                .header("Authorization", "Bearer " + clientAdminToken)
                .accept(APPLICATION_JSON));

        deleteResultActions
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/deleteClientTx", preprocessRequest(prettyPrint()), preprocessResponse(prettyPrint()),
                        requestHeaders(authorizationHeader, IDENTITY_ZONE_ID_HEADER, IDENTITY_ZONE_SUBDOMAIN_HEADER),
                        requestFields(fieldWithPath("[].client_id").required().description(clientIdDescription)),
                        responseFields((FieldDescriptor[]) ArrayUtils.addAll(
                                fieldsNoSecret,
                                subFields("[]", lastModifiedField, fieldWithPath("approvals_deleted").description("Indicates whether the approvals associated with the client were deleted as a result of this action"))
                        ))
                )
                );
    }

    private UaaClientDetails createBasicClientWithAdditionalInformation(List<String> scopes) {
        UaaClientDetails clientDetails = createBaseClient(null, SECRET, null, scopes, scopes);
        clientDetails.setAdditionalInformation(additionalInfo());
        return clientDetails;
    }

    private ResultActions createClientHelper() throws Exception {
        return mockMvc.perform(post("/oauth/clients")
                .header("Authorization", "Bearer " + clientAdminToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(writeValueAsString(
                        createBasicClientWithAdditionalInformation(Arrays.asList("clients.read", "clients.write"))
                )))
                .andExpect(status().isCreated());
    }

    private Map<String, Object> additionalInfo() {
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("redirect_uri", Arrays.asList("http://test1.com", "http://ant.path.wildcard/**/passback/*"));
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList(OriginKeys.UAA, OriginKeys.LDAP, "my-saml-provider"));
        additionalInformation.put(ClientConstants.CLIENT_NAME, "My Client Name");
        additionalInformation.put(ClientConstants.AUTO_APPROVE, true);
        additionalInformation.put(ClientConstants.TOKEN_SALT, new AlphanumericRandomValueStringGenerator().generate());
        return additionalInformation;
    }
}
