package org.cloudfoundry.identity.uaa.mock.clients;

import org.apache.commons.lang.ArrayUtils;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.Before;
import org.junit.Test;
import org.springframework.restdocs.headers.HeaderDescriptor;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.ResultActions;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.ADD;
import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.DELETE;
import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.UPDATE;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.fieldWithPath;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.subFields;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.serializeExcludingProperties;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.writeValueAsString;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
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
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ClientAdminEndpointsDocs extends AdminClientCreator {
    private String clientAdminToken;

    private static final FieldDescriptor clientSecretField = fieldWithPath("client_secret").constrained("Required if the client allows `authorization_code` or `client_credentials` grant type").type(STRING).description("A secret string used for authenticating as this client. To support secret rotation this can be space delimited string of two secrets.");
    private static final HeaderDescriptor authorizationHeader = headerWithName("Authorization").description("Bearer token containing `clients.write`, `clients.admin` or `zones.{zone.id}.admin`");
    private static final HeaderDescriptor IDENTITY_ZONE_ID_HEADER = headerWithName(IdentityZoneSwitchingFilter.HEADER).optional().description("If using a `zones.<zoneId>.admin scope/token, indicates what zone this request goes to by supplying a zone_id.");
    private static final HeaderDescriptor IDENTITY_ZONE_SUBDOMAIN_HEADER = headerWithName(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER).optional().description("If using a `zones.<zoneId>.admin scope/token, indicates what zone this request goes to by supplying a subdomain.");

    private static final FieldDescriptor lastModifiedField = fieldWithPath("lastModified").description("Epoch of the moment the client information was last altered");
    private static final String clientIdDescription = "Client identifier, unique within identity zone";

    private static final FieldDescriptor[] idempotentFields = new FieldDescriptor[]{
        fieldWithPath("client_id").required().description(clientIdDescription),
        fieldWithPath("authorized_grant_types").required().description("List of grant types that can be used to obtain a token with this client. Can include `authorization_code`, `password`, `implicit`, and/or `client_credentials`."),
        fieldWithPath("scope").optional("uaa.none").type(ARRAY).description("Scopes allowed for the client"),
        fieldWithPath("resource_ids").optional(Collections.emptySet()).type(ARRAY).description("Resources the client is allowed access to"),
        fieldWithPath("authorities").optional("uaa.none").type(ARRAY).description("Scopes which the client is able to grant when creating a client"),
        fieldWithPath("autoapprove").optional(Collections.emptySet()).type(ARRAY).description("Scopes that do not require user approval"),
        fieldWithPath("redirect_uri").optional(null).type(ARRAY).description("Allowed URI pattern for redirect during authorization. Wildcard patterns can be specified using the Ant-style pattern. A null value (not recommended) matches any uri."),
        fieldWithPath("access_token_validity").optional(null).type(NUMBER).description("time in seconds to access token expiration after it is issued"),
        fieldWithPath("refresh_token_validity").optional(null).type(NUMBER).description("time in seconds to refresh token expiration after it is issued"),
        fieldWithPath(ClientConstants.ALLOWED_PROVIDERS).optional(null).type(ARRAY).description("A list of origin keys (alias) for identity providers the client is limited to. Null implies any identity provider is allowed."),
        fieldWithPath(ClientConstants.CLIENT_NAME).optional(null).type(STRING).description("A human readable name for the client"),
        fieldWithPath(ClientConstants.TOKEN_SALT).optional(null).type(STRING).description("A random string used to generate the client's revokation key. Change this value to revoke all active tokens for the client"),
        fieldWithPath(ClientConstants.CREATED_WITH).optional(null).type(STRING).description("What scope the bearer token had when client was created"),
        fieldWithPath(ClientConstants.APPROVALS_DELETED).optional(null).type(BOOLEAN).description("Were the approvals deleted for the client, and an audit event sent"),
    };

    private static final FieldDescriptor[] secretChangeFields = new FieldDescriptor[]{
        fieldWithPath("clientId").required().description(clientIdDescription),
        fieldWithPath("oldSecret").constrained("Optional if authenticated as an admin client. Required otherwise.").type(STRING).description("A valid client secret before updating"),
        fieldWithPath("secret").required().description("The new client secret"),
        fieldWithPath("changeMode").optional(UPDATE).type(STRING).description("If change mode is set to `"+ADD+"`, the new `secret` will be added to the existing one and if the change mode is set to `"+DELETE+"`, the old secret will be deleted to support secret rotation. Currently only two client secrets are supported at any given time.")
    };

    @Before
    public void setup() throws Exception {
        clientAdminToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "uaa.admin clients.admin clients.secret");
    }

    @Test
    public void createClient() throws Exception {
        Snippet requestFields = requestFields(
            (FieldDescriptor[]) ArrayUtils.addAll(idempotentFields,
                new FieldDescriptor[]{clientSecretField}
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
    public void listClients() throws Exception {
        ClientDetails createdClientDetails = JsonUtils.readValue(createClientHelper().andReturn().getResponse().getContentAsString(), BaseClientDetails.class);

        ResultActions resultActions = getMockMvc().perform(get("/oauth/clients")
            .header("Authorization", "Bearer " + clientAdminToken)
            .param("filter", String.format("client_id eq \"%s\"", createdClientDetails.getClientId()))
            .param("sortBy", "client_id")
            .param("sortOrder", "descending")
            .param("startIndex", "1")
            .param("count", "10")
            .accept(APPLICATION_JSON));

        Snippet requestParameters = requestParameters(
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
            requestParameters,
            responseFields
        ));
    }

    @Test
    public void retrieveClient() throws Exception {
        ClientDetails createdClientDetails = JsonUtils.readValue(createClientHelper().andReturn().getResponse().getContentAsString(), BaseClientDetails.class);

        ResultActions resultActions = getMockMvc().perform(get("/oauth/clients/{client_id}", createdClientDetails.getClientId())
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
    public void updateClient() throws Exception {
        ClientDetails createdClientDetails = JsonUtils.readValue(createClientHelper().andReturn().getResponse().getContentAsString(), BaseClientDetails.class);
        BaseClientDetails updatedClientDetails = new BaseClientDetails();
        updatedClientDetails.setClientId(createdClientDetails.getClientId());
        updatedClientDetails.setScope(Arrays.asList("clients.new", "clients.autoapprove"));
        updatedClientDetails.setAutoApproveScopes(Arrays.asList("clients.autoapprove"));
        updatedClientDetails.setAuthorizedGrantTypes(createdClientDetails.getAuthorizedGrantTypes());

        ResultActions resultActions = getMockMvc().perform(put("/oauth/clients/{client_id}", createdClientDetails.getClientId())
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
    public void changeClientSecret() throws Exception {
        ClientDetails createdClientDetails = JsonUtils.readValue(createClientHelper().andReturn().getResponse().getContentAsString(), BaseClientDetails.class);

        ResultActions resultActions = getMockMvc().perform(put("/oauth/clients/{client_id}/secret", createdClientDetails.getClientId())
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
    public void deleteClient() throws Exception {
        ClientDetails createdClientDetails = JsonUtils.readValue(createClientHelper().andReturn().getResponse().getContentAsString(), BaseClientDetails.class);

        ResultActions resultActions = getMockMvc().perform(delete("/oauth/clients/{client_id}", createdClientDetails.getClientId())
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
    public void clientTx() throws Exception {
        // CREATE

        List<String> scopes = Arrays.asList("clients.read", "clients.write");
        BaseClientDetails createdClientDetails1 = createBasicClientWithAdditionalInformation(scopes);
        BaseClientDetails createdClientDetails2 = createBasicClientWithAdditionalInformation(scopes);

        ResultActions createResultActions = getMockMvc().perform(post("/oauth/clients/tx")
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(Arrays.asList(createdClientDetails1, createdClientDetails2)))
            .header("Authorization", "Bearer " + clientAdminToken)
            .accept(APPLICATION_JSON));

        FieldDescriptor[] fieldsNoSecret = subFields("[]", idempotentFields);
        FieldDescriptor[] fieldsWithSecret = (FieldDescriptor[]) ArrayUtils.addAll(
            fieldsNoSecret,
            subFields("[]", clientSecretField)
        );
        Snippet responseFields = responseFields((FieldDescriptor[]) ArrayUtils.addAll(
            fieldsNoSecret,
            subFields("[]", lastModifiedField)
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

        ResultActions updateResultActions = getMockMvc().perform(put("/oauth/clients/tx")
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
        ResultActions secretResultActions = getMockMvc().perform(post("/oauth/clients/tx/secret")
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

        BaseClientDetails createdClientDetails3 = createBasicClientWithAdditionalInformation(scopes);
        ClientDetailsModification modify3 = new ClientDetailsModification(createdClientDetails3);
        modify3.setAction(ClientDetailsModification.ADD);

        ResultActions modifyResultActions = getMockMvc().perform(post("/oauth/clients/tx/modify")
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(new Object[]{modify1, modify2, modify3}))
            .header("Authorization", "Bearer " + clientAdminToken)
            .accept(APPLICATION_JSON));

        modifyResultActions
            .andExpect(status().isOk())
            .andDo(document("{ClassName}/modifyClientTx", preprocessRequest(prettyPrint()), preprocessResponse(prettyPrint()),
                    requestHeaders(authorizationHeader, IDENTITY_ZONE_ID_HEADER, IDENTITY_ZONE_SUBDOMAIN_HEADER),
                    requestFields(
                        fieldWithPath("[]").required().description("Modification objects which will each be processed."),
                        fieldWithPath("[].client_id").required().description(clientIdDescription),
                        fieldWithPath("[].action").required().description("Can be any of `add` to create a client, `delete` to delete a client, `update` to alter non-secret client information, `secret` to change the client secret, `update_secret` to alter all client information including the client_secret. For the fields needed to perform any of these actions, see the appropriate endpoint documentation.")
                    ),
                    responseFields((FieldDescriptor[]) ArrayUtils.addAll(
                        fieldsNoSecret,
                        subFields("[]",
                            lastModifiedField,
                            fieldWithPath("approvals_deleted").description("Indicates whether the approvals associated with the client were deleted as a result of this action"),
                            fieldWithPath("action").description("The action that was specified and taken on the client")
                        )
                    ))
                )
            );

        //DELETE

        ResultActions deleteResultActions = getMockMvc().perform(post("/oauth/clients/tx/delete")
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

    private BaseClientDetails createBasicClientWithAdditionalInformation(List<String> scopes) {
        BaseClientDetails clientDetails = createBaseClient(null, null, scopes, scopes);
        clientDetails.setAdditionalInformation(additionalInfo());
        return clientDetails;
    }

    private ResultActions createClientHelper() throws Exception {
        return getMockMvc().perform(post("/oauth/clients")
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
        additionalInformation.put("redirect_uri", Arrays.asList("http://test1.com", "http*://ant.path.wildcard/**/passback/*"));
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList(OriginKeys.UAA, OriginKeys.LDAP, "my-saml-provider"));
        additionalInformation.put(ClientConstants.CLIENT_NAME, "My Client Name");
        additionalInformation.put(ClientConstants.AUTO_APPROVE, true);
        additionalInformation.put(ClientConstants.TOKEN_SALT, new RandomValueStringGenerator().generate());
        return additionalInformation;
    }
}
