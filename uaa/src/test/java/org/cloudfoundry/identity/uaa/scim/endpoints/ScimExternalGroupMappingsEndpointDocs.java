package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.EndpointDocs;
import org.cloudfoundry.identity.uaa.mock.util.DecodePathInfoPostProcessor;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.restdocs.headers.HeaderDescriptor;
import org.springframework.restdocs.request.ParameterDescriptor;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createGroup;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getClientCredentialsOAuthAccessToken;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.fieldWithPath;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.delete;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessRequest;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.NUMBER;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.request.RequestDocumentation.queryParameters;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class ScimExternalGroupMappingsEndpointDocs extends EndpointDocs {
    private static final String GROUP_ID_DESC = "The globally unique group ID";
    private static final String ORIGIN_DESC = "Unique alias of the identity provider";
    private static final String SCHEMAS_DESC = "`[\"urn:scim:schemas:core:1.0\"]`";
    private static final String VERSION_DESC = "The version of the group entity";
    private static final String DISPLAY_NAME_DESC = "The identifier specified upon creation of the group, unique within the identity zone";
    private static final String EXTERNAL_GROUP_DESCRIPTION = "The identifier for the group in external identity provider that needs to be mapped to internal UAA groups";

    private static final HeaderDescriptor AUTHORIZATION_HEADER = headerWithName("Authorization").description("Bearer token with authorization for `scim.write` scope");
    private static final HeaderDescriptor IDENTITY_ZONE_ID_HEADER = headerWithName(IdentityZoneSwitchingFilter.HEADER).description("May include this header to administer another zone if using `zones.<zoneId>.admin` or `uaa.admin` scope against the default UAA zone.").optional();
    private static final HeaderDescriptor IDENTITY_ZONE_SUBDOMAIN_HEADER = headerWithName(IdentityZoneSwitchingFilter.HEADER).optional().description("If using a `zones.<zoneId>.admin` scope/token, indicates what zone this request goes to by supplying a zone_id.");

    private final ParameterDescriptor externalGroup = parameterWithName("externalGroup").required().description(EXTERNAL_GROUP_DESCRIPTION);

    private final Snippet responseFields = responseFields(
            fieldWithPath("groupId").description(GROUP_ID_DESC),
            fieldWithPath("externalGroup").description(EXTERNAL_GROUP_DESCRIPTION),
            fieldWithPath("displayName").description(DISPLAY_NAME_DESC),
            fieldWithPath("origin").description(ORIGIN_DESC),
            fieldWithPath("meta.version").description(VERSION_DESC),
            fieldWithPath("meta.created").description("The time the group mapping was created"),
            fieldWithPath("meta.lastModified").description("The time the group mapping was last updated"),
            fieldWithPath("schemas").description(SCHEMAS_DESC)
    );
    private final ParameterDescriptor origin = parameterWithName("origin").required().description(ORIGIN_DESC);

    private String scimReadToken;
    private String scimWriteToken;

    @BeforeEach
    void setUp() throws Exception {
        scimReadToken = getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret",
                "scim.read", null, true);

        scimWriteToken = getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret",
                "scim.write", null, true);
    }

    @Test
    void createExternalGroupMapping() throws Exception {
        ScimGroup group = new ScimGroup();
        group.setDisplayName("Group For Testing Creating External Group Mapping");
        group = createGroup(mockMvc, scimWriteToken, group);

        Snippet requestHeader = requestHeaders(
                AUTHORIZATION_HEADER, IDENTITY_ZONE_ID_HEADER, IDENTITY_ZONE_SUBDOMAIN_HEADER
        );

        Snippet requestFields = requestFields(
                fieldWithPath("groupId").required().description(GROUP_ID_DESC),
                fieldWithPath("externalGroup").required().description(EXTERNAL_GROUP_DESCRIPTION),
                fieldWithPath("origin").optional(LDAP).type(STRING).description(ORIGIN_DESC),
                fieldWithPath("meta.version").optional(0).description(VERSION_DESC),
                fieldWithPath("meta.created").ignored(),
                fieldWithPath("schemas").ignored()
        );

        createExternalGroupMappingHelper(group)
                .andDo(document("{ClassName}/{methodName}", preprocessRequest(prettyPrint()), preprocessResponse(prettyPrint()),
                        requestHeader, requestFields, responseFields));
    }

    @Test
    void deleteExternalGroupMapping() throws Exception {
        ScimGroup group = new ScimGroup();
        group.setDisplayName("Group For Testing Deleting External Group Mapping");
        group = createGroup(mockMvc, scimWriteToken, group);

        ScimGroupExternalMember scimGroupExternalMember = JsonUtils.readValue(createExternalGroupMappingHelper(group)
                .andReturn().getResponse().getContentAsString(), ScimGroupExternalMember.class);

        Snippet pathParameters = pathParameters(
                parameterWithName("groupId").required().description(GROUP_ID_DESC),
                externalGroup,
                origin
        );

        Snippet requestHeaders = requestHeaders(
                AUTHORIZATION_HEADER, IDENTITY_ZONE_ID_HEADER, IDENTITY_ZONE_SUBDOMAIN_HEADER
        );

        MockHttpServletRequestBuilder delete =
                delete(
                        "/Groups/External/groupId/{groupId}/externalGroup/{externalGroup}/origin/{origin}",
                        group.getId(),
                        scimGroupExternalMember.getExternalGroup(),
                        scimGroupExternalMember.getOrigin()
                )
                .header("Authorization", "Bearer " + scimWriteToken)
                        .with(new DecodePathInfoPostProcessor());

        mockMvc.perform(delete)
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}", preprocessRequest(prettyPrint()), preprocessResponse(prettyPrint()),
                        pathParameters, requestHeaders, responseFields)
                );
    }

    @Test
    void deleteExternalGroupMappingUsingName() throws Exception {
        ScimGroup group = new ScimGroup();
        group.setDisplayName("Group For Testing Deleting External Group Mapping By Name");
        group = createGroup(mockMvc, scimWriteToken, group);

        ScimGroupExternalMember scimGroupExternalMember = JsonUtils.readValue(createExternalGroupMappingHelper(group)
                .andReturn().getResponse().getContentAsString(), ScimGroupExternalMember.class);

        Snippet pathParameters = pathParameters(
                parameterWithName("displayName").required().description(DISPLAY_NAME_DESC),
                externalGroup,
                origin
        );

        Snippet requestHeaders = requestHeaders(
                AUTHORIZATION_HEADER, IDENTITY_ZONE_ID_HEADER, IDENTITY_ZONE_SUBDOMAIN_HEADER
        );

        MockHttpServletRequestBuilder delete =
                delete(
                        "/Groups/External/displayName/{displayName}/externalGroup/{externalGroup}/origin/{origin}",
                        group.getDisplayName(),
                        scimGroupExternalMember.getExternalGroup(),
                        scimGroupExternalMember.getOrigin()
                )
                .header("Authorization", "Bearer " + scimWriteToken)
                        .with(new DecodePathInfoPostProcessor());

        mockMvc.perform(delete)
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}", preprocessRequest(prettyPrint()), preprocessResponse(prettyPrint()),
                        pathParameters, requestHeaders, responseFields));

    }

    @Test
    void listExternalGroupMapping() throws Exception {
        ScimGroup group = new ScimGroup();
        group.setDisplayName("Group For Testing Retrieving External Group Mappings");
        group = createGroup(mockMvc, scimWriteToken, group);

        createExternalGroupMappingHelper(group);

        Snippet queryParameters = queryParameters(
                parameterWithName("startIndex").optional("1").type(NUMBER).description("Display paged results beginning at specified index"),
                parameterWithName("count").optional("100").type(NUMBER).description("Number of results to return per page"),
                parameterWithName("origin").optional(null).type(STRING).description("Filters results based on supplied origin. default is to return all"),
                parameterWithName("externalGroup").optional(null).type(STRING).description("Filters results based on supplied externalGroup. default is to return all"),
                parameterWithName("filter").optional(null).type(STRING).description("Deprecated - will be removed in future release. Use `externalGroup` and `origin` parameters instead.")
        );

        Snippet requestHeaders = requestHeaders(
                headerWithName("Authorization").description("Bearer token with authorization for `scim.read` scope"),
                IDENTITY_ZONE_ID_HEADER,
                IDENTITY_ZONE_SUBDOMAIN_HEADER
        );

        Snippet responseFields = responseFields(
                fieldWithPath("resources[].groupId").description(GROUP_ID_DESC),
                fieldWithPath("resources[].displayName").description(DISPLAY_NAME_DESC),
                fieldWithPath("resources[].externalGroup").description(EXTERNAL_GROUP_DESCRIPTION),
                fieldWithPath("resources[].origin").description(ORIGIN_DESC),

                fieldWithPath("startIndex").description("The index of the first item of this page of results"),
                fieldWithPath("itemsPerPage").description("The page size used in producing this page of results"),
                fieldWithPath("totalResults").description("The number of results which matched the filter"),
                fieldWithPath("schemas").description(SCHEMAS_DESC)
        );

        MockHttpServletRequestBuilder get = get("/Groups/External")
                .header("Authorization", "Bearer " + scimReadToken)
                .param("startIndex", "1")
                .param("count", "50")
                .param("origin", OriginKeys.LDAP)
                .param("externalGroup", "")
                .param("filter", "");

        mockMvc.perform(get)
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}", preprocessRequest(prettyPrint()), preprocessResponse(prettyPrint()),
                        queryParameters, requestHeaders, responseFields));
    }

    private ResultActions createExternalGroupMappingHelper(ScimGroup group) throws Exception {
        ScimGroupExternalMember externalMember = new ScimGroupExternalMember();
        externalMember.setExternalGroup("External group");
        externalMember.setGroupId(group.getId());
        externalMember.setOrigin(OriginKeys.LDAP);

        MockHttpServletRequestBuilder post = post("/Groups/External")
                .contentType(APPLICATION_JSON)
                .header("Authorization", "Bearer " + scimWriteToken)
                .content(JsonUtils.writeValueAsString(externalMember));

        return mockMvc.perform(post)
                .andExpect(status().isCreated());
    }
}
