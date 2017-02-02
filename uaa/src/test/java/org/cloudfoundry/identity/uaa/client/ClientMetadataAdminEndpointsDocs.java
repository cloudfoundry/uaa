package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.mock.clients.AdminClientCreator;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimGroupEndpoints;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimUserEndpoints;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.Before;
import org.junit.Test;
import org.springframework.restdocs.payload.JsonFieldType;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import javax.servlet.http.HttpServletResponse;
import java.net.URL;
import java.util.Arrays;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.test.SnippetUtils.fieldWithPath;
import static org.mockito.Mockito.mock;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ClientMetadataAdminEndpointsDocs extends AdminClientCreator {

  private RandomValueStringGenerator generator = new RandomValueStringGenerator(8);
  private MultitenantJdbcClientDetailsService clients;
  private String adminClientTokenWithClientsWrite;
  private String adminUserToken;
  private UaaTestAccounts testAccounts;
  private static final String RESOURCE_OWNER_GUID = "The user guid of the resource owner who created this client";
  private static final String CLIENT_ID_DESC = "Client identifier, unique within identity zone";
  private static final String CLIENT_NAME_DESC = "Human readable display name for the client";
  private static final String SHOW_ON_HOME_PAGE_DESC = "Flag to control visibility on home page";
  private static final String APP_LAUNCH_URL_DESC = "URL to which the app is linked to";
  private static final String APP_ICON_DESC = "Base64 encoded image file";
  private Snippet responseFields = responseFields(
    fieldWithPath("clientId").description(CLIENT_ID_DESC),
    fieldWithPath("showOnHomePage").description(SHOW_ON_HOME_PAGE_DESC),
    fieldWithPath("appLaunchUrl").description(APP_LAUNCH_URL_DESC),
    fieldWithPath("appIcon").description(APP_ICON_DESC),
    fieldWithPath("createdBy").description(RESOURCE_OWNER_GUID).type(JsonFieldType.STRING).optional()
  );

  @Before
  public void setUp() throws Exception {
    testAccounts = UaaTestAccounts.standard(null);
    clients = getWebApplicationContext().getBean(MultitenantJdbcClientDetailsService.class);
    adminClientTokenWithClientsWrite = testClient.getClientCredentialsOAuthAccessToken(
      testAccounts.getAdminClientId(),
      testAccounts.getAdminClientSecret(),
      "clients.write,uaa.admin");

    ClientDetails adminClient = createAdminClient(adminClientTokenWithClientsWrite);

    HttpServletResponse mockResponse = mock(HttpServletResponse.class);

    ScimUserEndpoints scimUserEndpoints = getWebApplicationContext().getBean(ScimUserEndpoints.class);
    ScimGroupEndpoints scimGroupEndpoints = getWebApplicationContext().getBean(ScimGroupEndpoints.class);

    SearchResults<Map<String, Object>> marissa = (SearchResults<Map<String, Object>>)scimUserEndpoints.findUsers("id,userName", "userName eq \"marissa\"", "userName", "asc", 0, 1);
    String marissaId = (String)marissa.getResources().iterator().next().get("id");

    //add marissa to uaa.admin
    SearchResults<Map<String, Object>> uaaAdmin = (SearchResults<Map<String, Object>>) scimGroupEndpoints.listGroups("id,displayName", "displayName eq \"uaa.admin\"", "displayName", "asc", 1, 1);
    String groupId = (String)uaaAdmin.getResources().iterator().next().get("id");
    ScimGroup group = scimGroupEndpoints.getGroup(groupId, mockResponse);
    ScimGroupMember gm = new ScimGroupMember(marissaId, ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER));
    group.getMembers().add(gm);
    scimGroupEndpoints.updateGroup(group, groupId, String.valueOf(group.getVersion()), mockResponse);

   adminUserToken = testClient.getUserOAuthAccessToken(adminClient.getClientId(),
        "secret",
        "marissa",
        "koala",
        "uaa.admin");
  }

  @Test
  public void getClientMetadata() throws Exception {
    String clientId = generator.generate();
    createClient(clientId);
    updateClientMetadata(clientId);
    String marissaToken = getUserAccessToken(clientId);

    MockHttpServletRequestBuilder get = get("/oauth/clients/{clientId}/meta", clientId)
      .header("Authorization", "Bearer " + marissaToken)
      .accept(APPLICATION_JSON);

    Snippet pathParameters = pathParameters(
      parameterWithName("clientId").description(CLIENT_ID_DESC)
    );

    Snippet requestHeaders = requestHeaders(
      headerWithName("Authorization").description("Bearer token")
    );

    getMockMvc().perform(get).andExpect(status().isOk())
    .andDo(document("{ClassName}/{methodName}",
      preprocessResponse(prettyPrint()),
      pathParameters,
      requestHeaders,
      responseFields
    ));
  }

  @Test
  public void getAllClientMetadata() throws Exception {
    String clientId1 = generator.generate();
    createClient(clientId1);
    updateClientMetadata(clientId1);
    String marissaToken = getUserAccessToken(clientId1);

    String clientId2 = generator.generate();
    clients.addClientDetails(new BaseClientDetails(clientId2, null, null, null, null));

    String clientId3 = generator.generate();
    clients.addClientDetails(new BaseClientDetails(clientId3, null, null, null, null));
    ClientMetadata client3Metadata = new ClientMetadata();
    client3Metadata.setClientId(clientId3);
    client3Metadata.setIdentityZoneId("uaa");
    client3Metadata.setAppLaunchUrl(new URL("http://client3.com/app"));
    client3Metadata.setShowOnHomePage(true);
    client3Metadata.setAppIcon("Y2xpZW50IDMgaWNvbg==");
    performUpdate(client3Metadata);

    String clientId4 = generator.generate();
    clients.addClientDetails(new BaseClientDetails(clientId4, null, null, null, null));
    ClientMetadata client4Metadata = new ClientMetadata();
    client4Metadata.setClientId(clientId4);
    client4Metadata.setIdentityZoneId("uaa");
    client4Metadata.setAppLaunchUrl(new URL("http://client4.com/app"));
    client4Metadata.setAppIcon("aWNvbiBmb3IgY2xpZW50IDQ=");
    performUpdate(client4Metadata);

    Snippet requestHeaders = requestHeaders(
      headerWithName("Authorization").description("Bearer token")
    );

    Snippet responseFields = responseFields(
      fieldWithPath("[].clientId").description(CLIENT_ID_DESC),
      fieldWithPath("[].clientName").description(CLIENT_NAME_DESC),
      fieldWithPath("[].showOnHomePage").description(SHOW_ON_HOME_PAGE_DESC),
      fieldWithPath("[].appLaunchUrl").description(APP_LAUNCH_URL_DESC),
      fieldWithPath("[].appIcon").description(APP_ICON_DESC),
      fieldWithPath("[].createdBy").description(RESOURCE_OWNER_GUID)
    );

    getMockMvc().perform(get("/oauth/clients/meta")
      .header("Authorization", "Bearer " + marissaToken)
      .accept(APPLICATION_JSON)).andExpect(status().isOk())
      .andDo(document("{ClassName}/{methodName}",
        preprocessResponse(prettyPrint()),
        requestHeaders,
        responseFields
    ));
  }

  @Test
  public void updateClientMetadata() throws Exception {
    String clientId = generator.generate();
    createClient(clientId);

    ClientMetadata updatedClientMetadata = new ClientMetadata();
    updatedClientMetadata.setClientId(clientId);
    URL appLaunchUrl = new URL("http://changed.app.launch/url");
    updatedClientMetadata.setAppLaunchUrl(appLaunchUrl);

    ResultActions perform = performUpdate(updatedClientMetadata);

    Snippet requestHeaders = requestHeaders(
      headerWithName("Authorization").description("Bearer token containing `clients.read`, `clients.admin` or `zones.{zone.id}.admin`"),
      headerWithName("X-Identity-Zone-Id").description("May include this header to administer another zone if using `zones.<zone.id>.admin` or `uaa.admin` scope against the default UAA zone.").optional()
    );

    perform.andExpect(status().isOk())
      .andDo(document("{ClassName}/{methodName}",
        preprocessResponse(prettyPrint()),
        requestHeaders,
        responseFields
    ));

  }

  private String getUserAccessToken(String clientId) throws Exception {
    return testClient.getUserOAuthAccessToken(clientId, "secret", "marissa", "koala", "oauth.approvals");
  }

    private void updateClientMetadata(String clientId) throws Exception {
        ClientMetadata clientMetaData = new ClientMetadata();
        clientMetaData.setClientId(clientId);
        clientMetaData.setAppIcon("aWNvbiBmb3IgY2xpZW50IDQ=");
        clientMetaData.setAppLaunchUrl(new URL("http://myloginpage.com"));
        clientMetaData.setShowOnHomePage(true);
        performUpdate(clientMetaData);
    }

    private void createClient(String clientId) throws Exception {
        BaseClientDetails newClient = new BaseClientDetails(clientId, "oauth", "oauth.approvals", "password", "oauth.login");
        newClient.setClientSecret("secret");
        MockHttpServletRequestBuilder createClient = post("/oauth/clients")
            .header("Authorization", "Bearer " + adminUserToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(newClient));
        getMockMvc().perform(createClient);
    }

    private ResultActions performUpdate(ClientMetadata updatedClientMetadata) throws Exception {
    MockHttpServletRequestBuilder updateClientPut = put("/oauth/clients/" + updatedClientMetadata.getClientId() + "/meta")
      .header("Authorization", "Bearer " + adminClientTokenWithClientsWrite)
      .header("If-Match", "0")
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(JsonUtils.writeValueAsString(updatedClientMetadata));
    return getMockMvc().perform(updateClientPut);
  }
}
