package org.cloudfoundry.identity.uaa.mock.clients;

import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.mock.EndpointDocs;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.AuthorityUtils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.mock.util.ClientDetailsHelper.clientFromString;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public abstract class AdminClientCreator extends EndpointDocs {
    protected String adminToken;
    protected UaaTestAccounts testAccounts;

    public static final String SECRET = "secret";

    @BeforeEach
    public void initAdminToken() throws Exception {
        testAccounts = UaaTestAccounts.standard(null);
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "clients.admin clients.read clients.write clients.secret scim.read scim.write");
    }

    ClientDetailsModification createBaseClient(String id, String clientSecret, Collection<String> grantTypes, List<String> authorities, List<String> scopes) {
        if (id == null) {
            id = new RandomValueStringGenerator().generate();
        }
        if (grantTypes == null) {
            grantTypes = Collections.singleton("client_credentials");
        }
        ClientDetailsModification client = new ClientDetailsModification();
        client.setClientId(id);
        client.setScope(scopes);
        client.setAuthorizedGrantTypes(grantTypes);
        if (authorities != null) {
            client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList(String.join(",", authorities)));
        }
        client.setClientSecret(clientSecret);
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("foo", "bar");
        additionalInformation.put("name", makeClientName(id));
        client.setAdditionalInformation(additionalInformation);
        client.setRegisteredRedirectUri(Collections.singleton("http://some.redirect.url.com"));
        return client;
    }

    protected ClientDetails createClient(String token, String id, String clientSecret, Collection<String> grantTypes) throws Exception {
        ClientDetails client = createBaseClient(id, clientSecret, grantTypes);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }

    protected ClientDetails createAdminClient(String token) throws Exception {
        List<String> scopes = Arrays.asList("uaa.admin", "oauth.approvals", "clients.read", "clients.write");
        ClientDetails client = createBaseClient(null, SECRET, Arrays.asList("password", "client_credentials"), scopes, scopes);

        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }

    private ClientDetailsModification createBaseClient(String id, String clientSecret, Collection<String> grantTypes) {
        return createBaseClient(id, clientSecret, grantTypes, Collections.singletonList("uaa.none"), Arrays.asList("foo", "bar", "oauth.approvals"));
    }

    private ClientDetails getClient(String id) throws Exception {
        MockHttpServletResponse response = getClientHttpResponse(id);
        return getClientResponseAsClientDetails(response);
    }

    protected String toString(Object client) {
        return JsonUtils.writeValueAsString(client);
    }

    protected String toString(Object[] clients) {
        return JsonUtils.writeValueAsString(clients);
    }

    private MockHttpServletResponse getClientHttpResponse(String id) throws Exception {
        MockHttpServletRequestBuilder getClient = get("/oauth/clients/" + id)
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON);
        ResultActions result = mockMvc.perform(getClient);
        return result.andReturn().getResponse();
    }

    private ClientDetails getClientResponseAsClientDetails(MockHttpServletResponse response) throws Exception {
        int responseCode = response.getStatus();
        HttpStatus status = HttpStatus.valueOf(responseCode);
        String body = response.getContentAsString();
        if (status == HttpStatus.OK) {
            return clientFromString(body);
        } else if (status == HttpStatus.NOT_FOUND) {
            return null;
        } else {
            throw new InvalidClientDetailsException(status + " : " + body);
        }
    }

    private static String makeClientName(String id) {
        return "Client " + id;
    }
}
