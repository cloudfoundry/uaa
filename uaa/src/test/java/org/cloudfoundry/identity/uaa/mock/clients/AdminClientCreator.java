package org.cloudfoundry.identity.uaa.mock.clients;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.util.Arrays;
import java.util.List;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by pivotal on 1/10/17.
 */
public class ClientEndpointTestUtils extends InjectedMockContextTest {
    public static ClientDetails createAdminClient(String token) throws Exception {
        List<String> scopes = Arrays.asList("uaa.admin","oauth.approvals","clients.read","clients.write");
        BaseClientDetails client = createBaseClient(null, Arrays.asList("password","client_credentials"), scopes, scopes);

        MockHttpServletRequestBuilder createClientPost = MockMvcRequestBuilders.post("/oauth/clients")
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(client));
        getMockMvc().perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }
}
