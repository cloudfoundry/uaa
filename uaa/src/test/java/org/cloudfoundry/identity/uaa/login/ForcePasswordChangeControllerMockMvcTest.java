package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.account.UserAccountStatus;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.junit.Assert.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ForcePasswordChangeControllerMockMvcTest extends InjectedMockContextTest {
    @Test
    public void testChangePasswordValid() throws Exception {
        String username = new RandomValueStringGenerator().generate() + "@test.org";
        ScimUser user = new ScimUser(null, username, "givenname","familyname");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        String token = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", null, null);
        user = MockMvcUtils.utils().createUser(getMockMvc(), token, user);
        UserAccountStatus userAccountStatus = new UserAccountStatus();
        userAccountStatus.isPasswordChangeRequired(true);
        String jsonStatus = JsonUtils.writeValueAsString(userAccountStatus);
        getMockMvc().perform(
            patch("/Users/"+user.getId()+"/status")
                .header("Authorization", "Bearer "+token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(jsonStatus))
            .andExpect(status().isOk());

        getMockMvc().perform(
            post("/login.do")
                .
        )
    }
}
