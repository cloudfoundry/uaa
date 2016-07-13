package org.cloudfoundry.identity.uaa.login;

import junit.framework.Assert;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;

import static java.util.Arrays.asList;
import static junit.framework.TestCase.assertEquals;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;


@RunWith(Parameterized.class)
public class AccountSavingAuthenticationSuccessHandlerTest {

    private final boolean secure;

    public AccountSavingAuthenticationSuccessHandlerTest(boolean secure) {
        this.secure = secure;
    }

    @Parameterized.Parameters
    public static Collection parameters() {
        return asList(new Object[][]{
                {false}, {true}
        });
    }

    @Test
    public void whenSuccessfullyAuthenticated_accountGetsSavedViaCookie() throws IOException, ServletException {
        Date yesterday = new Date(System.currentTimeMillis()-(1000*60*60*24));
        UaaUser user = new UaaUser(
                "user-id",
                "username",
                "password",
                "email",
                Collections.EMPTY_LIST,
                "given name",
                "family name",
                yesterday,
                yesterday,
                "user-origin",
                null,
                true,
                IdentityZone.getUaa().getId(),
                "salt",
                yesterday
        );

        UaaPrincipal principal = new UaaPrincipal(user);
        UaaAuthentication authentication = new UaaAuthentication(principal, null, Collections.EMPTY_LIST, null, true, System.currentTimeMillis());
        AccountSavingAuthenticationSuccessHandler successHandler = new AccountSavingAuthenticationSuccessHandler();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSecure(secure);
        MockHttpServletResponse response = new MockHttpServletResponse();

        successHandler.onAuthenticationSuccess(request, response, authentication);

        Cookie accountOptionCookie = response.getCookie("Saved-Account-user-id");
        assertThat(accountOptionCookie, notNullValue());
        String cookieValue = accountOptionCookie.getValue();

        SavedAccountOption expectedCookieValue = new SavedAccountOption();
        expectedCookieValue.setUserId(user.getId());
        expectedCookieValue.setUsername(user.getUsername());
        expectedCookieValue.setEmail(user.getEmail());
        expectedCookieValue.setOrigin(user.getOrigin());

        assertEquals(JsonUtils.writeValueAsString(expectedCookieValue), cookieValue);
        assertEquals(true, accountOptionCookie.isHttpOnly());
        assertEquals(365*24*60*60, accountOptionCookie.getMaxAge());
        assertEquals("/login", accountOptionCookie.getPath());
        Assert.assertEquals(secure, accountOptionCookie.getSecure());
    }

}