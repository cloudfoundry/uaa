package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Date;
import java.util.Optional;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AccountSavingAuthenticationSuccessHandlerTest {

    private AccountSavingAuthenticationSuccessHandler successHandler;
    private SavedRequestAwareAuthenticationSuccessHandler redirectingHandler;
    private CurrentUserCookieFactory currentUserCookieFactory;

    public static Stream<Boolean> parameters() {
        return Stream.of(false, true);
    }

    @BeforeEach
    void setup() throws Exception {
        redirectingHandler = mock(SavedRequestAwareAuthenticationSuccessHandler.class);
        currentUserCookieFactory = mock(CurrentUserCookieFactory.class);
        when(currentUserCookieFactory.getCookie(any())).thenReturn(new Cookie("Current-User", "%7B%22userId%22%3A%22user-id%22%7D"));
        successHandler = new AccountSavingAuthenticationSuccessHandler(redirectingHandler, currentUserCookieFactory);
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void invalid_principal_throws(boolean secure) {
        Authentication a = mock(Authentication.class);
        when(a.getPrincipal()).thenReturn(new Object());
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSecure(secure);
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThatThrownBy(() -> successHandler.setSavedAccountOptionCookie(request, response, a))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unrecognized authentication principle.");
    }

    @MethodSource("parameters")
    @SuppressWarnings("deprecation")
    @ParameterizedTest
    void whenSuccessfullyAuthenticated_accountGetsSavedViaCookie(boolean secure) throws IOException, ServletException, CurrentUserCookieFactory.CurrentUserCookieEncodingException {
        IdentityZoneHolder.get().getConfig().setAccountChooserEnabled(true);
        Date yesterday = new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24));
        UaaUser user = new UaaUser(
                "user-id",
                "username",
                "password",
                "email",
                Collections.emptyList(),
                "given name",
                "family name",
                yesterday,
                yesterday,
                "user-origin",
                null,
                true,
                IdentityZone.getUaaZoneId(),
                "salt",
                yesterday
        );

        UaaPrincipal principal = new UaaPrincipal(user);
        UaaAuthentication authentication = new UaaAuthentication(principal, null, Collections.emptyList(), null, true, System.currentTimeMillis());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSecure(secure);
        MockHttpServletResponse response = new MockHttpServletResponse();

        successHandler.onAuthenticationSuccess(request, response, authentication);

        Cookie accountOptionCookie = response.getCookie("Saved-Account-user-id");
        assertThat(accountOptionCookie).isNotNull();
        String cookieValue = accountOptionCookie.getValue();

        SavedAccountOption expectedCookieValue = new SavedAccountOption();
        expectedCookieValue.setUserId(user.getId());
        expectedCookieValue.setUsername(user.getUsername());
        expectedCookieValue.setEmail(user.getEmail());
        expectedCookieValue.setOrigin(user.getOrigin());

        assertThat(cookieValue).isEqualTo(URLEncoder.encode(JsonUtils.writeValueAsString(expectedCookieValue), StandardCharsets.UTF_8));
        assertThat(accountOptionCookie.isHttpOnly()).isTrue();
        assertThat(accountOptionCookie.getMaxAge()).isEqualTo(365 * 24 * 60 * 60);
        assertThat(accountOptionCookie.getPath()).isEqualTo("/login");
        assertThat(accountOptionCookie.getSecure()).isEqualTo(secure);

        verify(redirectingHandler, times(1)).onAuthenticationSuccess(request, response, authentication);

        ArgumentCaptor<UaaPrincipal> uaaPrincipal = ArgumentCaptor.forClass(UaaPrincipal.class);
        verify(currentUserCookieFactory).getCookie(uaaPrincipal.capture());
        assertThat(uaaPrincipal.getValue().getId()).isEqualTo("user-id");

        Cookie currentUserCookie = response.getCookie("Current-User");
        assertThat(currentUserCookie).isNotNull();
        assertThat(currentUserCookie.getValue()).contains("user-id");

        Optional<String> actualCurrentUserCookieHeaderValue = response.getHeaders("Set-Cookie").stream()
                .filter(headerValue -> headerValue.startsWith("Current-User"))
                .findAny();
        assertThat(actualCurrentUserCookieHeaderValue).contains("Current-User=%7B%22userId%22%3A%22user-id%22%7D; SameSite=Strict");
    }

    @MethodSource("parameters")
    @ParameterizedTest
    void empty_Account_Cookie(boolean secure) throws IOException, ServletException {
        IdentityZoneHolder.get().getConfig().setAccountChooserEnabled(false);
        Date yesterday = new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24));
        UaaUser user = new UaaUser(
                "user-id",
                "username",
                "password",
                "email",
                Collections.emptyList(),
                "given name",
                "family name",
                yesterday,
                yesterday,
                "user-origin",
                null,
                true,
                IdentityZone.getUaaZoneId(),
                "salt",
                yesterday
        );

        UaaPrincipal principal = new UaaPrincipal(user);
        UaaAuthentication authentication = new UaaAuthentication(principal, null, Collections.emptyList(), null, true, System.currentTimeMillis());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSecure(secure);
        MockHttpServletResponse response = new MockHttpServletResponse();

        successHandler.onAuthenticationSuccess(request, response, authentication);

        Cookie accountOptionCookie = response.getCookie("Saved-Account-user-id");
        assertThat(accountOptionCookie).isNull();
    }
}