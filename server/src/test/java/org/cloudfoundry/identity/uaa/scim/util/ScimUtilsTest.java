package org.cloudfoundry.identity.uaa.scim.util;

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class ScimUtilsTest {

    @Test
    void getExpiringCode() {
        ExpiringCodeStore mockExpiringCodeStore = mock(ExpiringCodeStore.class);
        String userId = "userId";
        String email = "email";
        String clientId = "clientId";
        String redirectUri = "redirectUri";
        String currentZoneId = "currentZoneId";
        ExpiringCodeType expiringCodeType = ExpiringCodeType.REGISTRATION;

        Timestamp before = new Timestamp(System.currentTimeMillis() + (55 * 60 * 1000));

        ScimUtils.getExpiringCode(
                mockExpiringCodeStore,
                userId,
                email,
                clientId,
                redirectUri,
                expiringCodeType,
                currentZoneId
        );

        Timestamp after = new Timestamp(System.currentTimeMillis() + (65 * 60 * 1000));

        ArgumentCaptor<Timestamp> timestampArgumentCaptor = ArgumentCaptor.forClass(Timestamp.class);

        verify(mockExpiringCodeStore).generateCode(
                eq("{\"user_id\":\"userId\",\"redirect_uri\":\"redirectUri\",\"email\":\"email\",\"client_id\":\"clientId\"}"),
                timestampArgumentCaptor.capture(),
                eq("REGISTRATION"),
                eq(currentZoneId));

        assertThat(timestampArgumentCaptor.getValue())
                .isAfter(before)
                .isBefore(after);
    }

    @Nested
    class WithRequestContext {

        ExpiringCode mockExpiringCode;

        @BeforeEach
        void setUp() {
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setScheme("http");
            request.setServerName("localhost");
            request.setServerPort(8080);
            request.setContextPath("/uaa");

            ServletRequestAttributes attrs = new ServletRequestAttributes(request);

            RequestContextHolder.setRequestAttributes(attrs);

            mockExpiringCode = mock(ExpiringCode.class);
            when(mockExpiringCode.getCode()).thenReturn("code");
        }

        @AfterEach
        void tearDown() {
            RequestContextHolder.resetRequestAttributes();
        }

        @Nested
        class WhenZoneIsUaa {

            @Test
            void getVerificationURL() throws MalformedURLException {
                URL actual = ScimUtils.getVerificationURL(mockExpiringCode, IdentityZone.getUaa());
                URL expected = URI.create("http://localhost:8080/uaa/verify_user?code=code").toURL();
                assertThat(actual).hasToString(expected.toString());
            }
        }

        @Nested
        class WhenZoneIsNotUaa {
            @Test
            void getVerificationURL() throws MalformedURLException {
                IdentityZone mockIdentityZone = mock(IdentityZone.class);
                when(mockIdentityZone.isUaa()).thenReturn(false);
                when(mockIdentityZone.getSubdomain()).thenReturn("subdomain");

                URL actual = ScimUtils.getVerificationURL(mockExpiringCode, mockIdentityZone);
                URL expected = URI.create("http://subdomain.localhost:8080/uaa/verify_user?code=code").toURL();
                assertThat(actual).hasToString(expected.toString());
            }
        }
    }

    @Test
    void userWithEmptyandNonEmptyEmails() {
        ScimUser user = new ScimUser(null, "josephine", "Jo", "Jung");
        List<ScimUser.Email> emails = new ArrayList<>();
        ScimUser.Email email1 = new ScimUser.Email();
        email1.setValue("sample@sample.com");
        emails.add(email1);
        ScimUser.Email email2 = new ScimUser.Email();
        email2.setValue("");
        emails.add(email2);
        user.setEmails(emails);

        assertThatExceptionOfType(InvalidScimResourceException.class).isThrownBy(() -> ScimUtils.validate(user));
    }

    @Test
    void userWithEmptyEmail() {
        ScimUser user = new ScimUser(null, "josephine", "Jo", "Jung");
        List<ScimUser.Email> emails = new ArrayList<>();
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("");
        emails.add(email);
        user.setEmails(emails);

        assertThatExceptionOfType(InvalidScimResourceException.class).isThrownBy(() -> ScimUtils.validate(user));
    }

    @Test
    void userWithNonAsciiUsername() {
        ScimUser user = new ScimUser(null, "joe$eph", "Jo", "User");
        user.setOrigin(OriginKeys.UAA);
        user.addEmail("jo@blah.com");

        assertThatExceptionOfType(InvalidScimResourceException.class).isThrownBy(() -> ScimUtils.validate(user));
    }
}
