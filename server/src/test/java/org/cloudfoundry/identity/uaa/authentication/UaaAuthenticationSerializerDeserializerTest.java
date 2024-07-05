package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Test;

import java.util.Collections;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;

public class UaaAuthenticationSerializerDeserializerTest {

    @Test
    public void serializeUaaAuthentication() {
        UaaPrincipal p = new UaaPrincipal("user-id", "username", "user@example.com", OriginKeys.UAA, "", IdentityZoneHolder.get().getId());
        UaaAuthentication auth = new UaaAuthentication(p, UaaAuthority.USER_AUTHORITIES, new UaaAuthenticationDetails(false, "clientId", OriginKeys.ORIGIN, "sessionId"));
        auth.setAuthenticationMethods(Collections.singleton("pwd"));
        auth.setAuthContextClassRef(Collections.singleton("test:uri"));
        auth.setAuthenticatedTime(1485314434675L);
        auth.setLastLoginSuccessTime(1485305759366L);

        UaaAuthentication deserializedUaaAuthentication = JsonUtils.readValue(JsonUtils.writeValueAsString(auth), UaaAuthentication.class);

        assertThat(deserializedUaaAuthentication)
                .returns(auth.getDetails(), UaaAuthentication::getDetails)
                .returns(auth.getPrincipal(), UaaAuthentication::getPrincipal)
                .returns(auth.getExpiresAt(), UaaAuthentication::getExpiresAt)
                .returns(auth.getAuthenticatedTime(), UaaAuthentication::getAuthenticatedTime)
                .returns(auth.isAuthenticated(), UaaAuthentication::isAuthenticated)
                .returns(auth.getUserAttributesAsMap(), UaaAuthentication::getUserAttributesAsMap)
                .returns(auth.getAuthenticationMethods(), UaaAuthentication::getAuthenticationMethods)
                .returns(auth.getAuthContextClassRef(), UaaAuthentication::getAuthContextClassRef)
                .returns(auth.getLastLoginSuccessTime(), UaaAuthentication::getLastLoginSuccessTime);

        assertThat(deserializedUaaAuthentication.getAuthorities())
                .extracting(Objects::toString)
                .containsExactly("uaa.user");

        assertThat(deserializedUaaAuthentication.getExternalGroups())
                .isEmpty();
    }
}
