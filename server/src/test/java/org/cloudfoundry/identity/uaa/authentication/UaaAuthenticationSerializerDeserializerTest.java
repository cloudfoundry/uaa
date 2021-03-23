package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Test;

import java.util.Collections;
import java.util.LinkedList;

import static org.junit.Assert.assertEquals;

public class UaaAuthenticationSerializerDeserializerTest {

    @Test
    public void serializeUaaAuthentication() {
        UaaPrincipal p = new UaaPrincipal("user-id", "username", "user@example.com", OriginKeys.UAA, "", IdentityZoneHolder.get().getId());
        UaaAuthentication auth = new UaaAuthentication(p, UaaAuthority.USER_AUTHORITIES, new UaaAuthenticationDetails(false, "clientId", OriginKeys.ORIGIN,"sessionId"));
        auth.setAuthenticationMethods(Collections.singleton("pwd"));
        auth.setAuthContextClassRef(Collections.singleton("test:uri"));
        auth.setAuthenticatedTime(1485314434675L);
        auth.setLastLoginSuccessTime(1485305759366L);

        UaaAuthentication deserializedUaaAuthentication = JsonUtils.readValue(JsonUtils.writeValueAsString(auth), UaaAuthentication.class);

        assertEquals(auth.getDetails(), deserializedUaaAuthentication.getDetails());
        assertEquals(auth.getPrincipal(), deserializedUaaAuthentication.getPrincipal());
        assertEquals("uaa.user", ((LinkedList) deserializedUaaAuthentication.getAuthorities()).get(0).toString());
        assertEquals(Collections.EMPTY_SET, deserializedUaaAuthentication.getExternalGroups());
        assertEquals(auth.getExpiresAt(), deserializedUaaAuthentication.getExpiresAt());
        assertEquals(auth.getAuthenticatedTime(), deserializedUaaAuthentication.getAuthenticatedTime());
        assertEquals(auth.isAuthenticated(), deserializedUaaAuthentication.isAuthenticated());
        assertEquals(auth.getUserAttributesAsMap(), deserializedUaaAuthentication.getUserAttributesAsMap());
        assertEquals(auth.getAuthenticationMethods(), deserializedUaaAuthentication.getAuthenticationMethods());
        assertEquals(auth.getAuthContextClassRef(), deserializedUaaAuthentication.getAuthContextClassRef());
        assertEquals(auth.getLastLoginSuccessTime(), deserializedUaaAuthentication.getLastLoginSuccessTime());
    }
}
