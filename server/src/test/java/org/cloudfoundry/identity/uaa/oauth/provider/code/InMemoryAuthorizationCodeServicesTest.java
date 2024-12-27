package org.cloudfoundry.identity.uaa.oauth.provider.code;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

public class InMemoryAuthorizationCodeServicesTest {

    private InMemoryAuthorizationCodeServices inMemoryAuthorizationCodeServices;
    private OAuth2Authentication oAuth2Authentication;


    @Before
    public void setUp() throws Exception {
        inMemoryAuthorizationCodeServices = new InMemoryAuthorizationCodeServices();
        oAuth2Authentication = mock(OAuth2Authentication.class);
    }

    @Test
    public void store() {
        inMemoryAuthorizationCodeServices.store("code", oAuth2Authentication);
        assertEquals(oAuth2Authentication, inMemoryAuthorizationCodeServices.authorizationCodeStore.get("code"));
    }

    @Test
    public void remove() {
        assertEquals(0, inMemoryAuthorizationCodeServices.authorizationCodeStore.size());
        inMemoryAuthorizationCodeServices.store("code", oAuth2Authentication);
        assertEquals(1, inMemoryAuthorizationCodeServices.authorizationCodeStore.size());
        inMemoryAuthorizationCodeServices.remove("code");
        assertEquals(0, inMemoryAuthorizationCodeServices.authorizationCodeStore.size());
    }
}