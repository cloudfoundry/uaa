package org.cloudfoundry.identity.uaa.oauth.provider.code;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class InMemoryAuthorizationCodeServicesTest {

    private InMemoryAuthorizationCodeServices inMemoryAuthorizationCodeServices;
    private OAuth2Authentication oAuth2Authentication;


    @BeforeEach
    void setUp() throws Exception {
        inMemoryAuthorizationCodeServices = new InMemoryAuthorizationCodeServices();
        oAuth2Authentication = mock(OAuth2Authentication.class);
    }

    @Test
    void store() {
        inMemoryAuthorizationCodeServices.store("code", oAuth2Authentication);
        assertThat(inMemoryAuthorizationCodeServices.authorizationCodeStore).containsEntry("code", oAuth2Authentication);
    }

    @Test
    void remove() {
        assertThat(inMemoryAuthorizationCodeServices.authorizationCodeStore).isEmpty();
        inMemoryAuthorizationCodeServices.store("code", oAuth2Authentication);
        assertThat(inMemoryAuthorizationCodeServices.authorizationCodeStore).hasSize(1);
        inMemoryAuthorizationCodeServices.remove("code");
        assertThat(inMemoryAuthorizationCodeServices.authorizationCodeStore).isEmpty();
    }
}