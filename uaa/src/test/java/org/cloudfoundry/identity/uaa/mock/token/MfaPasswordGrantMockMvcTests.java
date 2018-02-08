package org.cloudfoundry.identity.uaa.mock.token;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mfa.JdbcUserGoogleMfaCredentialsProvisioning;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa.UserGoogleMfaCredentialsProvisioning;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.util.OAuth2Utils;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createMfaProvider;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.OPAQUE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REQUEST_TOKEN_FORMAT;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

public class MfaPasswordGrantMockMvcTests extends InjectedMockContextTest {

    IdentityZone zone;
    private String adminToken;
    private JdbcUserGoogleMfaCredentialsProvisioning jdbcUserGoogleMfaCredentialsProvisioning;
    private UserGoogleMfaCredentialsProvisioning userGoogleMfaCredentialsProvisioning;
    private UaaUserDatabase userDb;
    private MfaProvider mfaProvider;
    private IdentityZoneConfiguration uaaZoneConfig;
    private GoogleAuthenticator authenticator;

    @Before
    public void setupForMfaPasswordGrant() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "clients.read clients.write clients.secret clients.admin uaa.admin"
        );
        mfaProvider = createMfaProvider(getMockMvc(), IdentityZone.getUaa().getId(), adminToken);

        uaaZoneConfig = MockMvcUtils.getZoneConfiguration(getWebApplicationContext(), "uaa");
        uaaZoneConfig.getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        MockMvcUtils.setZoneConfiguration(getWebApplicationContext(), "uaa", uaaZoneConfig);

        userDb = getWebApplicationContext().getBean(UaaUserDatabase.class);
        String userId = userDb.retrieveUserByName("marissa", OriginKeys.UAA).getId();
        authenticator = getWebApplicationContext().getBean(GoogleAuthenticator.class);


        //GoogleAuthenticatorKey credentials = authenticator.createCredentials(userId);

    }

    @After
    public void cleanup() throws Exception {
        uaaZoneConfig.getMfaConfig().setEnabled(false).setProviderName(null);
        MockMvcUtils.setZoneConfiguration(getWebApplicationContext(), "uaa", uaaZoneConfig);

    }

    @Test
    public void mfa_happy_path() throws Exception {
        getMockMvc().perform(
            post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.RESPONSE_TYPE, "token")
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, "cf")
                .param(REQUEST_TOKEN_FORMAT, OPAQUE)
                .param("client_secret", "")
                .param("username", "marissa")
                .param("password", "koala")
        );
    }

}
