package org.cloudfoundry.identity.uaa.oauth;

import com.google.common.collect.Lists;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.*;

import static org.cloudfoundry.identity.uaa.config.IdentityZoneConfigurationBootstrapTests.PRIVATE_KEY;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.*;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TokenValidationServiceTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();
    private TokenValidationService tokenValidationService;
    private UaaUserDatabase userDatabase;
    private TokenEndpointBuilder tokenEndpointBuilder;
    private MultitenantClientServices mockMultitenantClientServices;
    private RevocableTokenProvisioning revocableTokenProvisioning;
    private Map<String, Object> header;
    private RsaSigner signer;
    private String userId = "asdf-bfdsajk-asdfjsa";
    private String clientId = "myclient";
    private Map<String, Object> content;

    @Before
    public void setup() {
        header = map(
                entry("alg", "RS256"),
                entry("kid", "key1"),
                entry("typ", "JWT")
        );
        content = map(
                entry(USER_ID, userId),
                entry(JTI, "abcdefg"),
                entry(CID, clientId),
                entry(SCOPE, Lists.newArrayList("foo.bar"))
        );
        signer = new RsaSigner(PRIVATE_KEY);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("key1", PRIVATE_KEY));

        userDatabase = mock(UaaUserDatabase.class);
        tokenEndpointBuilder = mock(TokenEndpointBuilder.class);
        mockMultitenantClientServices = mock(MultitenantClientServices.class);
        revocableTokenProvisioning = mock(RevocableTokenProvisioning.class);

        when(mockMultitenantClientServices.loadClientByClientId(clientId, IdentityZoneHolder.get().getId())).thenReturn(new BaseClientDetails(clientId, null, "foo.bar", null, null));
        UaaUser user = new UaaUser(userId, "marrisa", "koala", "marissa@gmail.com", buildGrantedAuthorities("foo.bar"), "Marissa", "Bloggs", null, null, null, null, true, null, null, null);
        when(userDatabase.retrieveUserById(userId)).thenReturn(user);

        tokenValidationService = new TokenValidationService(
                revocableTokenProvisioning,
                tokenEndpointBuilder,
                userDatabase,
                mockMultitenantClientServices,
                new KeyInfoService("http://localhost:8080/uaa")
        );
    }

    @After
    public void cleanup() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void validation_happyPath() {
        String accessToken = UaaTokenUtils.constructToken(header, content, signer);

        tokenValidationService.validateToken(accessToken, true);
    }

    @Test
    public void validation_enforcesKeyId() {
        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("Token header claim [kid] references unknown signing key : [testKey]");

        header.put("kid", "testKey");

        String accessToken = UaaTokenUtils.constructToken(header, content, signer);

        tokenValidationService.validateToken(accessToken, true);
    }

    @Test
    public void validationFails_whenUserNotFound() {
        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("Token bears a non-existent user ID: " + userId);

        when(userDatabase.retrieveUserById(userId)).thenThrow(UsernameNotFoundException.class);
        String accessToken = UaaTokenUtils.constructToken(header, content, signer);

        tokenValidationService.validateToken(accessToken, true);
    }

    @Test
    public void validationFails_whenClientNotFound() {
        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("Invalid client ID "+clientId);

        when(mockMultitenantClientServices.loadClientByClientId(clientId, IdentityZoneHolder.get().getId())).thenThrow(NoSuchClientException.class);
        String accessToken = UaaTokenUtils.constructToken(header, content, signer);

        tokenValidationService.validateToken(accessToken, true);
    }

    @Test
    public void refreshToken_validatesWithScopeClaim_forBackwardsCompatibilityReasons() {
        Map<String, Object> content = map(
                entry(USER_ID, userId),
                entry(JTI, "abcdefg-r"),
                entry(CID, clientId),
                entry(SCOPE, Lists.newArrayList("foo.bar"))
        );
        String refreshToken = UaaTokenUtils.constructToken(header, content, signer);

        tokenValidationService.validateToken(refreshToken, false);
    }

    @Test
    public void refreshToken_validatesWithGrantedScopesClaim() {
        Map<String, Object> content = map(
                entry(USER_ID, userId),
                entry(JTI, "abcdefg-r"),
                entry(CID, clientId),
                entry(GRANTED_SCOPES, Lists.newArrayList("foo.bar"))
        );
        String refreshToken = UaaTokenUtils.constructToken(header, content, signer);

        tokenValidationService.validateToken(refreshToken, false);
    }

    private ArrayList<GrantedAuthority> buildGrantedAuthorities(String authority) {
        ArrayList<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(UaaAuthority.authority(authority));
        return grantedAuthorities;
    }
}