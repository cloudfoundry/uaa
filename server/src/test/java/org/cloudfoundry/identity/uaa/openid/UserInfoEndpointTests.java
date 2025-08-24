package org.cloudfoundry.identity.uaa.openid;

import org.cloudfoundry.identity.uaa.account.UserInfoEndpoint;
import org.cloudfoundry.identity.uaa.account.UserInfoResponse;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ROLES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ID;

class UserInfoEndpointTests {

    private static final String MULTI_VALUE = "multi_value";
    private static final String SINGLE_VALUE = "single_value";
    private static final String ID = "12345";

    private static final UaaUser user = new UaaUser(new UaaUserPrototype()
            .withId(ID)
            .withPhoneNumber("8505551234")
            .withUsername("olds")
            .withPassword("")
            .withEmail("olds@vmware.com")
            .withFamilyName("Olds")
            .withGivenName("Dale")
            .withCreated(new Date())
            .withModified(new Date())
            .withAuthorities(UaaAuthority.USER_AUTHORITIES)
            .withOrigin(OriginKeys.UAA)
            .withExternalId("externalId")
            .withVerified(false)
            .withZoneId(IdentityZoneHolder.get().getId())
            .withSalt("12345")
            .withPasswordLastModified(new Date())
            .withLastLogonSuccess(1000L)
            .withPreviousLogonSuccess(1000L));

    private static final UaaUser verifiedUser = new UaaUser(new UaaUserPrototype()
            .withId(ID + "v")
            .withPhoneNumber("8505551234")
            .withUsername("somename")
            .withPassword("")
            .withEmail("comr@dstal.in")
            .withVerified(true)
            .withFamilyName("Olds")
            .withGivenName("Dale")
            .withCreated(new Date())
            .withModified(new Date())
            .withAuthorities(UaaAuthority.USER_AUTHORITIES)
            .withOrigin(OriginKeys.UAA)
            .withExternalId("externalId")
            .withZoneId(IdentityZoneHolder.get().getId())
            .withSalt("12345")
            .withPasswordLastModified(new Date())
            .withLastLogonSuccess(1000L)
            .withPreviousLogonSuccess(1000L));

    private InMemoryUaaUserDatabase userDatabase;
    private UserInfoEndpoint endpoint;
    private UserInfo info;
    private List<String> roles;

    @BeforeEach
    void setup() {
        userDatabase = new InMemoryUaaUserDatabase(Arrays.asList(user, verifiedUser));
        endpoint = new UserInfoEndpoint(userDatabase);
        MultiValueMap<String, String> customAttributes = new LinkedMultiValueMap<>();
        customAttributes.put(MULTI_VALUE, Arrays.asList("value1", "value2"));
        customAttributes.add(SINGLE_VALUE, "value3");
        roles = Arrays.asList("group1", "group1");
        info = new UserInfo()
                .setUserAttributes(customAttributes)
                .setRoles(roles);
        userDatabase.storeUserInfo(ID, info);
    }

    @Test
    void sunnyDay() {
        UaaUser user = userDatabase.retrieveUserByName("olds", OriginKeys.UAA);
        UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication(user.getId(), "olds",
                "olds@vmware.com", new HashSet<>(Collections.singletonList("openid")));

        UserInfoResponse userInfoResponse = endpoint.loginInfo(new OAuth2Authentication(createOauthRequest(Collections.singletonList(
                "openid")), authentication));

        assertThat(userInfoResponse.getUserName()).isEqualTo("olds");
        assertThat(userInfoResponse.getFullName()).isEqualTo("Dale Olds");
        assertThat(userInfoResponse.getEmail()).isEqualTo("olds@vmware.com");
        assertThat(userInfoResponse.getPhoneNumber()).isEqualTo("8505551234");
        assertThat(userInfoResponse.isEmailVerified()).isFalse();
        assertThat((long) userInfoResponse.getPreviousLogonSuccess()).isEqualTo(1000);
        assertThat(userInfoResponse.getSub()).isEqualTo(user.getId());
        assertThat(userInfoResponse.getUserAttributes()).isNull();
    }

    @Test
    void verifiedUser() {
        UaaUser user = userDatabase.retrieveUserByName("somename", OriginKeys.UAA);
        UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication(user.getId(), "somename",
                "comr@dstal.in", new HashSet<>(Collections.singletonList("openid")));

        UserInfoResponse userInfoResponse = endpoint.loginInfo(new OAuth2Authentication(createOauthRequest(Collections.singletonList(
                "openid")), authentication));

        assertThat(userInfoResponse.getUserName()).isEqualTo("somename");
        assertThat(userInfoResponse.isEmailVerified()).isTrue();
    }

    @Test
    void sunnyDay_whenLastLogonNull_displaysNull() {
        user.setPreviousLogonTime(null);
        UaaUser user = userDatabase.retrieveUserByName("olds", OriginKeys.UAA);
        UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication(user.getId(), "olds",
                "olds@vmware.com", new HashSet<>(Collections.singletonList("openid")));

        UserInfoResponse map = endpoint.loginInfo(new OAuth2Authentication(createOauthRequest(Collections.singletonList(
                "openid")), authentication));

        assertThat(map.getPreviousLogonSuccess()).isNull();
    }

    @Test
    void sunnyDay_WithCustomAttributes() {
        UaaUser user = userDatabase.retrieveUserByName("olds", OriginKeys.UAA);
        UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication(
                user.getId(),
                "olds",
                "olds@vmware.com"
        );
        OAuth2Request request = createOauthRequest(Arrays.asList(USER_ATTRIBUTES, "openid", ROLES));
        UserInfoResponse map = endpoint.loginInfo(new OAuth2Authentication(request, authentication));
        assertThat(map.getUserName()).isEqualTo("olds");
        assertThat(map.getFullName()).isEqualTo("Dale Olds");
        assertThat(map.getEmail()).isEqualTo("olds@vmware.com");
        assertThat(map.getPhoneNumber()).isEqualTo("8505551234");
        assertThat(map.getSub()).isEqualTo(user.getId());
        assertThat(map.getGivenName()).isEqualTo(user.getGivenName());
        assertThat(map.getFamilyName()).isEqualTo(user.getFamilyName());
        assertThat(map.getUserAttributes()).isNotNull();
        Map<String, List<String>> userAttributes = map.getUserAttributes();
        assertThat(userAttributes).containsEntry(MULTI_VALUE, info.getUserAttributes().get(MULTI_VALUE))
                .containsEntry(SINGLE_VALUE, info.getUserAttributes().get(SINGLE_VALUE))
                .doesNotContainKey(USER_ID);
        List<String> infoRoles = info.getRoles();
        assertThat(infoRoles).containsExactlyInAnyOrderElementsOf(roles);

        //remove permissions
        request = createOauthRequest(Collections.singletonList("openid"));
        map = endpoint.loginInfo(new OAuth2Authentication(request, authentication));
        assertThat(map.getUserAttributes()).isNull();
        assertThat(map.getRoles()).isNull();
    }

    @Test
    void missingUser() {
        UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication("nonexist-id", "Dale",
                "olds@vmware.com");
        assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(() -> endpoint.loginInfo(
                new OAuth2Authentication(createOauthRequest(
                        Collections.singletonList("openid")),
                        authentication)));
    }

    private static OAuth2Request createOauthRequest(final List<String> scopes) {
        return new OAuth2Request(Collections.emptyMap(),
                "clientId",
                scopes.stream().map(SimpleGrantedAuthority::new).toList(),
                true,
                new HashSet<>(scopes),
                Collections.emptySet(),
                null,
                Collections.emptySet(),
                null);
    }

}
