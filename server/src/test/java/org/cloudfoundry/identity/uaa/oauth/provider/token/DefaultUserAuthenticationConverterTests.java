package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class DefaultUserAuthenticationConverterTests {
    private final DefaultUserAuthenticationConverter converter = new DefaultUserAuthenticationConverter();

    @Test
    void shouldExtractAuthenticationWhenAuthoritiesIsCollection() {
        Map<String, Object> map = new HashMap<>();
        map.put(UserAuthenticationConverter.USERNAME, "test_user");
        ArrayList<String> lists = new ArrayList<>();
        lists.add("a1");
        lists.add("a2");
        map.put(UserAuthenticationConverter.AUTHORITIES, lists);

        assertThat(converter.extractAuthentication(Collections.emptyMap())).isNull();
        Authentication authentication = converter.extractAuthentication(map);

        assertThat(authentication.getAuthorities()).hasSize(2);
    }

    @Test
    void shouldExtractAuthenticationWhenAuthoritiesIsString() {
        Map<String, Object> map = new HashMap<>();
        map.put(UserAuthenticationConverter.USERNAME, "test_user");
        map.put(UserAuthenticationConverter.AUTHORITIES, "a1,a2");

        Authentication authentication = converter.extractAuthentication(map);

        assertThat(authentication.getAuthorities()).hasSize(2);
    }

    @Test
    void shouldExtractAuthenticationWhenUserDetailsProvided() {
        Map<String, Object> map = new HashMap<>();
        map.put(UserAuthenticationConverter.USERNAME, "test_user");

        UserDetailsService userDetailsService = Mockito.mock(UserDetailsService.class);
        Mockito.when(userDetailsService.loadUserByUsername("test_user")).thenReturn(
                new User("foo", "bar", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_SPAM")));
        converter.setUserDetailsService(userDetailsService);
        Authentication authentication = converter.extractAuthentication(map);

        assertThat(authentication.getAuthorities().iterator().next()).hasToString("ROLE_SPAM");
    }

    @Test
    void shouldExtractWithDefaultUsernameClaimWhenNotSet() {
        Map<String, Object> map = new HashMap<>();
        map.put(UserAuthenticationConverter.USERNAME, "test_user");

        Authentication authentication = converter.extractAuthentication(map);

        assertThat(authentication.getPrincipal()).isEqualTo("test_user");
    }

    @Test
    void shouldConvertUserWithDefaultUsernameClaimWhenNotSet() {
        Authentication authentication = new UsernamePasswordAuthenticationToken("test_user", "", AuthorityUtils.createAuthorityList("user"));
        converter.setDefaultAuthorities(new String[]{"user"});
        Map<String, Object> map = converter.convertUserAuthentication(authentication);

        assertThat(map).containsEntry(UserAuthenticationConverter.USERNAME, "test_user");
    }

    @Test
    void shouldExtractWithCustomUsernameClaimWhenSet() {
        String customUserClaim = "custom_user_name";
        DefaultUserAuthenticationConverter converter = new DefaultUserAuthenticationConverter();
        converter.setUserClaimName(customUserClaim);

        Map<String, Object> map = new HashMap<>();
        map.put(customUserClaim, "test_user");

        Authentication authentication = converter.extractAuthentication(map);

        assertThat(authentication.getPrincipal()).isEqualTo("test_user");
    }

    @Test
    void shouldConvertUserWithCustomUsernameClaimWhenSet() {
        String customUserClaim = "custom_user_name";
        DefaultUserAuthenticationConverter converter = new DefaultUserAuthenticationConverter();
        converter.setUserClaimName(customUserClaim);

        Authentication authentication = new UsernamePasswordAuthenticationToken("test_user", "");

        Map<String, Object> map = converter.convertUserAuthentication(authentication);

        assertThat(map).containsEntry(customUserClaim, "test_user");
    }

    @Test
    void shouldAuthorities() {
        DefaultUserAuthenticationConverter converter = new DefaultUserAuthenticationConverter();
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                converter.getAuthorities(Map.of("authorities", 1)));
    }
}
