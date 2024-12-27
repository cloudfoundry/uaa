package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.junit.Test;
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class DefaultUserAuthenticationConverterTests {
    private final DefaultUserAuthenticationConverter converter = new DefaultUserAuthenticationConverter();

    @Test
    public void shouldExtractAuthenticationWhenAuthoritiesIsCollection() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put(UserAuthenticationConverter.USERNAME, "test_user");
        ArrayList<String> lists = new ArrayList<>();
        lists.add("a1");
        lists.add("a2");
        map.put(UserAuthenticationConverter.AUTHORITIES, lists);

        assertNull(converter.extractAuthentication(Collections.emptyMap()));
        Authentication authentication = converter.extractAuthentication(map);

        assertEquals(2, authentication.getAuthorities().size());
    }

    @Test
    public void shouldExtractAuthenticationWhenAuthoritiesIsString() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put(UserAuthenticationConverter.USERNAME, "test_user");
        map.put(UserAuthenticationConverter.AUTHORITIES, "a1,a2");

        Authentication authentication = converter.extractAuthentication(map);

        assertEquals(2, authentication.getAuthorities().size());
    }

    @Test
    public void shouldExtractAuthenticationWhenUserDetailsProvided() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put(UserAuthenticationConverter.USERNAME, "test_user");

        UserDetailsService userDetailsService = Mockito.mock(UserDetailsService.class);
        Mockito.when(userDetailsService.loadUserByUsername("test_user")).thenReturn(
                new User("foo", "bar", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_SPAM")));
        converter.setUserDetailsService(userDetailsService);
        Authentication authentication = converter.extractAuthentication(map);

        assertEquals("ROLE_SPAM", authentication.getAuthorities().iterator().next().toString());
    }

    @Test
    public void shouldExtractWithDefaultUsernameClaimWhenNotSet() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put(UserAuthenticationConverter.USERNAME, "test_user");

        Authentication authentication = converter.extractAuthentication(map);

        assertEquals("test_user", authentication.getPrincipal());
    }

    @Test
    public void shouldConvertUserWithDefaultUsernameClaimWhenNotSet() throws Exception {
        Authentication authentication = new UsernamePasswordAuthenticationToken("test_user", "", AuthorityUtils.createAuthorityList("user"));
        converter.setDefaultAuthorities(new String[]{"user"});
        Map<String, ?> map = converter.convertUserAuthentication(authentication);

        assertEquals("test_user", map.get(UserAuthenticationConverter.USERNAME));
    }

    @Test
    public void shouldExtractWithCustomUsernameClaimWhenSet() throws Exception {
        String customUserClaim = "custom_user_name";
        DefaultUserAuthenticationConverter converter = new DefaultUserAuthenticationConverter();
        converter.setUserClaimName(customUserClaim);

        Map<String, Object> map = new HashMap<>();
        map.put(customUserClaim, "test_user");

        Authentication authentication = converter.extractAuthentication(map);

        assertEquals("test_user", authentication.getPrincipal());
    }

    @Test
    public void shouldConvertUserWithCustomUsernameClaimWhenSet() throws Exception {
        String customUserClaim = "custom_user_name";
        DefaultUserAuthenticationConverter converter = new DefaultUserAuthenticationConverter();
        converter.setUserClaimName(customUserClaim);

        Authentication authentication = new UsernamePasswordAuthenticationToken("test_user", "");

        Map<String, ?> map = converter.convertUserAuthentication(authentication);

        assertEquals("test_user", map.get(customUserClaim));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldAuthorities() {
        DefaultUserAuthenticationConverter converter = new DefaultUserAuthenticationConverter();
        converter.getAuthorities(Map.of("authorities", 1));
    }
}
