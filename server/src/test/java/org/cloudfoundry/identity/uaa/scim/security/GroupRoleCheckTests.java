package org.cloudfoundry.identity.uaa.scim.security;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.junit.After;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Created by pivotal on 12/7/15.
 */
public class GroupRoleCheckTests {

    @After
    public void cleanUp() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testCheckGroupMember() {
        SecurityContext context = getMockContext("member-id");
        SecurityContextHolder.setContext(context);

        ScimGroupMembershipManager manager = mock(ScimGroupMembershipManager.class);
        ScimGroupMember member = new ScimGroupMember("member-id", ScimGroupMember.Type.USER, Collections.singletonList(ScimGroupMember.Role.MEMBER));
        when(manager.getMembers("group-id", ScimGroupMember.Role.MEMBER)).thenReturn(Arrays.asList(member));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/Groups/group-id");
        request.setServletPath("/Groups/group-id");

        GroupRoleCheck checker = new GroupRoleCheck(manager);

        assertTrue(checker.isGroupMember(request, 1));
    }

    @Test
    public void testCheckGroupMemberWhenUaaDeployedInNonRootPath() {
        SecurityContext context = getMockContext("member-id");
        SecurityContextHolder.setContext(context);

        ScimGroupMembershipManager manager = mock(ScimGroupMembershipManager.class);
        ScimGroupMember member = new ScimGroupMember("member-id", ScimGroupMember.Type.USER, Collections.singletonList(ScimGroupMember.Role.MEMBER));
        when(manager.getMembers("group-id", ScimGroupMember.Role.MEMBER)).thenReturn(Arrays.asList(member));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/uaa/Groups/group-id");
        request.setContextPath("/uaa");
        request.setServletPath("/Groups/group-id");

        GroupRoleCheck checker = new GroupRoleCheck(manager);

        assertTrue(checker.isGroupMember(request, 1));
    }

    public static SecurityContext getMockContext(String userId) {
        return new SecurityContext() {
            @Override
            public Authentication getAuthentication() {
                return new Authentication() {
                    @Override
                    public Collection<? extends GrantedAuthority> getAuthorities() {
                        return null;
                    }

                    @Override
                    public Object getCredentials() {
                        return null;
                    }

                    @Override
                    public Object getDetails() {
                        return null;
                    }

                    @Override
                    public Object getPrincipal() {
                        return new UaaPrincipal(userId, "test-username", "test@email.com", OriginKeys.UAA, userId, "uaa");
                    }

                    @Override
                    public boolean isAuthenticated() {
                        return false;
                    }

                    @Override
                    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

                    }

                    @Override
                    public String getName() {
                        return null;
                    }
                };
            }

            @Override
            public void setAuthentication(Authentication authentication) {

            }
        };
    }
}
