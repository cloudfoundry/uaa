package org.cloudfoundry.identity.uaa.invitations;

import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.junit.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;

import java.util.Collections;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


public class InvitationsAuthenticationTrustResolverTest {

    @Test
    public void testIsAnonymous() {
        InvitationsAuthenticationTrustResolver resolver = new InvitationsAuthenticationTrustResolver();
        AnonymousAuthenticationToken invitedAuthenticationToken = new AnonymousAuthenticationToken("key", new Object(),
                Collections.singletonList(UaaAuthority.UAA_INVITED));
        assertFalse(resolver.isAnonymous(invitedAuthenticationToken));

        AnonymousAuthenticationToken anonymousAuthenticationToken = new AnonymousAuthenticationToken("key", new Object(),
                Collections.singletonList(UaaAuthority.UAA_USER));
        assertTrue(resolver.isAnonymous(anonymousAuthenticationToken));
    }
}