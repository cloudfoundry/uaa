package org.cloudfoundry.identity.uaa.openid2;

import java.util.List;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.openid.OpenIDAttribute;
import org.springframework.security.openid.OpenIDAuthenticationToken;

/**
 * Custom UserDetailsService which accepts any OpenID user, "registering" new users in a map so they can be welcomed
 * back to the site on subsequent logins.
 *
 * @author Luke Taylor
 * @author Dave Syer
 * 
 * @since 3.1
 */
public class OpenIdUserDetailsService implements AuthenticationUserDetailsService<OpenIDAuthenticationToken> {

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    
   /**
     * Implementation of {@code AuthenticationUserDetailsService} which allows full access to the submitted
     * {@code Authentication} object. Used by the OpenIDAuthenticationProvider.
     */
    public UserDetails loadUserDetails(OpenIDAuthenticationToken token) {
        // String id = token.getIdentityUrl();

        String email = null;
        String firstName = null;
        String lastName = null;
        String fullName = null;

        List<OpenIDAttribute> attributes = token.getAttributes();

        for (OpenIDAttribute attribute : attributes) {
            if (attribute.getName().equals("email")) {
                email = attribute.getValues().get(0);
            }

            if (attribute.getName().equals("firstname")) {
                firstName = attribute.getValues().get(0);
            }

            if (attribute.getName().equals("lastname")) {
                lastName = attribute.getValues().get(0);
            }

            if (attribute.getName().equals("fullname")) {
                fullName = attribute.getValues().get(0);
            }
        }

        if (fullName == null) {
            StringBuilder fullNameBldr = new StringBuilder();

            if (firstName != null) {
                fullNameBldr.append(firstName);
            }

            if (lastName != null) {
                fullNameBldr.append(" ").append(lastName);
            }
            fullName = fullNameBldr.toString();
        }

		UaaUser user = new UaaUser(email, generator.generate(), email, firstName, lastName);
        return new UaaUserDetails(user);
    }
}
