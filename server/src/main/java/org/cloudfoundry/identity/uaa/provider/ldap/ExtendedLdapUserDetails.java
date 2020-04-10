
package org.cloudfoundry.identity.uaa.provider.ldap;

import org.cloudfoundry.identity.uaa.user.DialableByPhone;
import org.cloudfoundry.identity.uaa.user.ExternallyIdentifiable;
import org.cloudfoundry.identity.uaa.user.Mailable;
import org.cloudfoundry.identity.uaa.user.Named;
import org.cloudfoundry.identity.uaa.user.VerifiableUser;

import org.springframework.security.ldap.userdetails.LdapUserDetails;

import java.util.Map;

public interface ExtendedLdapUserDetails extends LdapUserDetails, VerifiableUser, Mailable, Named, DialableByPhone, ExternallyIdentifiable {

    String[] getMail();

    Map<String,String[]> getAttributes();

    String[] getAttribute(String name, boolean caseSensitive);

}
