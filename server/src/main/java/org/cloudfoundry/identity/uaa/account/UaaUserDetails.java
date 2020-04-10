package org.cloudfoundry.identity.uaa.account;

import java.util.List;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.userdetails.User;

/**
 * User details adapting a {@link UaaUser} instance with a random password and all boolean flags set
 * to on.
 *
 * @author Dave Syer
 */
public class UaaUserDetails extends User {

  private static final List<UaaAuthority> DEFAULT_AUTHORITIES = UaaAuthority.USER_AUTHORITIES;

  private final UaaUser user;

  public UaaUserDetails(UaaUser user) {
    super(user.getUsername(), user.getPassword(), true, true, true, true, DEFAULT_AUTHORITIES);
    this.user = user;
  }

  public UaaUser getUser() {
    return user;
  }
}
