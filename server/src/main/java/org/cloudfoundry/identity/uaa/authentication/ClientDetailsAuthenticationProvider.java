package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class ClientDetailsAuthenticationProvider extends DaoAuthenticationProvider {

  public ClientDetailsAuthenticationProvider(
      UserDetailsService userDetailsService, PasswordEncoder encoder) {
    super();
    setUserDetailsService(userDetailsService);
    setPasswordEncoder(encoder);
  }

  @Override
  protected void additionalAuthenticationChecks(
      UserDetails userDetails, UsernamePasswordAuthenticationToken authentication)
      throws AuthenticationException {

    String[] passwordList;
    String password = userDetails.getPassword();
    if (password != null) {
      passwordList = password.split(" ");
    } else {
      passwordList = new String[] {password};
    }

    AuthenticationException error = null;
    for (String pwd : passwordList) {
      try {
        User user =
            new User(
                userDetails.getUsername(),
                pwd,
                userDetails.isEnabled(),
                userDetails.isAccountNonExpired(),
                userDetails.isCredentialsNonExpired(),
                userDetails.isAccountNonLocked(),
                userDetails.getAuthorities());
        super.additionalAuthenticationChecks(user, authentication);
        error = null;
        break;
      } catch (AuthenticationException e) {
        error = e;
      }
    }
    if (error != null) {
      throw error;
    }
  }
}
