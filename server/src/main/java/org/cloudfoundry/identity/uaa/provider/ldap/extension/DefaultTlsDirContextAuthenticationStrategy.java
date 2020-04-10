package org.cloudfoundry.identity.uaa.provider.ldap.extension;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

public class DefaultTlsDirContextAuthenticationStrategy
    extends org.springframework.ldap.core.support.DefaultTlsDirContextAuthenticationStrategy {

  @Override
  protected void applyAuthentication(LdapContext ctx, String userDn, String password)
      throws NamingException {
    super.applyAuthentication(ctx, userDn, password);
    ctx.reconnect(ctx.getConnectControls());
  }
}
