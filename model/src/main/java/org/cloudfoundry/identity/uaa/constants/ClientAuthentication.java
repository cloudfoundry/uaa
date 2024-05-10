package org.cloudfoundry.identity.uaa.constants;

/**
 * ClientAuthentication constants are defined in OIDC core and discovery standard, e.g. https://openid.net/specs/openid-connect-registration-1_0.html
 * OIDC possible values are: client_secret_post, client_secret_basic, client_secret_jwt, private_key_jwt, and none
 * UAA knows only: client_secret_post, client_secret_basic, private_key_jwt, and none
 *
 * Planned: tls_client_auth
 */
public final class ClientAuthentication {

  private ClientAuthentication() {}

  public static final String CLIENT_SECRET_BASIC = "client_secret_basic";
  public static final String CLIENT_SECRET_POST = "client_secret_post";
  public static final String PRIVATE_KEY_JWT = "private_key_jwt";
  public static final String NONE = "none";
}
