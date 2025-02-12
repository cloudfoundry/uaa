package org.cloudfoundry.identity.uaa.web;

/**
 * The order for all the filter chains in the UAA. The name references
 * Spring Security's {@code FilterOrderRegistration}.
 */
public class FilterChainOrder {

    // Order of filters in login-ui.xml
    public static final int AUTOLOGIN = 1200;
    public static final int INVITATIONS = 1201;
    public static final int INVITE = 1202;
    public static final int RESET_PASSWORD = 1203;
    public static final int FORGOT_PASSWORD = 1204;
    public static final int DELETE_SAVED_ACCOUNT = 1205;
    public static final int VERIFY_EMAIL = 1206;
    public static final int VERIFY_USER = 1207;
    public static final int INVITATIONS_ACCEPT = 1208;
    public static final int SAML_IDP_SSO = 1209;
    public static final int UI_SECURITY = 1210;

}