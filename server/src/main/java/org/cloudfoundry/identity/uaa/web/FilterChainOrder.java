package org.cloudfoundry.identity.uaa.web;

/**
 * The order for all the filter chains in the UAA. The name references
 * Spring Security's {@code FilterOrderRegistration}.
 */
public class FilterChainOrder {

    // Order of filters in login-ui.xml
    public static final int AUTOLOGIN_AUTHORIZE = 1200;
    public static final int AUTOLOGIN_CODE = 1201;
    public static final int AUTOLOGIN = 1202;
    public static final int INVITATIONS = 1203;
    public static final int INVITE = 1204;
    public static final int RESET_PASSWORD = 1205;
    public static final int FORGOT_PASSWORD = 1206;
    public static final int DELETE_SAVED_ACCOUNT = 1207;
    public static final int VERIFY_EMAIL = 1208;
    public static final int VERIFY_USER = 1209;
    public static final int INVITATIONS_ACCEPT = 1210;
    public static final int SAML_IDP_SSO = 1211;
    public static final int SCIM_GROUP = 1212;
    public static final int UI_SECURITY = 1213;

}