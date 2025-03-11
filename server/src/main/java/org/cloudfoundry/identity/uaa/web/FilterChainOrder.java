package org.cloudfoundry.identity.uaa.web;

/**
 * The order for all the filter chains in the UAA. The name references
 * Spring Security's {@code FilterOrderRegistration}.
 */
public class FilterChainOrder {

    // Order of filters handling user login features, formerly defined by
    // ordering filter chains in login-ui.xml
    public static final int AUTOLOGIN_CODE = 1200;
    public static final int AUTOLOGIN = 1201;
    public static final int INVITATIONS = 1202;
    public static final int INVITE = 1203;
    public static final int LOGIN_PUBLIC_OPERATIONS = 1204;
    public static final int UI_SECURITY = 1205;

}