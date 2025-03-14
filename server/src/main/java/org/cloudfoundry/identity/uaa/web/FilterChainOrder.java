package org.cloudfoundry.identity.uaa.web;

/**
 * The order for all the filter chains in the UAA. The name references
 * Spring Security's {@code FilterOrderRegistration}.
 * <p>
 * This class allows us to retain the implicit filter chain ordering that we had in
 * {@code spring-servlet.xml}. The specific order is computed like so:
 * {@code 100 * (position of file in spring-servlet) + (position of filter chain in file)}.
 */
public class FilterChainOrder {

    // login-server-security.xml: 100

    // oauth-endpoints.xml: 200

    // scim-endpoints.xml: 300
    public static final int SCIM_PASSWORD = 300;
    public static final int SCIM = 301;

    // multitenant-endpoints.xml: 400

    // approval-endpoints.xml: 500
    public static final int APPROVAL = 500;

    // client-admin-endpoints.xml: 600
    public static final int CLIENT_ADMIN = 600;

    // resource-endpoints.xml: 700
    public static final int RESOURCE = 700;

    // openid-endpoints.xml: 800
    public static final int USERINFO = 800;

    // codestore-endpoints.xml: 900
    public static final int CODESTORE = 900;

    // login-ui.xml: 1200
    public static final int AUTOLOGIN_CODE = 1200;
    public static final int AUTOLOGIN = 1201;
    public static final int INVITATIONS = 1202;
    public static final int INVITE = 1203;
    public static final int LOGIN_PUBLIC_OPERATIONS = 1204;
    public static final int UI_SECURITY = 1205;

}