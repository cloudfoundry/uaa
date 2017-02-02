/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenStore;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import javax.sql.DataSource;
import java.io.PrintWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class UaaTokenStoreTests extends JdbcTestBase {

    private UaaTokenStore store;
    private JdbcAuthorizationCodeServices legacyCodeServices;
    private OAuth2Authentication clientAuthentication;
    private OAuth2Authentication usernamePasswordAuthentication;
    private OAuth2Authentication uaaAuthentication;
    public static final String LONG_CLIENT_ID = "a-client-id-that-is-longer-than-thirty-six-characters-but-less-than-two-hundred-fifty-five-characters-wow-two-hundred-fifty-five-characters-is-actually-a-very-long-client-id-and-we-hope-that-size-limit-should-be-sufficient-for-any-reasonable-application";

    private UaaPrincipal principal = new UaaPrincipal("userid","username","username@test.org", OriginKeys.UAA, null, IdentityZone.getUaa().getId());

    @Before
    public void createTokenStore() throws Exception {
        jdbcTemplate.update("delete from oauth_code");

        List<GrantedAuthority> userAuthorities = Arrays.<GrantedAuthority>asList(new SimpleGrantedAuthority("openid"));

        store = new UaaTokenStore(dataSource);
        legacyCodeServices = new JdbcAuthorizationCodeServices(dataSource);
        BaseClientDetails client = new BaseClientDetails("clientid", null, "openid","client_credentials,password", "oauth.login", null);
        Map<String,String> parameters = new HashMap<>();
        parameters.put(OAuth2Utils.CLIENT_ID, client.getClientId());

        TokenRequest clientRequest = new TokenRequest(new HashMap<>(parameters), client.getClientId(), UaaStringUtils.getStringsFromAuthorities(client.getAuthorities()), "client_credentials");
        clientAuthentication = new OAuth2Authentication(clientRequest.createOAuth2Request(client), null);

        parameters.put("scope","openid");
        parameters.put("grant_type","password");
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(principal,null,userAuthorities);

        clientRequest = new TokenRequest(new HashMap<>(parameters), client.getClientId(), client.getScope(), "password");
        usernamePasswordAuthentication = new OAuth2Authentication(clientRequest.createOAuth2Request(client), usernamePasswordAuthenticationToken);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");

        UaaAuthentication authentication = new UaaAuthentication(principal, userAuthorities, new UaaAuthenticationDetails(request));
        uaaAuthentication = new OAuth2Authentication(clientRequest.createOAuth2Request(client), authentication);

    }

    @Test
    public void test_deserialization_of_uaa_authentication() throws Exception {
        UaaAuthentication modifiedAuthentication = (UaaAuthentication) uaaAuthentication.getUserAuthentication();
        MultiValueMap<String,String> userAttributes = new LinkedMultiValueMap<>();
        userAttributes.put("atest", Arrays.asList("test1","test2","test3"));
        userAttributes.put("btest", Arrays.asList("test1","test2","test3"));
        modifiedAuthentication.setUserAttributes(userAttributes);

        Set<String> externalGroups = new HashSet<>(Arrays.asList("group1","group2","group3"));
        modifiedAuthentication.setExternalGroups(externalGroups);

        String code = store.createAuthorizationCode(uaaAuthentication);
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code WHERE code = ?", new Object[] {code}, Integer.class), is(1));
        OAuth2Authentication authentication = store.consumeAuthorizationCode(code);
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code WHERE code = ?", new Object[] {code}, Integer.class), is(0));
        assertNotNull(authentication);

        UaaAuthentication userAuthentication = (UaaAuthentication) authentication.getUserAuthentication();
        assertNotNull(userAuthentication.getUserAttributes());
        assertEquals(2, userAuthentication.getUserAttributes().size());
        assertThat(userAuthentication.getUserAttributes().get("atest"), containsInAnyOrder("test1", "test2", "test3"));
        assertThat(userAuthentication.getUserAttributes().get("btest"), containsInAnyOrder("test1", "test2", "test3"));

        assertNotNull(userAuthentication.getExternalGroups());
        assertEquals(3, userAuthentication.getExternalGroups().size());
        assertThat(userAuthentication.getExternalGroups(), containsInAnyOrder("group1","group2","group3"));
    }

    @Test
    public void test_ConsumeClientCredentials_From_OldStore() throws  Exception {
        String code = legacyCodeServices.createAuthorizationCode(clientAuthentication);
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code WHERE code = ?", new Object[] {code}, Integer.class), is(1));
        OAuth2Authentication authentication = store.consumeAuthorizationCode(code);
        assertNotNull(authentication);
        assertTrue(authentication.isClientOnly());
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code WHERE code = ?", new Object[] {code}, Integer.class), is(0));
    }

    @Test
    public void testStoreToken_ClientCredentials() throws Exception {
        String code = store.createAuthorizationCode(clientAuthentication);
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code WHERE code = ?", new Object[] {code}, Integer.class), is(1));
        assertNotNull(code);
    }

    @Test
    public void testStoreToken_PasswordGrant_UsernamePasswordAuthentication() throws Exception {
        String code = store.createAuthorizationCode(usernamePasswordAuthentication);
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code WHERE code = ?", new Object[] {code}, Integer.class), is(1));
        assertNotNull(code);
    }

    @Test
    public void testStoreToken_PasswordGrant_UaaAuthentication() throws Exception {
        String code = store.createAuthorizationCode(uaaAuthentication);
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code WHERE code = ?", new Object[] {code}, Integer.class), is(1));
        assertNotNull(code);
    }

    @Test
    public void deserialize_from_old_format() throws Exception {
        OAuth2Authentication authentication = store.deserializeOauth2Authentication(UAA_AUTHENTICATION_DATA_OLD_STYLE);
        assertNotNull(authentication);
        assertEquals(principal, authentication.getUserAuthentication().getPrincipal());
    }

    @Test
    public void testRetrieveToken() throws Exception {
        String code = store.createAuthorizationCode(clientAuthentication);
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code WHERE code = ?", new Object[] {code}, Integer.class), is(1));
        OAuth2Authentication authentication = store.consumeAuthorizationCode(code);
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code WHERE code = ?", new Object[] {code}, Integer.class), is(0));
        assertNotNull(authentication);

        code = store.createAuthorizationCode(usernamePasswordAuthentication);
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code WHERE code = ?", new Object[] {code}, Integer.class), is(1));
        authentication = store.consumeAuthorizationCode(code);
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code WHERE code = ?", new Object[] {code}, Integer.class), is(0));
        assertNotNull(authentication);

        code = store.createAuthorizationCode(uaaAuthentication);
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code WHERE code = ?", new Object[] {code}, Integer.class), is(1));
        authentication = store.consumeAuthorizationCode(code);
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code WHERE code = ?", new Object[] {code}, Integer.class), is(0));
        assertNotNull(authentication);
    }

    @Test(expected = InvalidGrantException.class)
    public void testRetrieve_Expired_Token() throws Exception {
        String code = store.createAuthorizationCode(clientAuthentication);
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code WHERE code = ?", new Object[] {code}, Integer.class), is(1));
        jdbcTemplate.update("update oauth_code set expiresat = 1");
        store.consumeAuthorizationCode(code);
    }

    @Test(expected = InvalidGrantException.class)
    public void testRetrieve_Non_Existent_Token() throws Exception {
        String code = store.createAuthorizationCode(clientAuthentication);
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code WHERE code = ?", new Object[] {code}, Integer.class), is(1));
        store.consumeAuthorizationCode("non-existent");
    }

    @Test
    public void testCleanUpExpiredTokensBasedOnExpiresField() throws Exception {
        int count = 10;
        String lastCode = null;
        for (int i=0; i<count; i++) {
            lastCode = store.createAuthorizationCode(clientAuthentication);
        }
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code", Integer.class), is(count));

        jdbcTemplate.update("UPDATE oauth_code SET expiresat = ?", System.currentTimeMillis() - 60000);

        try {
            store.consumeAuthorizationCode(lastCode);
            fail();
        } catch (InvalidGrantException e) {
        }
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code", Integer.class), is(0));

    }

    @Test
    public void testCleanUpLegacyCodes_Codes_Without_ExpiresAt_After_3_Days() throws Exception {
        int count = 10;
        long oneday = 1000 * 60 * 60 * 24;
        for (int i=0; i<count; i++) {
            legacyCodeServices.createAuthorizationCode(clientAuthentication);
        }
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code", Integer.class), is(count));
        jdbcTemplate.update("UPDATE oauth_code SET created = ?", new Timestamp(System.currentTimeMillis() - (2 * oneday)));
        try {
            store.consumeAuthorizationCode("non-existent");
            fail();
        } catch (InvalidGrantException e) {}
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code", Integer.class), is(count));
        jdbcTemplate.update("UPDATE oauth_code SET created = ?", new Timestamp(System.currentTimeMillis() - (4 * oneday)));
        try {
            store.consumeAuthorizationCode("non-existent");
            fail();
        } catch (InvalidGrantException e) {}
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM oauth_code", Integer.class), is(0));
    }

    @Test
    public void testExpiresAtOnCode() {
        UaaTokenStore.TokenCode code = store.createTokenCode("code", "userid", "clientid", System.currentTimeMillis() - 1000, new Timestamp(System.currentTimeMillis()), new byte[0]);
        assertTrue(code.isExpired());
    }

    @Test
    public void testExpiresAtOnCreated() {
        UaaTokenStore.TokenCode code = store.createTokenCode("code","userid","clientid",0, new Timestamp(System.currentTimeMillis()), new byte[0]);
        assertFalse(code.isExpired());

        code = store.createTokenCode("code","userid","clientid",0, new Timestamp(System.currentTimeMillis()-(2*store.getExpirationTime())), new byte[0]);
        assertTrue(code.isExpired());
    }

    @Test
    public void testCleanUpUnusedOldTokens_MySQL_In_Another_Timezone() throws Exception {
        //only run tests for MySQL for now.
        Optional<String> dbProfile = Arrays.stream(environment.getActiveProfiles()).filter(s -> s.contains("sql")).findFirst();
        String db = dbProfile.isPresent() ? dbProfile.get() : "hsqldb";

        Connection con = dataSource.getConnection();
        try {
            Connection dontClose = (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                                                                       new Class[]{Connection.class},
                                                                       new DontCloseConnection(con));

            SameConnectionDataSource sameConnectionDataSource = new SameConnectionDataSource(dontClose);
            JdbcTemplate template = new JdbcTemplate(sameConnectionDataSource);
            switch (db) {
                case "mysql" :
                    template.update("SET @@session.time_zone='-11:00'");
                    break;
                case "postgresql" :
                    template.update("SET TIME ZONE -11");
                    break;
                case "hsqldb" :
                    template.update("SET TIME ZONE INTERVAL '-11:00' HOUR TO MINUTE");
                    break;
                case "sqlserver" :
                    //TODO find a way to set offset for a connection
                    break;
                default:
                    fail("Unknown DB profile:"+db);
            }

            store = new UaaTokenStore(sameConnectionDataSource);
            legacyCodeServices = new JdbcAuthorizationCodeServices(sameConnectionDataSource);
            int count = 10;
            String lastCode = null;
            for (int i=0; i<count; i++) {
                lastCode = legacyCodeServices.createAuthorizationCode(clientAuthentication);
            }

            assertThat(template.queryForObject("SELECT count(*) FROM oauth_code", Integer.class), is(count));
            try { store.consumeAuthorizationCode(lastCode); } catch (Exception ignore) {}
            assertThat(template.queryForObject("SELECT count(*) FROM oauth_code", Integer.class), is(count-1));
        } finally {
            con.close();
            store = new UaaTokenStore(dataSource);
            legacyCodeServices = new JdbcAuthorizationCodeServices(dataSource);
        }
    }



    public class SameConnectionDataSource implements DataSource {
        private final Connection con;

        public SameConnectionDataSource(Connection con) {
            this.con = con;
        }

        @Override
        public Connection getConnection() throws SQLException {
            return con;
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            return con;
        }

        @Override
        public PrintWriter getLogWriter() throws SQLException {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) throws SQLException {

        }

        @Override
        public void setLoginTimeout(int seconds) throws SQLException {

        }

        @Override
        public int getLoginTimeout() throws SQLException {
            return 0;
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            return null;
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            return null;
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) throws SQLException {
            return false;
        }
    }

    public class DontCloseConnection implements InvocationHandler {
        public static final String CLOSE_VAL = "close";
        private final Connection con;

        public DontCloseConnection(Connection con) {
            this.con = con;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (CLOSE_VAL.equals(method.getName())) {
                return null;
            } else {
                return method.invoke(con, args);
            }
        }
    }

    private static final byte[] UAA_AUTHENTICATION_DATA_OLD_STYLE = new byte[] {123, 34, 111, 97, 117, 116, 104, 50, 82, 101, 113, 117, 101, 115, 116, 46, 114, 101, 115, 112, 111, 110, 115, 101, 84, 121, 112, 101, 115, 34, 58, 91, 93, 44, 34, 111, 97, 117, 116, 104, 50, 82, 101, 113, 117, 101, 115, 116, 46, 114, 101, 115, 111, 117, 114, 99, 101, 73, 100, 115, 34, 58, 91, 93, 44, 34, 117, 115, 101, 114, 65, 117, 116, 104, 101, 110, 116, 105, 99, 97, 116, 105, 111, 110, 46, 117, 97, 97, 80, 114, 105, 110, 99, 105, 112, 97, 108, 34, 58, 34, 123, 92, 34, 105, 100, 92, 34, 58, 92, 34, 117, 115, 101, 114, 105, 100, 92, 34, 44, 92, 34, 110, 97, 109, 101, 92, 34, 58, 92, 34, 117, 115, 101, 114, 110, 97, 109, 101, 92, 34, 44, 92, 34, 101, 109, 97, 105, 108, 92, 34, 58, 92, 34, 117, 115, 101, 114, 110, 97, 109, 101, 64, 116, 101, 115, 116, 46, 111, 114, 103, 92, 34, 44, 92, 34, 111, 114, 105, 103, 105, 110, 92, 34, 58, 92, 34, 117, 97, 97, 92, 34, 44, 92, 34, 101, 120, 116, 101, 114, 110, 97, 108, 73, 100, 92, 34, 58, 110, 117, 108, 108, 44, 92, 34, 122, 111, 110, 101, 73, 100, 92, 34, 58, 92, 34, 117, 97, 97, 92, 34, 125, 34, 44, 34, 111, 97, 117, 116, 104, 50, 82, 101, 113, 117, 101, 115, 116, 46, 114, 101, 113, 117, 101, 115, 116, 80, 97, 114, 97, 109, 101, 116, 101, 114, 115, 34, 58, 123, 34, 103, 114, 97, 110, 116, 95, 116, 121, 112, 101, 34, 58, 34, 112, 97, 115, 115, 119, 111, 114, 100, 34, 44, 34, 99, 108, 105, 101, 110, 116, 95, 105, 100, 34, 58, 34, 99, 108, 105, 101, 110, 116, 105, 100, 34, 44, 34, 115, 99, 111, 112, 101, 34, 58, 34, 111, 112, 101, 110, 105, 100, 34, 125, 44, 34, 111, 97, 117, 116, 104, 50, 82, 101, 113, 117, 101, 115, 116, 46, 114, 101, 100, 105, 114, 101, 99, 116, 85, 114, 105, 34, 58, 110, 117, 108, 108, 44, 34, 117, 115, 101, 114, 65, 117, 116, 104, 101, 110, 116, 105, 99, 97, 116, 105, 111, 110, 46, 97, 117, 116, 104, 111, 114, 105, 116, 105, 101, 115, 34, 58, 91, 34, 111, 112, 101, 110, 105, 100, 34, 93, 44, 34, 111, 97, 117, 116, 104, 50, 82, 101, 113, 117, 101, 115, 116, 46, 97, 117, 116, 104, 111, 114, 105, 116, 105, 101, 115, 34, 58, 91, 34, 111, 97, 117, 116, 104, 46, 108, 111, 103, 105, 110, 34, 93, 44, 34, 111, 97, 117, 116, 104, 50, 82, 101, 113, 117, 101, 115, 116, 46, 99, 108, 105, 101, 110, 116, 73, 100, 34, 58, 34, 99, 108, 105, 101, 110, 116, 105, 100, 34, 44, 34, 111, 97, 117, 116, 104, 50, 82, 101, 113, 117, 101, 115, 116, 46, 97, 112, 112, 114, 111, 118, 101, 100, 34, 58, 116, 114, 117, 101, 44, 34, 111, 97, 117, 116, 104, 50, 82, 101, 113, 117, 101, 115, 116, 46, 115, 99, 111, 112, 101, 34, 58, 91, 34, 111, 112, 101, 110, 105, 100, 34, 93, 125};
}
