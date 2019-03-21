package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.ACCESS_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class JdbcRevocableTokenProvisioningTest extends JdbcTestBase {

    private JdbcRevocableTokenProvisioning dao;
    private RevocableToken expected;
    private String tokenId;
    private String clientId;
    private String userId;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();

    @Rule
    public ExpectedException error = ExpectedException.none();

    @Before
    public void createData() {
        JdbcTemplate template = spy(jdbcTemplate);
        dao = spy(new JdbcRevocableTokenProvisioning(template, limitSqlAdapter, new TimeServiceImpl()));
        createData("test-token-id", "test-user-id", "test-client-id");
    }

    @After
    public void clear() {
        IdentityZoneHolder.clear();
        jdbcTemplate.update("DELETE FROM revocable_tokens");
    }

    @Test
    public void on_application_event_calls_internal_delete_method() {
        BaseClientDetails clientDetails = new BaseClientDetails("id", "", "", "", "", "");
        IdentityZone otherZone = MultitenancyFixture.identityZone("other", "other");
        for (IdentityZone zone : Arrays.asList(IdentityZone.getUaa(), otherZone)) {
            IdentityZoneHolder.set(zone);
            reset(dao);
            try {
                dao.onApplicationEvent(new EntityDeletedEvent<>(clientDetails, mock(UaaAuthentication.class)));
            } catch (Exception ignored) {
            }
            try {
                dao.onApplicationEvent((AbstractUaaEvent) new EntityDeletedEvent<>(clientDetails, mock(UaaAuthentication.class)));
            } catch (Exception ignored) {
            }
            verify(dao, times(2)).deleteByClient(eq("id"), eq(zone.getId()));
        }
    }

    @Test
    public void revocable_tokens_deleted_when_client_is() {
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, "", "", "", "", "");
        IdentityZone otherZone = MultitenancyFixture.identityZone("other", "other");
        for (IdentityZone zone : Arrays.asList(IdentityZone.getUaa(), otherZone)) {
            IdentityZoneHolder.set(zone);
            dao.create(this.expected, IdentityZoneHolder.get().getId());
            assertEquals(1, getCountOfTokens(jdbcTemplate));
            assertEquals(zone.getId(), dao.retrieve(tokenId, IdentityZoneHolder.get().getId()).getZoneId());
            dao.onApplicationEvent((AbstractUaaEvent) new EntityDeletedEvent<>(clientDetails, mock(UaaAuthentication.class)));
            assertEquals(0, getCountOfTokens(jdbcTemplate));
        }
    }

    @Test
    public void revocable_tokens_deleted_when_user_is() {
        IdentityZone otherZone = MultitenancyFixture.identityZone("other", "other");
        for (IdentityZone zone : Arrays.asList(IdentityZone.getUaa(), otherZone)) {
            IdentityZoneHolder.set(zone);
            UaaUser user = new UaaUser(
                    new UaaUserPrototype()
                            .withId(userId)
                            .withUsername("username")
                            .withEmail("test@test.com")
                            .withZoneId(zone.getId())
            );
            dao.create(this.expected, IdentityZoneHolder.get().getId());
            assertEquals(1, getCountOfTokens(jdbcTemplate));;
            assertEquals(zone.getId(), dao.retrieve(tokenId, IdentityZoneHolder.get().getId()).getZoneId());
            dao.onApplicationEvent((AbstractUaaEvent) new EntityDeletedEvent<>(user, mock(UaaAuthentication.class)));
            assertEquals(0, getCountOfTokens(jdbcTemplate));;
        }
    }

    @Test
    public void retrieve_all_returns_nothing() {
        assertNull(dao.retrieveAll(IdentityZoneHolder.get().getId()));
    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void testNotFound() {
        dao.retrieve(tokenId, IdentityZoneHolder.get().getId());
    }

    @Test
    public void testGetFound() {
        dao.create(this.expected, IdentityZoneHolder.get().getId());
        assertNotNull(dao.retrieve(tokenId, IdentityZoneHolder.get().getId()));
    }

    @Test
    public void testAdd_Duplicate_Fails() {
        dao.create(this.expected, IdentityZoneHolder.get().getId());
        error.expect(DuplicateKeyException.class);
        dao.create(this.expected, IdentityZoneHolder.get().getId());
    }

    @Test
    public void testGetFound_In_Zone() {
        IdentityZoneHolder.set(MultitenancyFixture.identityZone("new-zone", "new-zone"));
        dao.create(this.expected, IdentityZoneHolder.get().getId());
        assertNotNull(dao.retrieve(tokenId, IdentityZoneHolder.get().getId()));
        IdentityZoneHolder.clear();
        error.expect(EmptyResultDataAccessException.class);
        dao.retrieve(tokenId, IdentityZoneHolder.get().getId());
    }

    @Test
    public void create() {
        RevocableToken createdToken = dao.create(expected, IdentityZoneHolder.get().getId());
        assertTokensAreEqual(expected, createdToken);
    }

    @Test
    public void listUserTokens() {
        listTokens(false);
    }

    @Test(expected = NullPointerException.class)
    public void listUserTokens_Null_ClientId() {
        dao.getUserTokens("userid", null, IdentityZoneHolder.get().getId());
    }

    @Test(expected = NullPointerException.class)
    public void listUserTokens_Empty_ClientId() {
        dao.getUserTokens("userid", "", IdentityZoneHolder.get().getId());
    }

    @Test
    public void listUserTokenForClient() {
        String clientId = "test-client-id";
        String userId = "test-user-id";
        List<RevocableToken> expectedTokens = new ArrayList<>();
        int count = 37;
        RandomValueStringGenerator generator = new RandomValueStringGenerator(36);
        for (int i = 0; i < count; i++) {
            createData(generator.generate(), userId, clientId);
            dao.create(this.expected, IdentityZoneHolder.get().getId());
            expectedTokens.add(this.expected);
        }

        for (int i = 0; i < count; i++) {
            //create a random record that should not show up
            createData(generator.generate(), generator.generate(), generator.generate());
            dao.create(this.expected, IdentityZoneHolder.get().getId());
        }

        List<RevocableToken> actualTokens = dao.getUserTokens(userId, clientId, IdentityZoneHolder.get().getId());
        assertThat(actualTokens, containsInAnyOrder(expectedTokens.toArray()));
    }

    @Test
    public void listClientTokens() {
        listTokens(true);
    }

    @Test
    public void update() {
        char[] data = new char[200 * 1024];
        Arrays.fill(data, 'Y');
        dao.create(this.expected, IdentityZoneHolder.get().getId());
        RevocableToken toUpdate = dao.retrieve(tokenId, IdentityZoneHolder.get().getId());
        long expiresAt = System.currentTimeMillis() + 1000;
        String scope = "scope1,scope2,scope3";
        toUpdate.setFormat("format")
                .setExpiresAt(expiresAt)
                .setIssuedAt(expiresAt)
                .setClientId("new-client-id")
                .setScope(scope)
                .setValue(new String(data))
                .setUserId("new-user-id")
                .setZoneId("arbitrary-zone-id")
                .setResponseType(REFRESH_TOKEN);

        RevocableToken revocableToken = dao.update(tokenId, toUpdate, IdentityZoneHolder.get().getId());
        assertTokensAreEqual(toUpdate, revocableToken);
    }

    @Test
    public void testDelete() {
        dao.create(this.expected, IdentityZoneHolder.get().getId());
        dao.retrieve(tokenId, IdentityZoneHolder.get().getId());
        dao.delete(tokenId, 8, IdentityZoneHolder.get().getId());

        error.expect(EmptyResultDataAccessException.class);
        dao.retrieve(tokenId, IdentityZoneHolder.get().getId());

    }

    @Test
    public void testDeleteRefreshTokenForClientIdUserId() {
        expected.setResponseType(REFRESH_TOKEN);
        dao.create(this.expected, IdentityZoneHolder.get().getId());
        createData(new RandomValueStringGenerator().generate(), userId, clientId);
        expected.setResponseType(REFRESH_TOKEN);
        dao.create(this.expected, IdentityZoneHolder.get().getId());
        assertEquals(2, dao.deleteRefreshTokensForClientAndUserId(clientId, userId, IdentityZoneHolder.get().getId()));
        assertEquals(0, dao.deleteRefreshTokensForClientAndUserId(clientId, userId, IdentityZoneHolder.get().getId()));
        List<RevocableToken> userTokens = dao.getUserTokens(userId, clientId, IdentityZoneHolder.get().getId());
        assertEquals(0, userTokens.stream().filter(t -> t.getResponseType().equals(REFRESH_TOKEN)).count());
    }

    @Test
    public void ensure_expired_token_is_deleted() {
        dao.create(this.expected, IdentityZoneHolder.get().getId());
        jdbcTemplate.update("UPDATE revocable_tokens SET expires_at=? WHERE token_id=?", System.currentTimeMillis() - 10000, tokenId);
        try {
            dao.retrieve(tokenId, IdentityZoneHolder.get().getId());
            fail("Token should have been deleted prior to retrieval");
        } catch (EmptyResultDataAccessException ignored) {
        }
        assertEquals(0, getCountOfTokens(jdbcTemplate));;

    }

    @Test
    public void ensure_expired_token_is_deleted_on_create() {
        jdbcTemplate.update("DELETE FROM revocable_tokens");
        dao.create(this.expected, IdentityZoneHolder.get().getId());
        jdbcTemplate.update("UPDATE revocable_tokens SET expires_at=? WHERE token_id=?", System.currentTimeMillis() - 10000, tokenId);
        expected.setTokenId(generator.generate());
        dao.lastExpiredCheck.set(0); //simulate time has passed
        dao.create(expected, IdentityZoneHolder.get().getId());
        assertEquals(1, getCountOfTokens(jdbcTemplate));
        assertEquals(1, getCountOfTokensById(jdbcTemplate, expected.getTokenId()));
        assertEquals(0, getCountOfTokensById(jdbcTemplate, tokenId));
    }

    @Test
    public void test_periodic_deletion_of_expired_tokens() {
        dao.create(this.expected, IdentityZoneHolder.get().getId());
        expected.setTokenId(new RandomValueStringGenerator().generate());
        dao.create(this.expected, IdentityZoneHolder.get().getId());
        assertEquals(2, getCountOfTokens(jdbcTemplate));
        jdbcTemplate.update("UPDATE revocable_tokens SET expires_at=?", System.currentTimeMillis() - 10000);
        try {
            dao.lastExpiredCheck.set(0);
            dao.retrieve(tokenId, IdentityZoneHolder.get().getId());
            fail("Token should have been deleted prior to retrieval");
        } catch (EmptyResultDataAccessException ignored) {
        }
        assertEquals(0, getCountOfTokens(jdbcTemplate));
    }

    @Test
    public void testDeleteByIdentityZone() {
        IdentityZone zone = MultitenancyFixture.identityZone("test-zone", "test-zone");
        IdentityZoneHolder.set(zone);
        dao.create(this.expected, IdentityZoneHolder.get().getId());
        dao.retrieve(tokenId, IdentityZoneHolder.get().getId());
        EntityDeletedEvent<IdentityZone> zoneDeleted = new EntityDeletedEvent<>(zone, null);
        dao.onApplicationEvent(zoneDeleted);
        error.expect(EmptyResultDataAccessException.class);
        dao.retrieve(tokenId, IdentityZoneHolder.get().getId());
    }

    @Test
    public void testDeleteByOrigin() {
        //no op - doesn't affect tokens
    }

    private void createData(String tokenId, String userId, String clientId) {
        char[] value = new char[100 * 1024];
        Arrays.fill(value, 'X');
        this.tokenId = tokenId;
        this.clientId = clientId;
        this.userId = userId;
        long issuedAt = System.currentTimeMillis();
        String scope = "test1,test2";
        String format = "format";
        expected = new RevocableToken()
                .setTokenId(tokenId)
                .setClientId(clientId)
                .setResponseType(ACCESS_TOKEN)
                .setIssuedAt(issuedAt)
                .setExpiresAt(issuedAt + 10000)
                .setValue(new String(value))
                .setScope(scope)
                .setFormat(format)
                .setUserId(userId)
                .setZoneId(IdentityZoneHolder.get().getId());
    }

    private static void assertTokensAreEqual(RevocableToken expected, RevocableToken actual) {
        assertNotNull(actual);
        assertNotNull(actual.getTokenId());
        assertEquals(expected.getTokenId(), actual.getTokenId());
        assertEquals(expected.getClientId(), actual.getClientId());
        assertEquals(expected.getExpiresAt(), actual.getExpiresAt());
        assertEquals(expected.getIssuedAt(), actual.getIssuedAt());
        assertEquals(expected.getFormat(), actual.getFormat());
        assertEquals(expected.getScope(), actual.getScope());
        assertEquals(expected.getValue(), actual.getValue());
        assertEquals(expected.getTokenId(), actual.getTokenId());
        assertEquals(expected.getResponseType(), actual.getResponseType());
        // TODO: Compare expected.getZoneId() and actual.getZoneId()
        assertEquals(IdentityZoneHolder.get().getId(), actual.getZoneId());
    }

    private void listTokens(boolean client) {
        String clientId = "test-client-id";
        String userId = "test-user-id";
        List<RevocableToken> expectedTokens = new ArrayList<>();
        int count = 37;
        RandomValueStringGenerator generator = new RandomValueStringGenerator(36);
        for (int i = 0; i < count; i++) {
            if (client) {
                userId = generator.generate();
            } else {
                clientId = generator.generate();
            }
            createData(generator.generate(), userId, clientId);
            dao.create(this.expected, IdentityZoneHolder.get().getId());
            expectedTokens.add(this.expected);
        }

        //create a random record that should not show up
        createData(generator.generate(), generator.generate(), generator.generate());
        dao.create(this.expected, IdentityZoneHolder.get().getId());

        List<RevocableToken> actualTokens = client ? dao.getClientTokens(clientId, IdentityZoneHolder.get().getId()) : dao.getUserTokens(userId, IdentityZoneHolder.get().getId());
        assertThat(actualTokens, containsInAnyOrder(expectedTokens.toArray()));
    }

    private static int getCountOfTokens(JdbcTemplate jdbcTemplate) {
        return jdbcTemplate.queryForObject("select count(1) from revocable_tokens", Integer.class);
    }

    private static int getCountOfTokensById(JdbcTemplate jdbcTemplate, String tokenId) {
        return jdbcTemplate.queryForObject("select count(1) from revocable_tokens where token_id=?", Integer.class, tokenId);
    }

}