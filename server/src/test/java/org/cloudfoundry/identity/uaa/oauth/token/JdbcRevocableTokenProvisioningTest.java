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

    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_CLIENT_ID = "test-client-id";

    private JdbcRevocableTokenProvisioning jdbcRevocableTokenProvisioning;
    private RevocableToken revocableToken;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();

    @Rule
    public ExpectedException error = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
        super.setUp();
        
        JdbcTemplate template = spy(jdbcTemplate);
        jdbcRevocableTokenProvisioning = spy(new JdbcRevocableTokenProvisioning(template, limitSqlAdapter, new TimeServiceImpl()));
        createData("test-token-id", TEST_USER_ID, TEST_CLIENT_ID);
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();

        IdentityZoneHolder.clear();
        jdbcTemplate.update("DELETE FROM revocable_tokens");
    }

    @Test
    public void onApplicationEventCallsInternalDeleteMethod() {
        BaseClientDetails clientDetails = new BaseClientDetails("id", "", "", "", "", "");
        IdentityZone otherZone = MultitenancyFixture.identityZone("other", "other");
        for (IdentityZone zone : Arrays.asList(IdentityZone.getUaa(), otherZone)) {
            IdentityZoneHolder.set(zone);
            reset(jdbcRevocableTokenProvisioning);
            try {
                jdbcRevocableTokenProvisioning.onApplicationEvent(new EntityDeletedEvent<>(clientDetails, mock(UaaAuthentication.class)));
            } catch (Exception ignored) {
            }
            try {
                jdbcRevocableTokenProvisioning.onApplicationEvent((AbstractUaaEvent) new EntityDeletedEvent<>(clientDetails, mock(UaaAuthentication.class)));
            } catch (Exception ignored) {
            }
            verify(jdbcRevocableTokenProvisioning, times(2)).deleteByClient(eq("id"), eq(zone.getId()));
        }
    }

    @Test
    public void revocableTokensDeletedWhenClientIs() {
        BaseClientDetails clientDetails = new BaseClientDetails(TEST_CLIENT_ID, "", "", "", "", "");
        IdentityZone otherZone = MultitenancyFixture.identityZone("other", "other");
        for (IdentityZone zone : Arrays.asList(IdentityZone.getUaa(), otherZone)) {
            IdentityZoneHolder.set(zone);
            jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
            assertEquals(1, getCountOfTokens(jdbcTemplate));
            assertEquals(zone.getId(), jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()).getZoneId());
            jdbcRevocableTokenProvisioning.onApplicationEvent((AbstractUaaEvent) new EntityDeletedEvent<>(clientDetails, mock(UaaAuthentication.class)));
            assertEquals(0, getCountOfTokens(jdbcTemplate));
        }
    }

    @Test
    public void revocableTokensDeletedWhenUserIs() {
        IdentityZone otherZone = MultitenancyFixture.identityZone("other", "other");
        for (IdentityZone zone : Arrays.asList(IdentityZone.getUaa(), otherZone)) {
            IdentityZoneHolder.set(zone);
            UaaUser user = new UaaUser(
                    new UaaUserPrototype()
                            .withId(TEST_USER_ID)
                            .withUsername("username")
                            .withEmail("test@test.com")
                            .withZoneId(zone.getId())
            );
            jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
            assertEquals(1, getCountOfTokens(jdbcTemplate));;
            assertEquals(zone.getId(), jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()).getZoneId());
            jdbcRevocableTokenProvisioning.onApplicationEvent((AbstractUaaEvent) new EntityDeletedEvent<>(user, mock(UaaAuthentication.class)));
            assertEquals(0, getCountOfTokens(jdbcTemplate));;
        }
    }

    @Test
    public void retrieveAllReturnsNothing() {
        assertNull(jdbcRevocableTokenProvisioning.retrieveAll(IdentityZoneHolder.get().getId()));
    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void tokenNotFound() {
        jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId());
    }

    @Test
    public void getFound() {
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertNotNull(jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()));
    }

    @Test
    public void addDuplicateFails() {
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        error.expect(DuplicateKeyException.class);
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
    }

    @Test
    public void getFoundInZone() {
        IdentityZoneHolder.set(MultitenancyFixture.identityZone("new-zone", "new-zone"));
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertNotNull(jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()));
        IdentityZoneHolder.clear();
        error.expect(EmptyResultDataAccessException.class);
        jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId());
    }

    @Test
    public void create() {
        RevocableToken createdToken = jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertTokensAreEqual(revocableToken, createdToken);
    }

    @Test
    public void listUserTokens() {
        listTokens(false);
    }

    @Test(expected = NullPointerException.class)
    public void getUserTokens_WithNullClientId() {
        jdbcRevocableTokenProvisioning.getUserTokens("userid", null, IdentityZoneHolder.get().getId());
    }

    @Test(expected = NullPointerException.class)
    public void getUserTokens_WithEmptyClientId() {
        jdbcRevocableTokenProvisioning.getUserTokens("userid", "", IdentityZoneHolder.get().getId());
    }

    @Test
    public void listUserTokenForClient() {
        String clientId = TEST_CLIENT_ID;
        String userId = TEST_USER_ID;
        List<RevocableToken> expectedTokens = new ArrayList<>();
        int count = 37;
        RandomValueStringGenerator generator = new RandomValueStringGenerator(36);
        for (int i = 0; i < count; i++) {
            createData(generator.generate(), userId, clientId);
            jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
            expectedTokens.add(revocableToken);
        }

        for (int i = 0; i < count; i++) {
            //create a random record that should not show up
            createData(generator.generate(), generator.generate(), generator.generate());
            jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        }

        List<RevocableToken> actualTokens = jdbcRevocableTokenProvisioning.getUserTokens(userId, clientId, IdentityZoneHolder.get().getId());
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
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        RevocableToken toUpdate = jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId());
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

        RevocableToken revocableToken = jdbcRevocableTokenProvisioning.update(toUpdate.getTokenId(), toUpdate, IdentityZoneHolder.get().getId());
        assertTokensAreEqual(toUpdate, revocableToken);
    }

    @Test
    public void delete() {
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId());
        jdbcRevocableTokenProvisioning.delete(revocableToken.getTokenId(), 8, IdentityZoneHolder.get().getId());

        error.expect(EmptyResultDataAccessException.class);
        jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId());
    }

    @Test
    public void deleteRefreshTokenForClientIdUserId() {
        revocableToken.setResponseType(REFRESH_TOKEN);
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        createData(new RandomValueStringGenerator().generate(), TEST_USER_ID, TEST_CLIENT_ID);
        revocableToken.setResponseType(REFRESH_TOKEN);
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertEquals(2, jdbcRevocableTokenProvisioning.deleteRefreshTokensForClientAndUserId(TEST_CLIENT_ID, TEST_USER_ID, IdentityZoneHolder.get().getId()));
        assertEquals(0, jdbcRevocableTokenProvisioning.deleteRefreshTokensForClientAndUserId(TEST_CLIENT_ID, TEST_USER_ID, IdentityZoneHolder.get().getId()));
        List<RevocableToken> userTokens = jdbcRevocableTokenProvisioning.getUserTokens(TEST_USER_ID, TEST_CLIENT_ID, IdentityZoneHolder.get().getId());
        assertEquals(0, userTokens.stream().filter(t -> t.getResponseType().equals(REFRESH_TOKEN)).count());
    }

    @Test
    public void ensureExpiredTokenIsDeleted() {
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        jdbcTemplate.update("UPDATE revocable_tokens SET expires_at=? WHERE token_id=?", System.currentTimeMillis() - 10000, revocableToken.getTokenId());
        try {
            jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId());
            fail("Token should have been deleted prior to retrieval");
        } catch (EmptyResultDataAccessException ignored) {
        }
        assertEquals(0, getCountOfTokens(jdbcTemplate));;
    }

    @Test
    public void ensureExpiredTokenIsDeletedOnCreate() {
        jdbcTemplate.update("DELETE FROM revocable_tokens");
        final String originalTokenId = revocableToken.getTokenId();
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        jdbcTemplate.update("UPDATE revocable_tokens SET expires_at=? WHERE token_id=?", System.currentTimeMillis() - 10000, revocableToken.getTokenId());
        revocableToken.setTokenId(generator.generate());
        jdbcRevocableTokenProvisioning.lastExpiredCheck.set(0); //simulate time has passed
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertEquals(1, getCountOfTokens(jdbcTemplate));
        assertEquals(1, getCountOfTokensById(jdbcTemplate, revocableToken.getTokenId()));
        assertEquals(0, getCountOfTokensById(jdbcTemplate, originalTokenId));
    }

    @Test
    public void periodicDeletionOfExpiredTokens() {
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        revocableToken.setTokenId(new RandomValueStringGenerator().generate());
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertEquals(2, getCountOfTokens(jdbcTemplate));
        jdbcTemplate.update("UPDATE revocable_tokens SET expires_at=?", System.currentTimeMillis() - 10000);
        try {
            jdbcRevocableTokenProvisioning.lastExpiredCheck.set(0);
            jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId());
            fail("Token should have been deleted prior to retrieval");
        } catch (EmptyResultDataAccessException ignored) {
        }
        assertEquals(0, getCountOfTokens(jdbcTemplate));
    }

    @Test
    public void deleteByIdentityZone() {
        IdentityZone zone = MultitenancyFixture.identityZone("test-zone", "test-zone");
        IdentityZoneHolder.set(zone);
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId());
        EntityDeletedEvent<IdentityZone> zoneDeleted = new EntityDeletedEvent<>(zone, null);
        jdbcRevocableTokenProvisioning.onApplicationEvent(zoneDeleted);
        error.expect(EmptyResultDataAccessException.class);
        jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId());
    }

    @Test
    public void deleteByOrigin() {
        //no op - doesn't affect tokens
    }

    private void createData(String tokenId, String userId, String clientId) {
        char[] value = new char[100 * 1024];
        Arrays.fill(value, 'X');
        long issuedAt = System.currentTimeMillis();
        String scope = "test1,test2";
        String format = "format";
        revocableToken = new RevocableToken()
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
        // TODO: Compare revocableToken.getZoneId() and actual.getZoneId()
        assertEquals(IdentityZoneHolder.get().getId(), actual.getZoneId());
    }

    private void listTokens(boolean client) {
        String clientId = TEST_CLIENT_ID;
        String userId = TEST_USER_ID;
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
            jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
            expectedTokens.add(revocableToken);
        }

        //create a random record that should not show up
        createData(generator.generate(), generator.generate(), generator.generate());
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());

        List<RevocableToken> actualTokens = client ? jdbcRevocableTokenProvisioning.getClientTokens(clientId, IdentityZoneHolder.get().getId()) : jdbcRevocableTokenProvisioning.getUserTokens(userId, IdentityZoneHolder.get().getId());
        assertThat(actualTokens, containsInAnyOrder(expectedTokens.toArray()));
    }

    private static int getCountOfTokens(JdbcTemplate jdbcTemplate) {
        return jdbcTemplate.queryForObject("select count(1) from revocable_tokens", Integer.class);
    }

    private static int getCountOfTokensById(JdbcTemplate jdbcTemplate, String tokenId) {
        return jdbcTemplate.queryForObject("select count(1) from revocable_tokens where token_id=?", Integer.class, tokenId);
    }

}