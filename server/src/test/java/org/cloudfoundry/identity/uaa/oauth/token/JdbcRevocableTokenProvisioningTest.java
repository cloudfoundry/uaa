package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;

import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.ACCESS_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@WithDatabaseContext
class JdbcRevocableTokenProvisioningTest {

    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_CLIENT_ID = "test-client-id";

    private JdbcRevocableTokenProvisioning jdbcRevocableTokenProvisioning;
    private RevocableToken revocableToken;
    private RandomValueStringGenerator generator;
    private Random random;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    @BeforeEach
    void setUp() {
        generator = new RandomValueStringGenerator();
        random = new Random();

        JdbcTemplate template = spy(jdbcTemplate);
        jdbcRevocableTokenProvisioning = spy(new JdbcRevocableTokenProvisioning(template, limitSqlAdapter, new TimeServiceImpl()));
        revocableToken = createRevocableToken("test-token-id", TEST_USER_ID, TEST_CLIENT_ID, random);
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
        jdbcTemplate.update("DELETE FROM revocable_tokens");
    }

    static class IdentityZoneArgumentsProvider implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(IdentityZone.getUaa()),
                    Arguments.of(MultitenancyFixture.identityZone("other", "other"))
            );
        }
    }

    @ParameterizedTest
    @ArgumentsSource(IdentityZoneArgumentsProvider.class)
    void onApplicationEventCallsInternalDeleteMethod(IdentityZone zone) {
        BaseClientDetails clientDetails = new BaseClientDetails("id", "", "", "", "", "");
        IdentityZoneHolder.set(zone);
        reset(jdbcRevocableTokenProvisioning);
        jdbcRevocableTokenProvisioning.onApplicationEvent(new EntityDeletedEvent<>(clientDetails, mock(UaaAuthentication.class), IdentityZoneHolder.getCurrentZoneId()));
        jdbcRevocableTokenProvisioning.onApplicationEvent((AbstractUaaEvent) new EntityDeletedEvent<>(clientDetails, mock(UaaAuthentication.class), IdentityZoneHolder.getCurrentZoneId()));
        verify(jdbcRevocableTokenProvisioning, times(2)).deleteByClient(eq("id"), eq(zone.getId()));
    }

    @ParameterizedTest
    @ArgumentsSource(IdentityZoneArgumentsProvider.class)
    void revocableTokensDeletedWhenClientIs(IdentityZone zone) {
        BaseClientDetails clientDetails = new BaseClientDetails(TEST_CLIENT_ID, "", "", "", "", "");
        IdentityZoneHolder.set(zone);
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertEquals(1, getCountOfTokens(jdbcTemplate));
        assertEquals(zone.getId(), jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()).getZoneId());
        jdbcRevocableTokenProvisioning.onApplicationEvent((AbstractUaaEvent) new EntityDeletedEvent<>(clientDetails, mock(UaaAuthentication.class), IdentityZoneHolder.getCurrentZoneId()));
        assertEquals(0, getCountOfTokens(jdbcTemplate));
    }

    @ParameterizedTest
    @ArgumentsSource(IdentityZoneArgumentsProvider.class)
    void revocableTokensDeletedWhenUserIs(IdentityZone zone) {
        IdentityZoneHolder.set(zone);
        UaaUser user = new UaaUser(
                new UaaUserPrototype()
                        .withId(TEST_USER_ID)
                        .withUsername("username")
                        .withEmail("test@test.com")
                        .withZoneId(zone.getId())
        );
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertEquals(1, getCountOfTokens(jdbcTemplate));
        assertEquals(zone.getId(), jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()).getZoneId());
        jdbcRevocableTokenProvisioning.onApplicationEvent((AbstractUaaEvent) new EntityDeletedEvent<>(user, mock(UaaAuthentication.class), IdentityZoneHolder.getCurrentZoneId()));
        assertEquals(0, getCountOfTokens(jdbcTemplate));
    }

    @Test
    void retrieveAllReturnsNothing() {
        assertNull(jdbcRevocableTokenProvisioning.retrieveAll(IdentityZoneHolder.get().getId()));
    }

    @Test
    void tokenNotFound() {
        assertThrows(EmptyResultDataAccessException.class,
                () -> jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()));
    }

    @Test
    void getFound() {
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertNotNull(jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()));
    }

    @Test
    void addDuplicateFails() {
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertThrows(DuplicateKeyException.class,
                () -> jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId()));
    }

    @Test
    void getFoundInZone() {
        IdentityZoneHolder.set(MultitenancyFixture.identityZone("new-zone", "new-zone"));
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertNotNull(jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()));
        IdentityZoneHolder.clear();
        assertThrows(EmptyResultDataAccessException.class,
                () -> jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()));
    }

    @Test
    void create() {
        RevocableToken createdToken = jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertTokensAreEqual(revocableToken, createdToken);
    }

    @Test
    void listUserTokens() {
        listTokens(false, jdbcRevocableTokenProvisioning, random);
    }

    @Test
    void getUserTokens_WithNullClientId() {
        assertThrows(NullPointerException.class,
                () -> jdbcRevocableTokenProvisioning.getUserTokens("userid", null, IdentityZoneHolder.get().getId()));
    }

    @Test
    void getUserTokens_WithEmptyClientId() {
        assertThrows(NullPointerException.class,
                () -> jdbcRevocableTokenProvisioning.getUserTokens("userid", "", IdentityZoneHolder.get().getId()));
    }

    @Test
    void listUserTokenForClient() {
        List<RevocableToken> expectedTokens = new ArrayList<>();
        int count = 37;
        RandomValueStringGenerator generator = new RandomValueStringGenerator(36);
        for (int i = 0; i < count; i++) {
            RevocableToken revocableToken = createRevocableToken(generator.generate(), TEST_USER_ID, TEST_CLIENT_ID, random);
            jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
            expectedTokens.add(revocableToken);
        }

        for (int i = 0; i < count; i++) {
            //create a random record that should not show up
            RevocableToken revocableToken = createRevocableToken(generator.generate(), generator.generate(), generator.generate(), random);
            jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        }

        List<RevocableToken> actualTokens = jdbcRevocableTokenProvisioning.getUserTokens(TEST_USER_ID, TEST_CLIENT_ID, IdentityZoneHolder.get().getId());
        assertThat(actualTokens, containsInAnyOrder(expectedTokens.toArray()));
    }

    @Test
    void listClientTokens() {
        listTokens(true, jdbcRevocableTokenProvisioning, random);
    }

    @Test
    void update() {
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        RevocableToken toUpdate = jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId());
        toUpdate.setFormat("format")
                .setExpiresAt(0L)
                .setIssuedAt(Long.MAX_VALUE)
                .setClientId("new-client-id")
                .setScope("scope1,scope2,scope3")
                .setValue(buildRandomTokenValue(random))
                .setUserId("new-user-id")
                .setZoneId("arbitrary-zone-id")
                .setResponseType(REFRESH_TOKEN);

        RevocableToken revocableToken = jdbcRevocableTokenProvisioning.update(toUpdate.getTokenId(), toUpdate, IdentityZoneHolder.get().getId());
        assertTokensAreEqual(toUpdate, revocableToken);
    }

    @Test
    void delete() {
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId());
        jdbcRevocableTokenProvisioning.delete(revocableToken.getTokenId(), 8, IdentityZoneHolder.get().getId());

        assertThrows(EmptyResultDataAccessException.class,
                () -> jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()));
    }

    @Test
    void deleteRefreshTokenForClientIdUserId() {
        revocableToken.setResponseType(REFRESH_TOKEN);
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        revocableToken = createRevocableToken(generator.generate(), TEST_USER_ID, TEST_CLIENT_ID, random);
        revocableToken.setResponseType(REFRESH_TOKEN);
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertEquals(2, jdbcRevocableTokenProvisioning.deleteRefreshTokensForClientAndUserId(TEST_CLIENT_ID, TEST_USER_ID, IdentityZoneHolder.get().getId()));
        assertEquals(0, jdbcRevocableTokenProvisioning.deleteRefreshTokensForClientAndUserId(TEST_CLIENT_ID, TEST_USER_ID, IdentityZoneHolder.get().getId()));
        List<RevocableToken> userTokens = jdbcRevocableTokenProvisioning.getUserTokens(TEST_USER_ID, TEST_CLIENT_ID, IdentityZoneHolder.get().getId());
        assertEquals(0, userTokens.stream().filter(t -> t.getResponseType().equals(REFRESH_TOKEN)).count());
    }

    @Test
    void ensureExpiredTokenIsDeleted() {
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        jdbcTemplate.update("UPDATE revocable_tokens SET expires_at=? WHERE token_id=?", System.currentTimeMillis() - 10000, revocableToken.getTokenId());
        assertThrows(EmptyResultDataAccessException.class, () -> jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()));
        assertEquals(0, getCountOfTokens(jdbcTemplate));
    }

    @Test
    void ensureExpiredTokenIsDeletedOnCreate() {
        jdbcTemplate.update("DELETE FROM revocable_tokens");
        final String originalTokenId = revocableToken.getTokenId();
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        jdbcTemplate.update("UPDATE revocable_tokens SET expires_at=? WHERE token_id=?", System.currentTimeMillis() - 10000, revocableToken.getTokenId());
        revocableToken.setTokenId(generator.generate());
        jdbcRevocableTokenProvisioning.resetLastExpiredCheck(); //simulate time has passed
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertEquals(1, getCountOfTokens(jdbcTemplate));
        assertEquals(1, getCountOfTokensById(jdbcTemplate, revocableToken.getTokenId()));
        assertEquals(0, getCountOfTokensById(jdbcTemplate, originalTokenId));
    }

    @Test
    void periodicDeletionOfExpiredTokens() {
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        revocableToken.setTokenId(generator.generate());
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertEquals(2, getCountOfTokens(jdbcTemplate));
        jdbcTemplate.update("UPDATE revocable_tokens SET expires_at=?", System.currentTimeMillis() - 10000);
        jdbcRevocableTokenProvisioning.resetLastExpiredCheck();
        assertThrows(EmptyResultDataAccessException.class, () -> jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()));
        assertEquals(0, getCountOfTokens(jdbcTemplate));
    }

    @Test
    void deleteByIdentityZone() {
        IdentityZone zone = MultitenancyFixture.identityZone("test-zone", "test-zone");
        IdentityZoneHolder.set(zone);
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId());
        EntityDeletedEvent<IdentityZone> zoneDeleted = new EntityDeletedEvent<>(zone, null, IdentityZoneHolder.getCurrentZoneId());
        jdbcRevocableTokenProvisioning.onApplicationEvent(zoneDeleted);
        assertThrows(EmptyResultDataAccessException.class,
                () -> jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()));
    }

    @Test
    void deleteByOrigin() {
        //no op - doesn't affect tokens
    }

    private static String buildRandomTokenValue(Random random) {
        final int size = 100 + random.nextInt(100);
        final char c = (char) (65 + random.nextInt(26));
        char[] value = new char[size * 1024];
        Arrays.fill(value, c);
        return new String(value);
    }

    private static RevocableToken createRevocableToken(String tokenId, String userId, String clientId, Random random) {
        return new RevocableToken()
                .setTokenId(tokenId)
                .setClientId(clientId)
                .setResponseType(ACCESS_TOKEN)
                .setIssuedAt(0)
                .setExpiresAt(Long.MAX_VALUE)
                .setValue(buildRandomTokenValue(random))
                .setScope("test1,test2")
                .setFormat("format")
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

    private static void listTokens(boolean client, JdbcRevocableTokenProvisioning jdbcRevocableTokenProvisioning, Random random) {
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
            RevocableToken revocableToken = createRevocableToken(generator.generate(), userId, clientId, random);
            jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
            expectedTokens.add(revocableToken);
        }

        //create a random record that should not show up
        RevocableToken revocableToken = createRevocableToken(generator.generate(), generator.generate(), generator.generate(), random);
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