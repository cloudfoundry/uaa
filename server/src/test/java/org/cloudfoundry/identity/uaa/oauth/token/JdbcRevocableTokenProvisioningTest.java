package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.ACCESS_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@WithDatabaseContext
class JdbcRevocableTokenProvisioningTest {

    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_CLIENT_ID = "test-client-id";

    private JdbcRevocableTokenProvisioning jdbcRevocableTokenProvisioning;
    private RevocableToken revocableToken;
    private AlphanumericRandomValueStringGenerator generator;
    private Random random;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    @BeforeEach
    void setUp() {
        generator = new AlphanumericRandomValueStringGenerator();
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
        UaaClientDetails clientDetails = new UaaClientDetails("id", "", "", "", "", "");
        IdentityZoneHolder.set(zone);
        reset(jdbcRevocableTokenProvisioning);
        jdbcRevocableTokenProvisioning.onApplicationEvent(new EntityDeletedEvent<>(clientDetails, mock(UaaAuthentication.class), IdentityZoneHolder.getCurrentZoneId()));
        jdbcRevocableTokenProvisioning.onApplicationEvent((AbstractUaaEvent) new EntityDeletedEvent<>(clientDetails, mock(UaaAuthentication.class), IdentityZoneHolder.getCurrentZoneId()));
        verify(jdbcRevocableTokenProvisioning, times(2)).deleteByClient(eq("id"), eq(zone.getId()));
    }

    @ParameterizedTest
    @ArgumentsSource(IdentityZoneArgumentsProvider.class)
    void revocableTokensDeletedWhenClientIs(IdentityZone zone) {
        UaaClientDetails clientDetails = new UaaClientDetails(TEST_CLIENT_ID, "", "", "", "", "");
        IdentityZoneHolder.set(zone);
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertThat(getCountOfTokens(jdbcTemplate)).isOne();
        assertThat(jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()).getZoneId()).isEqualTo(zone.getId());
        jdbcRevocableTokenProvisioning.onApplicationEvent((AbstractUaaEvent) new EntityDeletedEvent<>(clientDetails, mock(UaaAuthentication.class), IdentityZoneHolder.getCurrentZoneId()));
        assertThat(getCountOfTokens(jdbcTemplate)).isZero();
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
        assertThat(getCountOfTokens(jdbcTemplate)).isOne();
        assertThat(jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()).getZoneId()).isEqualTo(zone.getId());
        jdbcRevocableTokenProvisioning.onApplicationEvent((AbstractUaaEvent) new EntityDeletedEvent<>(user, mock(UaaAuthentication.class), IdentityZoneHolder.getCurrentZoneId()));
        assertThat(getCountOfTokens(jdbcTemplate)).isZero();
    }

    @Test
    void retrieveAllReturnsNothing() {
        assertThat(jdbcRevocableTokenProvisioning.retrieveAll(IdentityZoneHolder.get().getId())).isNull();
    }

    @Test
    void tokenNotFound() {
        assertThatExceptionOfType(EmptyResultDataAccessException.class).isThrownBy(() -> jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()));
    }

    @Test
    void getFound() {
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertThat(jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId())).isNotNull();
    }

    @Test
    void addDuplicateFails() {
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertThatExceptionOfType(DuplicateKeyException.class).isThrownBy(() -> jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId()));
    }

    @Test
    void getFoundInZone() {
        IdentityZoneHolder.set(MultitenancyFixture.identityZone("new-zone", "new-zone"));
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertThat(jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId())).isNotNull();
        IdentityZoneHolder.clear();
        assertThatExceptionOfType(EmptyResultDataAccessException.class).isThrownBy(() -> jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()));
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
        assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> jdbcRevocableTokenProvisioning.getUserTokens("userid", null, IdentityZoneHolder.get().getId()));
    }

    @Test
    void getUserTokens_WithEmptyClientId() {
        assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> jdbcRevocableTokenProvisioning.getUserTokens("userid", "", IdentityZoneHolder.get().getId()));
    }

    @Test
    void listUserTokenForClient() {
        List<RevocableToken> expectedTokens = new ArrayList<>();
        int count = 37;
        AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator(36);
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
        assertThat(actualTokens).containsExactlyInAnyOrderElementsOf(expectedTokens);
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

        assertThatExceptionOfType(EmptyResultDataAccessException.class).isThrownBy(() -> jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()));
    }

    @Test
    void deleteRefreshTokenForClientIdUserId() {
        revocableToken.setResponseType(REFRESH_TOKEN);
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        revocableToken = createRevocableToken(generator.generate(), TEST_USER_ID, TEST_CLIENT_ID, random);
        revocableToken.setResponseType(REFRESH_TOKEN);
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertThat(jdbcRevocableTokenProvisioning.deleteRefreshTokensForClientAndUserId(TEST_CLIENT_ID, TEST_USER_ID, IdentityZoneHolder.get().getId())).isEqualTo(2);
        // should be empty on second call
        assertThat(jdbcRevocableTokenProvisioning.deleteRefreshTokensForClientAndUserId(TEST_CLIENT_ID, TEST_USER_ID, IdentityZoneHolder.get().getId())).isZero();
        List<RevocableToken> userTokens = jdbcRevocableTokenProvisioning.getUserTokens(TEST_USER_ID, TEST_CLIENT_ID, IdentityZoneHolder.get().getId());
        assertThat(userTokens.stream().filter(t -> t.getResponseType().equals(REFRESH_TOKEN)).count()).isZero();
    }

    @Test
    void ensureExpiredTokenIsDeleted() {
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        jdbcTemplate.update("UPDATE revocable_tokens SET expires_at=? WHERE token_id=?", System.currentTimeMillis() - 10000, revocableToken.getTokenId());
        assertThatExceptionOfType(EmptyResultDataAccessException.class).isThrownBy(() -> jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()));
        assertThat(getCountOfTokens(jdbcTemplate)).isZero();
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
        assertThat(getCountOfTokens(jdbcTemplate)).isOne();
        assertThat(getCountOfTokensById(jdbcTemplate, revocableToken.getTokenId())).isOne();
        assertThat(getCountOfTokensById(jdbcTemplate, originalTokenId)).isZero();
    }

    @Test
    void periodicDeletionOfExpiredTokens() {
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        revocableToken.setTokenId(generator.generate());
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        assertThat(getCountOfTokens(jdbcTemplate)).isEqualTo(2);
        jdbcTemplate.update("UPDATE revocable_tokens SET expires_at=?", System.currentTimeMillis() - 10000);
        jdbcRevocableTokenProvisioning.resetLastExpiredCheck();
        assertThatExceptionOfType(EmptyResultDataAccessException.class).isThrownBy(() -> jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()));
        assertThat(getCountOfTokens(jdbcTemplate)).isZero();
    }

    @Test
    void deleteByIdentityZone() {
        IdentityZone zone = MultitenancyFixture.identityZone("test-zone", "test-zone");
        IdentityZoneHolder.set(zone);
        jdbcRevocableTokenProvisioning.create(revocableToken, IdentityZoneHolder.get().getId());
        jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId());
        EntityDeletedEvent<IdentityZone> zoneDeleted = new EntityDeletedEvent<>(zone, null, IdentityZoneHolder.getCurrentZoneId());
        jdbcRevocableTokenProvisioning.onApplicationEvent(zoneDeleted);
        assertThatExceptionOfType(EmptyResultDataAccessException.class).isThrownBy(() -> jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), IdentityZoneHolder.get().getId()));
    }

    @Test
    void deleteByOrigin() {
        //no op - doesn't affect tokens
    }

    @Test
    void createIfNotExistsWithoutExisting() {
        try {
            jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), "uaa");
            fail("Revocable token should not exist.");
        } catch (EmptyResultDataAccessException e) {
            assertThat(e).isNotNull();
        }
        jdbcRevocableTokenProvisioning.createIfNotExists(revocableToken, "uaa");
        assertThat(jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), "uaa")).isNotNull();
    }

    @Test
    void createIfNotExistsWithExisting() {
        jdbcRevocableTokenProvisioning.create(revocableToken, "uaa");
        assertThat(jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), "uaa")).isNotNull();
        jdbcRevocableTokenProvisioning.createIfNotExists(revocableToken, "uaa");
        assertThat(jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), "uaa")).isNotNull();
    }

    @Test
    void upsertWithExisting() {
        jdbcRevocableTokenProvisioning.create(revocableToken, "uaa");
        RevocableToken token = jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), "uaa");
        assertThat(token.getTokenId()).isEqualTo("test-token-id");
        revocableToken.setTokenId("test");
        jdbcRevocableTokenProvisioning.upsert(revocableToken.getTokenId(), revocableToken, "uaa");
        token = jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), "uaa");
        assertThat(token.getTokenId()).isEqualTo("test");
    }

    @Test
    void upsertWithoutExisting() {
        try {
            jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), "uaa");
            fail("Revocable token should not exist.");
        } catch (EmptyResultDataAccessException e) {
            assertThat(e).isNotNull();
        }
        jdbcRevocableTokenProvisioning.upsert(revocableToken.getTokenId(), revocableToken, "uaa");
        assertThat(jdbcRevocableTokenProvisioning.retrieve(revocableToken.getTokenId(), "uaa")).isNotNull();
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
        assertThat(actual).isNotNull();
        assertThat(actual.getTokenId()).isNotNull();
        assertThat(actual.getTokenId()).isEqualTo(expected.getTokenId());
        assertThat(actual.getClientId()).isEqualTo(expected.getClientId());
        assertThat(actual.getExpiresAt()).isEqualTo(expected.getExpiresAt());
        assertThat(actual.getIssuedAt()).isEqualTo(expected.getIssuedAt());
        assertThat(actual.getFormat()).isEqualTo(expected.getFormat());
        assertThat(actual.getScope()).isEqualTo(expected.getScope());
        assertThat(actual.getValue()).isEqualTo(expected.getValue());
        assertThat(actual.getTokenId()).isEqualTo(expected.getTokenId());
        assertThat(actual.getResponseType()).isEqualTo(expected.getResponseType());
        // TODO: Compare revocableToken.getZoneId() and actual.getZoneId()
        assertThat(actual.getZoneId()).isEqualTo(IdentityZoneHolder.get().getId());
    }

    private static void listTokens(boolean client, JdbcRevocableTokenProvisioning jdbcRevocableTokenProvisioning, Random random) {
        String clientId = TEST_CLIENT_ID;
        String userId = TEST_USER_ID;
        List<RevocableToken> expectedTokens = new ArrayList<>();
        int count = 37;
        AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator(36);
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
        assertThat(actualTokens).containsExactlyInAnyOrderElementsOf(expectedTokens);
    }

    private static int getCountOfTokens(JdbcTemplate jdbcTemplate) {
        return jdbcTemplate.queryForObject("select count(1) from revocable_tokens", Integer.class);
    }

    private static int getCountOfTokensById(JdbcTemplate jdbcTemplate, String tokenId) {
        return jdbcTemplate.queryForObject("select count(1) from revocable_tokens where token_id=?", Integer.class, tokenId);
    }

}