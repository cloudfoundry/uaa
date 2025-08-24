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

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeServices;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DeadlockLoserDataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.support.SqlLobValue;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.common.util.SerializationUtils;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.io.Serializable;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Semaphore;

@Component("authorizationCodeServices")
@DependsOnDatabaseInitialization
public class UaaTokenStore implements AuthorizationCodeServices {
    public static final Duration DEFAULT_EXPIRATION_TIME = Duration.ofMinutes(5);
    public static final Duration LEGACY_CODE_EXPIRATION_TIME = Duration.ofDays(3);
    public static final String USER_AUTHENTICATION_UAA_AUTHENTICATION = "userAuthentication.uaaAuthentication";
    public static final String USER_AUTHENTICATION_UAA_PRINCIPAL = "userAuthentication.uaaPrincipal";
    public static final String USER_AUTHENTICATION_AUTHORITIES = "userAuthentication.authorities";
    public static final String OAUTH2_REQUEST_PARAMETERS = "oauth2Request.requestParameters";
    public static final String OAUTH2_REQUEST_CLIENT_ID = "oauth2Request.clientId";
    public static final String OAUTH2_REQUEST_AUTHORITIES = "oauth2Request.authorities";
    public static final String OAUTH2_REQUEST_APPROVED = "oauth2Request.approved";
    public static final String OAUTH2_REQUEST_SCOPE = "oauth2Request.scope";
    public static final String OAUTH2_REQUEST_RESOURCE_IDS = "oauth2Request.resourceIds";
    public static final String OAUTH2_REQUEST_REDIRECT_URI = "oauth2Request.redirectUri";
    public static final String OAUTH2_REQUEST_RESPONSE_TYPES = "oauth2Request.responseTypes";

    protected static Logger logger = LoggerFactory.getLogger(UaaTokenStore.class);

    private static final String SQL_SELECT_STATEMENT = "select code, user_id, client_id, expiresat, created, authentication from oauth_code where code = ?";
    private static final String SQL_INSERT_STATEMENT = "insert into oauth_code (code, user_id, client_id, expiresat, authentication, identity_zone_id) values (?, ?, ?, ?, ?, ?)";
    private static final String SQL_DELETE_STATEMENT = "delete from oauth_code where code = ?";
    private static final String SQL_EXPIRE_STATEMENT = "delete from oauth_code where expiresat > 0 AND expiresat < ?";
    private static final String SQL_CLEAN_STATEMENT = "delete from oauth_code where created < ? and expiresat = 0";

    private final DataSource dataSource;
    private final TimeService timeService;
    private final IdentityZoneManager identityZoneManager;
    private final Duration expirationTime;
    private final RandomValueStringGenerator generator = new RandomValueStringGenerator(32);
    private final RowMapper rowMapper = new TokenCodeRowMapper();

    private Instant lastClean = Instant.EPOCH;
    private Semaphore cleanMutex = new Semaphore(1);

    @Autowired
    public UaaTokenStore(DataSource dataSource, TimeService timeService, IdentityZoneManager identityZoneManager) {
        this(dataSource, timeService, identityZoneManager, DEFAULT_EXPIRATION_TIME);
    }

    public UaaTokenStore(DataSource dataSource, TimeService timeService, IdentityZoneManager identityZoneManager, Duration expirationTime) {
        this.dataSource = dataSource;
        this.timeService = timeService;
        this.identityZoneManager = identityZoneManager;
        this.expirationTime = expirationTime;
    }

    @Override
    public String createAuthorizationCode(OAuth2Authentication authentication) {
        final int maxAttempts = 3;
        performExpirationCleanIfEnoughTimeHasElapsed();
        JdbcTemplate template = new JdbcTemplate(dataSource);
        int attempt = 0;
        while (true) {
            attempt++;
            try {
                String code = generator.generate();
                Instant expiresAt = timeService.getCurrentInstant().plus(getExpirationTime());
                String userId = authentication.getUserAuthentication() == null ? null : ((UaaPrincipal) authentication.getUserAuthentication().getPrincipal()).getId();
                String clientId = authentication.getOAuth2Request().getClientId();
                SqlLobValue data = new SqlLobValue(serializeOauth2Authentication(authentication));
                int updated = template.update(
                        SQL_INSERT_STATEMENT,
                        new Object[]{code, userId, clientId, expiresAt.toEpochMilli(), data, identityZoneManager.getCurrentIdentityZoneId()},
                        new int[]{Types.VARCHAR, Types.VARCHAR, Types.VARCHAR, Types.NUMERIC, Types.BLOB, Types.VARCHAR}
                );
                if (updated == 0) {
                    throw new DataIntegrityViolationException("[oauth_code] Failed to insert code. Result was 0");
                }
                return code;
            } catch (DataIntegrityViolationException exists) {
                if (attempt >= maxAttempts) {
                    throw exists;
                }
            }
        }
    }

    @Override
    public OAuth2Authentication consumeAuthorizationCode(String code) throws InvalidGrantException {
        performExpirationCleanIfEnoughTimeHasElapsed();
        JdbcTemplate template = new JdbcTemplate(dataSource);
        try {
            TokenCode tokenCode = (TokenCode) template.queryForObject(SQL_SELECT_STATEMENT, rowMapper, code);
            if (tokenCode != null) {
                try {
                    if (tokenCode.isExpired()) {
                        logger.debug("[oauth_code] Found code, but it expired:{}", tokenCode);
                        throw new InvalidGrantException("Authorization code expired: " + code);
                    } else {
                        return tokenCode.deserialize();
                    }
                } finally {
                    template.update(SQL_DELETE_STATEMENT, code);
                }
            }
        } catch (EmptyResultDataAccessException ignored) {
        }
        throw new InvalidGrantException("Invalid authorization code: " + code);
    }

    protected byte[] serializeOauth2Authentication(OAuth2Authentication auth2Authentication) {
        Authentication userAuthentication = auth2Authentication.getUserAuthentication();
        HashMap<String, Object> data = new HashMap<>();
        if (userAuthentication != null) {
            if (userAuthentication instanceof UaaAuthentication) {
                data.put(USER_AUTHENTICATION_UAA_AUTHENTICATION, JsonUtils.writeValueAsString(userAuthentication));
            } else {
                data.put(USER_AUTHENTICATION_UAA_PRINCIPAL, JsonUtils.writeValueAsString(userAuthentication.getPrincipal()));
                data.put(USER_AUTHENTICATION_AUTHORITIES, UaaStringUtils.getStringsFromAuthorities(userAuthentication.getAuthorities()));
            }
        }
        data.put(OAUTH2_REQUEST_PARAMETERS, auth2Authentication.getOAuth2Request().getRequestParameters());
        data.put(OAUTH2_REQUEST_CLIENT_ID, auth2Authentication.getOAuth2Request().getClientId());
        data.put(OAUTH2_REQUEST_AUTHORITIES, UaaStringUtils.getStringsFromAuthorities(auth2Authentication.getOAuth2Request().getAuthorities()));
        data.put(OAUTH2_REQUEST_APPROVED, auth2Authentication.getOAuth2Request().isApproved());
        data.put(OAUTH2_REQUEST_SCOPE, auth2Authentication.getOAuth2Request().getScope());
        data.put(OAUTH2_REQUEST_RESOURCE_IDS, auth2Authentication.getOAuth2Request().getResourceIds());
        data.put(OAUTH2_REQUEST_REDIRECT_URI, auth2Authentication.getOAuth2Request().getRedirectUri());
        data.put(OAUTH2_REQUEST_RESPONSE_TYPES, auth2Authentication.getOAuth2Request().getResponseTypes());

        //currently not serializing any of the
        //Map<String, Serializable > extensionProperties
        if (auth2Authentication.getOAuth2Request().getExtensions() != null && auth2Authentication.getOAuth2Request().getExtensions().size() > 0) {
            logger.warn("[oauth_code] Unable to serialize extensions:{}", auth2Authentication.getOAuth2Request().getExtensions());
        }
        return JsonUtils.writeValueAsBytes(data);
    }

    protected OAuth2Authentication deserializeOauth2Authentication(byte[] data) {
        Map<String, Object> map = JsonUtils.readValue(data, new TypeReference<Map<String, Object>>() {
        });
        Authentication userAuthentication = null;
        if (map.get(USER_AUTHENTICATION_UAA_AUTHENTICATION) != null) {
            userAuthentication = JsonUtils.readValue((String) map.get(USER_AUTHENTICATION_UAA_AUTHENTICATION), UaaAuthentication.class);
        } else if (map.get(USER_AUTHENTICATION_UAA_PRINCIPAL) != null) {
            UaaPrincipal principal = JsonUtils.readValue((String) map.get(USER_AUTHENTICATION_UAA_PRINCIPAL), UaaPrincipal.class);
            Collection<? extends GrantedAuthority> authorities = UaaStringUtils.getAuthoritiesFromStrings((Collection<String>) map.get(USER_AUTHENTICATION_AUTHORITIES));
            userAuthentication = new UaaAuthentication(principal, (List<? extends GrantedAuthority>) authorities, UaaAuthenticationDetails.UNKNOWN);
        }

        Map<String, String> requestParameters = (Map<String, String>) map.get(OAUTH2_REQUEST_PARAMETERS);
        String clientId = (String) map.get(OAUTH2_REQUEST_CLIENT_ID);
        Collection<? extends GrantedAuthority> authorities = UaaStringUtils.getAuthoritiesFromStrings((Collection<String>) map.get(OAUTH2_REQUEST_AUTHORITIES));
        boolean approved = (boolean) map.get(OAUTH2_REQUEST_APPROVED);
        Collection<String> scope = (Collection<String>) map.get(OAUTH2_REQUEST_SCOPE);
        Collection<String> resourceIds = (Collection<String>) map.get(OAUTH2_REQUEST_RESOURCE_IDS);
        String redirectUri = (String) map.get(OAUTH2_REQUEST_REDIRECT_URI);
        Collection<String> responseTypes = (Collection<String>) map.get(OAUTH2_REQUEST_RESPONSE_TYPES);

        OAuth2Request request = new OAuth2Request(
                requestParameters,
                clientId,
                authorities,
                approved,
                new HashSet<>(scope),
                new HashSet<>(resourceIds),
                redirectUri,
                new HashSet<>(responseTypes),
                new HashMap<String, Serializable>()
        );

        return new OAuth2Authentication(request, userAuthentication);
    }

    protected void performExpirationCleanIfEnoughTimeHasElapsed() {
        if (cleanMutex.tryAcquire()) {
            //check if we should expire again
            try {
                Instant now = timeService.getCurrentInstant();
                if (enoughTimeHasPassedSinceLastExpirationClean(lastClean, now)) {
                    //avoid concurrent deletes from the same UAA - performance improvement
                    lastClean = now;
                    actuallyPerformExpirationClean(now);
                }
            } finally {
                cleanMutex.release();
            }
        }
    }

    private void actuallyPerformExpirationClean(Instant now) {
        try {
            JdbcTemplate template = new JdbcTemplate(dataSource);
            int expired = template.update(SQL_EXPIRE_STATEMENT, now.toEpochMilli());
            logger.debug("[oauth_code] Removed {} expired entries.", expired);
            expired = template.update(SQL_CLEAN_STATEMENT, Timestamp.from(now.minus(LEGACY_CODE_EXPIRATION_TIME)));
            logger.debug("[oauth_code] Removed {} old entries.", expired);
        } catch (DeadlockLoserDataAccessException e) {
            logger.debug("[oauth code] Deadlock trying to expire entries, ignored.");
        }
    }

    private boolean enoughTimeHasPassedSinceLastExpirationClean(Instant last, Instant now) {
        return Duration.between(last, now).toMillis() > getExpirationTime().toMillis();
    }

    public Duration getExpirationTime() {
        return expirationTime;
    }

    protected class TokenCodeRowMapper implements RowMapper<TokenCode> {

        @Override
        public TokenCode mapRow(ResultSet rs, int rowNum) throws SQLException {
            int pos = 1;
            String code = rs.getString(pos++);
            String userid = rs.getString(pos++);
            String clientId = rs.getString(pos++);
            long expiresat = rs.getLong(pos++);
            Instant created = rs.getTimestamp(pos++).toInstant();
            byte[] authentication = rs.getBytes(pos++);

            if (expiresat == 0) {
                return new LegacyTokenCode(code, userid, created, clientId, authentication);
            } else {
                return new NewTokenCode(code, userid, Instant.ofEpochMilli(expiresat), clientId, authentication);
            }
        }
    }

    public TokenCode createTokenCodeForTesting(String code, String userId, String clientId, Optional<Instant> expiresAt, Instant created, byte[] authentication) {
        if (expiresAt.isPresent()) {
            return new NewTokenCode(code, userId, expiresAt.get(), clientId, authentication);
        } else {
            return new LegacyTokenCode(code, userId, created, clientId, authentication);
        }
    }

    protected abstract class TokenCode {
        private final String code;
        private final String userId;
        private final String clientId;
        private final byte[] authentication;

        protected TokenCode(String code, String userId, String clientId, byte[] authentication) {
            this.code = code;
            this.userId = userId;
            this.clientId = clientId;
            this.authentication = authentication;
        }

        public byte[] getAuthentication() {
            return authentication;
        }

        public String getClientId() {
            return clientId;
        }

        public String getCode() {
            return code;
        }

        public String getUserId() {
            return userId;
        }

        abstract boolean isExpired();

        @Override
        public abstract String toString();

        public abstract OAuth2Authentication deserialize();

    }

    protected class NewTokenCode extends TokenCode {
        private final Instant expiresAt;

        public NewTokenCode(String code, String userId, Instant expiresAt, String clientId, byte[] authentication) {
            super(code, userId, clientId, authentication);
            this.expiresAt = expiresAt;
        }

        @Override
        boolean isExpired() {
            return expiresAt.isBefore(timeService.getCurrentInstant());
        }

        @Override
        public String toString() {
            return "TokenCode{" +
                    ", code='" + getCode() + '\'' +
                    ", userId='" + getUserId() + '\'' +
                    ", clientId='" + getClientId() + '\'' +
                    ", expiresAt=" + expiresAt +
                    '}';
        }

        @Override
        public OAuth2Authentication deserialize() {
            return deserializeOauth2Authentication(getAuthentication());
        }
    }

    protected  class LegacyTokenCode extends TokenCode {
        private final Instant created;

        public LegacyTokenCode(String code, String userId, Instant created, String clientId, byte[] authentication) {
            super(code, userId, clientId, authentication);
            this.created = created;
        }

        @Override
        boolean isExpired() {
            return timeService.getCurrentInstant().minus(getExpirationTime()).isAfter(created);
        }

        @Override
        public String toString() {
            return "TokenCode{" +
                    ", code='" + getCode() + '\'' +
                    ", userId='" + getUserId() + '\'' +
                    ", clientId='" + getClientId() + '\'' +
                    ", created=" + created +
                    '}';
        }

        @Override
        public OAuth2Authentication deserialize() {
            return SerializationUtils.deserialize(getAuthentication());
        }
    }
}
