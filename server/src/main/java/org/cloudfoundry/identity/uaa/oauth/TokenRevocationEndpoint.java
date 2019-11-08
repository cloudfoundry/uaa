package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.event.TokenRevocationEvent;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.expression.OAuth2ExpressionUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

import static org.springframework.http.HttpStatus.OK;
import static org.springframework.web.bind.annotation.RequestMethod.DELETE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;

@Controller
public class TokenRevocationEndpoint implements ApplicationEventPublisherAware {

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    private final MultitenantJdbcClientDetailsService clientDetailsService;
    private final ScimUserProvisioning userProvisioning;
    private final RevocableTokenProvisioning tokenProvisioning;

    private final WebResponseExceptionTranslator exceptionTranslator;
    private final RandomValueStringGenerator generator;

    private ApplicationEventPublisher eventPublisher;

    public TokenRevocationEndpoint(
            final @Qualifier("jdbcClientDetailsService") MultitenantJdbcClientDetailsService clientDetailsService,
            final @Qualifier("scimUserProvisioning") ScimUserProvisioning userProvisioning,
            final @Qualifier("revocableTokenProvisioning") RevocableTokenProvisioning tokenProvisioning) {
        this.clientDetailsService = clientDetailsService;
        this.userProvisioning = userProvisioning;
        this.tokenProvisioning = tokenProvisioning;

        this.exceptionTranslator = new DefaultWebResponseExceptionTranslator();
        this.generator = new RandomValueStringGenerator(8);
    }

    @RequestMapping("/oauth/token/revoke/user/{userId}")
    public ResponseEntity<Void> revokeTokensForUser(@PathVariable String userId) {
        logger.debug("Revoking tokens for user: " + userId);
        String zoneId = IdentityZoneHolder.get().getId();
        ScimUser user = userProvisioning.retrieve(userId, zoneId);
        user.setSalt(generator.generate());
        userProvisioning.update(userId, user, zoneId);
        eventPublisher.publishEvent(new TokenRevocationEvent(userId, null, zoneId, SecurityContextHolder.getContext().getAuthentication()));
        logger.debug("Tokens revoked for user: " + userId);
        return new ResponseEntity<>(OK);
    }

    @RequestMapping("/oauth/token/revoke/user/{userId}/client/{clientId}")
    public ResponseEntity<Void> revokeTokensForUserAndClient(@PathVariable String userId, @PathVariable String clientId) {
        String zoneId = IdentityZoneHolder.get().getId();
        logger.debug("Revoking tokens for user " + userId + " and client " + clientId);
        List<RevocableToken> tokens = tokenProvisioning.getUserTokens(userId, clientId, zoneId);
        for (RevocableToken token : tokens) {
            tokenProvisioning.delete(token.getTokenId(), -1, zoneId);
        }
        eventPublisher.publishEvent(new TokenRevocationEvent(userId, clientId, zoneId, SecurityContextHolder.getContext().getAuthentication()));
        logger.debug("Tokens revoked for user " + userId + " and client " + clientId);
        return new ResponseEntity<>(OK);
    }

    @RequestMapping("/oauth/token/revoke/client/{clientId}")
    public ResponseEntity<Void> revokeTokensForClient(@PathVariable String clientId) {
        logger.debug("Revoking tokens for client: " + clientId);
        String zoneId = IdentityZoneHolder.get().getId();
        BaseClientDetails client = (BaseClientDetails) clientDetailsService.loadClientByClientId(clientId, zoneId);
        client.addAdditionalInformation(ClientConstants.TOKEN_SALT, generator.generate());
        clientDetailsService.updateClientDetails(client, zoneId);
        eventPublisher.publishEvent(new TokenRevocationEvent(null, clientId, zoneId, SecurityContextHolder.getContext().getAuthentication()));
        logger.debug("Tokens revoked for client: " + clientId);
        ((SystemDeletable) tokenProvisioning).deleteByClient(clientId, zoneId);
        return new ResponseEntity<>(OK);
    }

    @RequestMapping(value = "/oauth/token/revoke/{tokenId}", method = DELETE)
    public ResponseEntity<Void> revokeTokenById(@PathVariable String tokenId) {
        logger.debug("Revoking token with ID:" + tokenId);
        String zoneId = IdentityZoneHolder.get().getId();
        RevocableToken revokedToken = tokenProvisioning.delete(tokenId, -1, zoneId);
        eventPublisher.publishEvent(new TokenRevocationEvent(revokedToken.getUserId(), revokedToken.getClientId(), zoneId, SecurityContextHolder.getContext().getAuthentication()));
        logger.debug("Revoked token with ID: " + tokenId);
        return new ResponseEntity<>(OK);
    }

    @RequestMapping(value = "/oauth/token/list", method = GET)
    public ResponseEntity<List<RevocableToken>> listUserTokens(OAuth2Authentication authentication) {
        UaaPrincipal principal = (UaaPrincipal) authentication.getUserAuthentication().getPrincipal();
        String userId = principal.getId();
        String clientId = authentication.getOAuth2Request().getClientId();
        logger.debug("Listing revocable tokens access token userId:" + userId + " clientId:" + clientId);
        List<RevocableToken> result = tokenProvisioning.getUserTokens(userId, clientId, IdentityZoneHolder.get().getId());
        removeTokenValues(result);
        return new ResponseEntity<>(result, OK);
    }

    protected void removeTokenValues(List<RevocableToken> result) {
        result.forEach(t -> t.setValue(null));
    }

    @RequestMapping(value = "/oauth/token/list/user/{userId}", method = GET)
    public ResponseEntity<List<RevocableToken>> listUserTokens(@PathVariable String userId, OAuth2Authentication authentication) {
        if (OAuth2ExpressionUtils.hasAnyScope(authentication, new String[]{"tokens.list", "uaa.admin"})) {
            logger.debug("Listing revocable tokens for user:" + userId);
            List<RevocableToken> result = tokenProvisioning.getUserTokens(userId, IdentityZoneHolder.get().getId());
            removeTokenValues(result);
            return new ResponseEntity<>(result, OK);
        } else {
            return listUserTokens(authentication);
        }
    }

    @RequestMapping(value = "/oauth/token/list/client/{clientId}", method = GET)
    public ResponseEntity<List<RevocableToken>> listClientTokens(@PathVariable String clientId, OAuth2Authentication authentication) {
        if (OAuth2ExpressionUtils.hasAnyScope(authentication, new String[]{"tokens.list", "uaa.admin"})) {
            logger.debug("Listing revocable tokens for client:" + clientId);
            List<RevocableToken> result = tokenProvisioning.getClientTokens(clientId, IdentityZoneHolder.get().getId());
            removeTokenValues(result);
            return new ResponseEntity<>(result, OK);
        } else {
            return listUserTokens(authentication);
        }
    }


    @ExceptionHandler({ScimResourceNotFoundException.class, NoSuchClientException.class, EmptyResultDataAccessException.class})
    public ResponseEntity<OAuth2Exception> handleException(Exception e) throws Exception {
        logger.info("Handling error: " + e.getClass().getSimpleName() + ", " + e.getMessage());
        InvalidTokenException e404 = new InvalidTokenException("Resource not found") {
            @Override
            public int getHttpErrorCode() {
                return 404;
            }
        };
        return exceptionTranslator.translate(e404);
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.eventPublisher = applicationEventPublisher;
    }
}
