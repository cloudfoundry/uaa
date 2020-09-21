package org.cloudfoundry.identity.uaa.cache.infinispan;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.cloudfoundry.identity.uaa.oauth.TokenRevocationEndpoint;
import org.cloudfoundry.identity.uaa.oauth.TokenValidationService;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Aspect
@Slf4j
@Conditional(InfinispanConfig.InfinispanConfigured.class)
public class AccessTokenCaching {
	
	private final InfinispanTokenStore tokenStore;
	private final IdentityZoneManager zoneManager;
	private final UaaTokenServices tokenServices;
	private final TokenRevocationEndpoint revokeEndpoint;
	private final TokenValidationService tokenValidation;
	
	public AccessTokenCaching(InfinispanTokenStore tokenStore, IdentityZoneManager zoneManager, UaaTokenServices tokenServices, TokenRevocationEndpoint revocationEndpoint, TokenValidationService tokenValidation) {
		this.tokenStore = tokenStore;
		this.zoneManager = zoneManager;
		this.tokenServices = tokenServices;
		this.revokeEndpoint = revocationEndpoint;
		this.tokenValidation = tokenValidation;
	}
	
	@PostConstruct
	public void setupTokenStore() {
		try {
			TokenPolicy tokenPolicy = zoneManager.getCurrentIdentityZone().getConfig().getTokenPolicy();
			tokenPolicy.setJwtRevocable(true);
			tokenPolicy.setRefreshTokenFormat(TokenFormat.OPAQUE.getStringValue());
		}
		catch (Exception e) {
			log.error("Failed to setup revokable access tokens :"+ e.getMessage());
		}
		tokenServices.setTokenProvisioning(tokenStore);
		revokeEndpoint.setTokenProvisioning(tokenStore);
		tokenValidation.setTokenProvisioning(tokenStore);
	}

	@Around("execution(public * org.cloudfoundry.identity.uaa.oauth.UaaTokenServices.createAccessToken(..)) && args(auth,..)")
	public Object  accessTokenCaching(final ProceedingJoinPoint pjp , OAuth2Authentication auth) throws Throwable {
		String clientId = auth.getOAuth2Request().getClientId();
		String zoneId = zoneManager.getCurrentIdentityZoneId();
		List<RevocableToken> clientTokens;
		if (auth.getUserAuthentication() != null) {
		   String userName = auth.getUserAuthentication().getName();
		   log.info("User Authentication found, get tokens for '{}'", userName);	
		   clientTokens = tokenStore.getUserTokens(userName, clientId, zoneId);
		}
		else {		
		   log.info("Fetch client token '{}'", clientId);	
		   clientTokens = tokenStore.getClientTokens(clientId, zoneId);
		}
		
		if (clientTokens.isEmpty()) {
			log.info("No cached tokens found for [clientId: {}, zone: {}]", clientId, zoneId);
			return pjp.proceed();
		} else {
			log.info("Found  cached entry for [clientId: {}, zone: {}]", clientId, zoneId);
			 Map<TokenType, RevocableToken> tokenMap = clientTokens.stream()
					 .collect(Collectors.toMap(RevocableToken::getResponseType, t->t));
			 RevocableToken token = tokenMap.get(TokenType.ACCESS_TOKEN);
			 RevocableToken refreshToken = tokenMap.get(TokenType.REFRESH_TOKEN);
			 boolean isOpaque = tokenServices.isOpaqueTokenRequired(auth);
			 CompositeToken oauth2Token = new CompositeToken(isOpaque ?
					                                         token.getTokenId() : 
					                                         token.getValue());
			 oauth2Token.setExpiration(new Date(token.getExpiresAt()));
			 Set<String> scope = new TreeSet<String>();
			 for (StringTokenizer tokenizer = new StringTokenizer(token.getScope(), " ,"); tokenizer
						.hasMoreTokens();) {
					scope.add(tokenizer.nextToken());
			 }
			 oauth2Token.setScope(scope);
			 oauth2Token.setTokenType(TokenType.ACCESS_TOKEN.name().toLowerCase());
			 if (refreshToken !=null) {
				 String refreshTokenFormat = zoneManager.getCurrentIdentityZone().getConfig().getTokenPolicy().getRefreshTokenFormat();
				 boolean isRefreshTokenOpaque = TokenFormat.fromStringValue(refreshTokenFormat) == TokenFormat.OPAQUE;
				 oauth2Token.setRefreshToken(new DefaultOAuth2RefreshToken( isRefreshTokenOpaque ? refreshToken.getTokenId() : refreshToken.getValue()));
			 }
			 log.debug("Oauth2 access token  returned from cache [clientId: {}, zone: {}]", clientId, zoneId);
		     return oauth2Token;
		}
			
	}
	

}