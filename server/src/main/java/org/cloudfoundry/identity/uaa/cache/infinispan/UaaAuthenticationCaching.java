package org.cloudfoundry.identity.uaa.cache.infinispan;

import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.infinispan.client.hotrod.MetadataValue;
import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.spring.remote.provider.SpringRemoteCacheManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Aspect
@Slf4j
@Conditional(InfinispanConfig.InfinispanConfigured.class)
public class UaaAuthenticationCaching {
	
	@Value("${ldap.cache.ttl:30000}")
	private long authTTL;
	
	private final RemoteCache<String, String> ldapAuthentications;

	public UaaAuthenticationCaching(SpringRemoteCacheManager cm) {
		super();
		this.ldapAuthentications = cm.getNativeCacheManager().getCache("ldap-authentications");
	}
	
	@PostConstruct
	public void initCache() {
		Objects.requireNonNull(ldapAuthentications, "Remote cache is not configured");
		log.info("Initialized");
	}
	
	@Before("execution(* org.cloudfoundry.identity.uaa.authentication.manager.*.authenticate(..))")
	public void logBeforeAuthenticate(JoinPoint joinPoint) {
		log.trace("'authenticate' UAA joint point: {}",joinPoint.toShortString());
    } 
	
	
	@Around("execution(public * org.cloudfoundry..DynamicZoneAwareAuthenticationManager.authenticate(..)) && args(auth,..)")
	public Authentication ldapAuthCaching(ProceedingJoinPoint pjp, Authentication auth) throws Throwable {
		String userName = auth.getName();
		String credentials = (String) auth.getCredentials();
		String hash = Base64.getEncoder().encodeToString((userName+":"+credentials).getBytes());
		MetadataValue<String> metadata = ldapAuthentications.getWithMetadata(hash);
		if (metadata == null) {
			log.info("No cache UAA authentication found for '{}', invoking downstream", userName);
			UaaAuthentication authObj = (UaaAuthentication) pjp.proceed();
			String effectiveLdap = JsonUtils.writeValueAsString(authObj);
			ldapAuthentications.putIfAbsent(hash, effectiveLdap, authTTL, TimeUnit.MILLISECONDS);
			return authObj;
		}
		log.info("Found cached UAA authentication for '{}'", hash);
		return JsonUtils.readValue(metadata.getValue(), UaaAuthentication.class);
	}
	

}