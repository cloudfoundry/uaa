package org.cloudfoundry.identity.uaa.cache.infinispan;

import java.io.IOException;
import java.util.Properties;

import javax.annotation.PostConstruct;

import org.apache.commons.io.IOUtils;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.web.beans.UaaSessionConfig;
import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.client.hotrod.RemoteCacheManager;
import org.infinispan.client.hotrod.marshall.ProtoStreamMarshaller;
import org.infinispan.protostream.FileDescriptorSource;
import org.infinispan.protostream.SerializationContext;
import org.infinispan.query.remote.client.ProtobufMetadataManagerConstants;
import org.infinispan.spring.remote.provider.SpringRemoteCacheManager;
import org.infinispan.spring.remote.provider.SpringRemoteCacheManagerFactoryBean;
import org.infinispan.spring.remote.session.configuration.EnableInfinispanRemoteHttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.core.io.Resource;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.lang.NonNull;
import org.springframework.session.web.context.AbstractHttpSessionApplicationInitializer;

@Configuration
@Conditional(InfinispanConfig.InfinispanConfigured.class)
@EnableInfinispanRemoteHttpSession
@EnableAspectJAutoProxy
public class InfinispanConfig extends AbstractHttpSessionApplicationInitializer {
	
	public static class InfinispanConfigured extends UaaSessionConfig  implements Condition {
        @Override
        public boolean matches(@NonNull ConditionContext context, @NonNull AnnotatedTypeMetadata metadata) {
            String sessionStore = getSessionStore(context.getEnvironment());
            validateSessionStore(sessionStore);
            return UaaSessionConfig.CACHE_SESSION_STORE_TYPE.equals(sessionStore);
        }
    }
	
	@Value("${uaa.remote.infinispan:}")
	private Properties cacheConfig;
	
	@Bean
	public SpringRemoteCacheManagerFactoryBean infinispanCacheManager() {
		SpringRemoteCacheManagerFactoryBean cacheFactoryBean = new SpringRemoteCacheManagerFactoryBean();
		cacheFactoryBean.setConfigurationProperties(cacheConfig);
		return cacheFactoryBean;
	}
	
}