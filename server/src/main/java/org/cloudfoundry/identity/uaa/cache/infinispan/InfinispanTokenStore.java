package org.cloudfoundry.identity.uaa.cache.infinispan;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;

import org.apache.commons.io.IOUtils;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.client.hotrod.RemoteCacheManager;
import org.infinispan.client.hotrod.Search;
import org.infinispan.client.hotrod.marshall.ProtoStreamMarshaller;
import org.infinispan.protostream.FileDescriptorSource;
import org.infinispan.protostream.SerializationContext;
import org.infinispan.query.dsl.QueryFactory;
import org.infinispan.query.remote.client.ProtobufMetadataManagerConstants;
import org.infinispan.spring.remote.provider.SpringRemoteCacheManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.io.Resource;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Component;

import com.google.common.collect.ImmutableMap;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
@Conditional(InfinispanConfig.InfinispanConfigured.class)
public class InfinispanTokenStore implements RevocableTokenProvisioning {
 
    public static final String REVOCATION_TOKEN_RESOURCE = "uaa.proto";

    
	final private SpringRemoteCacheManager cacheManager;
	private RemoteCache<String, RevocableToken> revocableTokenCache;
 
    public InfinispanTokenStore(SpringRemoteCacheManager cm) throws Exception {
        this.cacheManager = cm;
       
    }
 
    private <T> List<T> findBy(Class<T> entityType, RemoteCache<String, T> nativeCache, Map<String, Object> attrs, String rawFilter) {
    	log.debug("Execute cache query for {} with attributes {}", entityType.getSimpleName(), Objects.toString(attrs));
		QueryFactory qf = Search.getQueryFactory(nativeCache);
		String stringQuery = attrs.keySet().stream()
		   .map(k -> k+" = :"+k)
		   .collect(Collectors.joining(" and "));
		return 
		  qf
		  .create("from uaa."+entityType.getSimpleName()+" where "+stringQuery + (rawFilter != null ? " and " + rawFilter : "") )
		  .setParameters(attrs)
		  .list();
    }
    
    private <T> List<T> findBy(Class<T> entityType, RemoteCache<String, T> nativeCache, Map<String, Object> attrs) {
    	return findBy(entityType, nativeCache, attrs, null);
    }
    
    
	@Override
	public List<RevocableToken> retrieveAll(String zoneId) {
		return findBy(RevocableToken.class, revocableTokenCache, Collections.singletonMap("zoneId", zoneId));
	}

	@Override
	public RevocableToken retrieve(String id, String zoneId) {
		return revocableTokenCache.get(id);
	}

	@Override
	public RevocableToken create(RevocableToken resource, String zoneId) {
		var token = revocableTokenCache.putIfAbsent(resource.getTokenId(), 
				resource, 
				resource.getExpiresAt() - resource.getIssuedAt(), 
				TimeUnit.MILLISECONDS);
		if (token == null)
			throw new DuplicateKeyException(resource.getTokenId()+" already exists");
		log.debug("{}  token '{}'  added", resource.getResponseType(), resource.getTokenId() );
		return token;
	}

	@Override
	public RevocableToken update(String id, RevocableToken resource, String zoneId) {
		return revocableTokenCache.replace(id, 
				resource, 
				resource.getExpiresAt() - Instant.now().toEpochMilli(), 
				TimeUnit.MILLISECONDS);
	}

	@Override
	public RevocableToken delete(String id, int version, String zoneId) {
		return revocableTokenCache.remove(id);
	}

	@Override
	public int deleteRefreshTokensForClientAndUserId(String clientId, String userId, String zoneId) {
		List<RevocableToken> toDelete = findBy(RevocableToken.class, revocableTokenCache, ImmutableMap.of("tokenType",TokenType.REFRESH_TOKEN.ordinal(),
				                                                                                          "clientId", clientId, 
				                                                                                          "userId", userId, 
				                                                                                          "zoneId", zoneId));
		toDelete.forEach(token -> revocableTokenCache.remove(token.getTokenId()));
		return toDelete.size();
	}

	@Override
	public List<RevocableToken> getUserTokens(String userId, String zoneId) {
		return findBy(RevocableToken.class, revocableTokenCache, ImmutableMap.of(
                "userId", userId, 
                "zoneId", zoneId));
	}

	@Override
	public List<RevocableToken> getUserTokens(String userId, String clientId, String zoneId) {
		return findBy(RevocableToken.class, revocableTokenCache, ImmutableMap.of(
                "clientId", clientId, 
                "userId", userId, 
                "zoneId", zoneId));
	}

	@Override
	public List<RevocableToken> getClientTokens(String clientId, String zoneId) {
		return findBy(RevocableToken.class, revocableTokenCache, ImmutableMap.of(
                "clientId", clientId, 
                "zoneId", zoneId), "(userId is null or userId ='')");
	}
	
	@Value("classpath:"+REVOCATION_TOKEN_RESOURCE)
	private Resource protoFile;
	
	@PostConstruct
	public void registerSchemasAndMarshallers() throws Exception {		
		String protoMessages = IOUtils.toString(protoFile.getInputStream(), "UTF-8");
	    // Register entity marshallers on the client side ProtoStreamMarshaller
	    // instance associated with the remote cache manager.
	    RemoteCacheManager remoteCacheManager = cacheManager.getNativeCacheManager();
		SerializationContext ctx = ProtoStreamMarshaller.getSerializationContext(remoteCacheManager);
	    // register the necessary proto files
		FileDescriptorSource proto = FileDescriptorSource.fromString(protoFile.getFilename(), protoMessages);
	    try {
		  ctx.registerProtoFiles(proto);
	    } catch (Exception e) {
	      throw new RuntimeException("Failed to read protobuf definition '" + protoFile.getFilename() + "'", e);
	    }
	    ctx.registerMarshaller(new RevocableTokenSerializer());
	    ctx.registerMarshaller(new MapSessionSerializer());


	    // register the schemas with the server too
	    final RemoteCache<String, String> protoMetadataCache = remoteCacheManager.getCache(ProtobufMetadataManagerConstants.PROTOBUF_METADATA_CACHE_NAME);

	    protoMetadataCache.put(protoFile.getFilename(), protoMessages);

	    // check for definition error for the registered protobuf schemas
	    String errors = protoMetadataCache.get(ProtobufMetadataManagerConstants.ERRORS_KEY_SUFFIX);
	    if (errors != null) {
	      throw new IllegalStateException("Some Protobuf schema files contain errors:\n" + errors);
	    }
	    revocableTokenCache =  remoteCacheManager.getCache("tokens");
	  }
	
}