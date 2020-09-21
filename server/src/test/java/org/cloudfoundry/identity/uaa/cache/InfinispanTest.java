package org.cloudfoundry.identity.uaa.cache;


import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.util.Collections;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.cache.infinispan.MapSessionSerializer;
import org.cloudfoundry.identity.uaa.cache.infinispan.RevocableTokenSerializer;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestCache;
import org.infinispan.protostream.FileDescriptorSource;
import org.infinispan.protostream.ProtobufUtil;
import org.infinispan.protostream.SerializationContext;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.session.MapSession;

public class InfinispanTest {
	
	@Test
	public void testSerializers() throws Exception {
		
		SerializationContext ctx = ProtobufUtil.newSerializationContext();
		ctx.registerProtoFiles(FileDescriptorSource.fromResources("uaa.proto"));
		ctx.registerMarshaller(new RevocableTokenSerializer());
		ctx.registerMarshaller(new MapSessionSerializer());
		
		MapSession test = new MapSession();
		test.setAttribute("int", 2);
		test.setAttribute("long", Long.valueOf("0"));
		test.setLastAccessedTime(Instant.now());
		
		test.setAttribute("ff", new UaaSavedRequestCache.ClientRedirectSavedRequest.Builder()
				                            .setRedirectUrl("http://fff")
				                            .setRequestURL("http://ddd")
				                            .setContextPath("/")
				                            .setServerPort(80).build());
		
		test.setAttribute(MapSessionSerializer.secHeader, new SecurityContextImpl(
				          new UaaAuthentication(new UaaPrincipal("d", "d", "r", "r", "d", "d"), 
				        		  UaaStringUtils.getAuthoritiesFromStrings( Collections.singletonList("openid") ),  UaaAuthenticationDetails.UNKNOWN)
				          ));
		
		byte[] testBytes = ProtobufUtil.toByteArray(ctx, test);
		
		MapSession restored = ProtobufUtil.fromByteArray(ctx, testBytes, MapSession.class);
		
		assertNotNull(restored);
		assertNotNull(restored.getAttribute("long"));
		assertNotNull(restored.getAttribute("int"));
		Object ff = restored.getAttribute("ff");
		assertTrue(ff instanceof UaaSavedRequestCache.ClientRedirectSavedRequest);
		assertEquals(Long.valueOf("0"), restored.getAttribute("long"));
		assertEquals(Integer.valueOf("2"), restored.getAttribute("int"));
		
		
	}
	

}
