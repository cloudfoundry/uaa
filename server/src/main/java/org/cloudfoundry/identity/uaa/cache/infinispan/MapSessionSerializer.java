package org.cloudfoundry.identity.uaa.cache.infinispan;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.stream.Collectors;

import org.infinispan.protostream.MessageMarshaller;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.session.MapSession;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class MapSessionSerializer implements MessageMarshaller<MapSession> {

	@Override
	public Class<? extends MapSession> getJavaClass() {
		return MapSession.class;
	}

	@Override
	public String getTypeName() {
		return "uaa.MapSession";
	}
	
	private final ObjectMapper mapper = new ObjectMapper()
			            .enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL)
			            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
 
	private final ObjectMapper raw = new ObjectMapper();
	
	private final TypeReference<HashMap<String,Object>> typeRef = new TypeReference<HashMap<String,Object>>() {};
	
	public static final String secHeader = HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;
	public static final String secException = "SPRING_SECURITY_LAST_EXCEPTION";
	private static final String authClazz = "SPRING_SECURITY_AUTH_CLASS";

	@Override
	public MapSession readFrom(ProtoStreamReader reader) throws IOException {
		String id = reader.readString("id");
		MapSession session = new MapSession(id);
		session.setCreationTime(Instant.ofEpochMilli(reader.readLong("creationTime")));
		session.setLastAccessedTime(Instant.ofEpochMilli(reader.readLong("lastAccessedTime")));
		HashMap<String, Object> sessionAttrs = mapper.readValue(reader.readString("sessionAttrs"), typeRef);
		sessionAttrs.forEach(session::setAttribute);
		String sec_ctx = reader.readString("security_context");
		if (sec_ctx != null) {
			String authClass = session.getAttribute(authClazz);
			Authentication ctx;
			try {
				ctx = (Authentication) raw.readValue(sec_ctx, Class.forName(authClass));
				session.setAttribute(secHeader, new SecurityContextImpl(ctx));
			} catch (ClassNotFoundException e) {
				log.error(e.getMessage());
			}			
		}
		return session;
	}

	@Override
	public void writeTo(ProtoStreamWriter writer, MapSession t) throws IOException {
		writer.writeString("id", t.getId());
		writer.writeString("originalId", t.getOriginalId());
		writer.writeLong("creationTime", t.getCreationTime().toEpochMilli());
		writer.writeLong("lastAccessedTime", t.getLastAccessedTime().toEpochMilli());
		SecurityContextImpl sec_ctx = t.getAttribute(secHeader);
		Authentication authentication = sec_ctx != null ? sec_ctx.getAuthentication() : null;
		var attrs = t.getAttributeNames()
		     .stream()
		     .filter(attr-> !attr.equals(secHeader))
		     .filter(attr-> !attr.equals(secException))
		    .collect(Collectors.toMap(k -> k , t::getAttribute));	
		if (authentication!=null) {
			attrs.put(authClazz, authentication.getClass().getName());
		}
		writer.writeString("sessionAttrs", mapper.writerFor(HashMap.class).writeValueAsString(attrs));
		
		if (authentication!=null)
		   writer.writeString("security_context", raw.writeValueAsString(authentication));
	}

}