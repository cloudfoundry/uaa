package org.cloudfoundry.identity.uaa.scim.util.json;

import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.JsonToken;
import org.codehaus.jackson.map.DeserializationContext;
import org.codehaus.jackson.map.JsonDeserializer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ScimGroupJsonDeserializer extends JsonDeserializer<ScimGroup> {

	@Override
	public ScimGroup deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
		ScimGroup group = new ScimGroup();

		List<ScimGroupMember> members = Collections.emptyList();

		Map<ScimGroup.Authority, List<ScimGroupMember>> roles = new HashMap<ScimGroup.Authority, List<ScimGroupMember>>();
		for (ScimGroup.Authority authority : ScimGroup.Authority.values()) {
			roles.put(authority, new ArrayList<ScimGroupMember>());
		}

		while(jp.nextToken() != JsonToken.END_OBJECT) {
			if (jp.getCurrentToken() == JsonToken.FIELD_NAME) {
				String fieldName = jp.getCurrentName();
				jp.nextToken();

				if ("id".equalsIgnoreCase(fieldName)) {
					group.setId(jp.readValueAs(String.class));
				} else if ("displayname".equalsIgnoreCase(fieldName)) {
					group.setDisplayName(jp.readValueAs(String.class));
				} else if ("meta".equalsIgnoreCase(fieldName)) {
					group.setMeta(jp.readValueAs(ScimMeta.class));
				} else if ("schemas".equalsIgnoreCase(fieldName)) {
					group.setSchemas(jp.readValueAs(String[].class));
				} else if ("members".equalsIgnoreCase(fieldName)) {
					members = Arrays.asList(jp.readValueAs(ScimGroupMember[].class));
				} else {
					for (ScimGroup.Authority authority : ScimGroup.Authority.values()) {
						if (fieldName.equalsIgnoreCase(authority.getRoleName()+"s")) {
							roles.get(authority).addAll(Arrays.asList(jp.readValueAs(ScimGroupMember[].class)));
						}
					}
				}
			}
		}

		for (ScimGroupMember member : members) {
			member.setAuthorities(new ArrayList<ScimGroup.Authority>());
			for (ScimGroup.Authority authority : roles.keySet()) {
				if (roles.get(authority).contains(member)) {
					member.getAuthorities().add(authority);
				}
			}
			if (!member.getAuthorities().contains(ScimGroup.Authority.READ)) {
				member.getAuthorities().add(ScimGroup.Authority.READ);
			}
		}
		group.setMembers(members);
		return group;
	}
}
