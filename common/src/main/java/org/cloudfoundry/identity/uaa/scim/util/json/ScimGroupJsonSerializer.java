package org.cloudfoundry.identity.uaa.scim.util.json;

import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.codehaus.jackson.JsonGenerator;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.map.JsonSerializer;
import org.codehaus.jackson.map.SerializerProvider;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ScimGroupJsonSerializer extends JsonSerializer<ScimGroup> {

	@Override
	public void serialize(ScimGroup group, JsonGenerator jgen, SerializerProvider provider) throws IOException, JsonProcessingException {
		Map<String, List<ScimGroupMember>> roles = new HashMap<String, List<ScimGroupMember>>();
		for (ScimGroup.Authority authority : ScimGroup.Authority.values()) {
			String role = authority.getRoleName()+"s";
			roles.put(role, new ArrayList<ScimGroupMember>());
			for (ScimGroupMember member : group.getMembers()) {
				if (member.getAuthorities().contains(authority)) {
					roles.get(role).add(member);
				}
			}
		}

		Map<Object, Object> groupJson = new HashMap<Object, Object>();
		groupJson.put("meta", group.getMeta());
		groupJson.put("schemas", group.getSchemas());
		groupJson.put("id", group.getId());
		groupJson.put("displayName", group.getDisplayName());
		groupJson.put("members", group.getMembers());
		groupJson.putAll(roles);

		jgen.writeObject(groupJson);

	}
}
