package org.cloudfoundry.identity.uaa.scim;

import java.util.*;

public class SimpleAttributeNameMapper implements AttributeNameMapper {

	private Map<String, String> paramsMap = Collections.<String, String>emptyMap();

	public SimpleAttributeNameMapper(Map<String, String> paramsMap) {
		this.paramsMap = paramsMap;
	}

	@Override
	public String map(String attr) {
		String mappedAttr = attr;
		for (Map.Entry<String, String> entry : paramsMap.entrySet()) {
			mappedAttr = mappedAttr.replaceAll(entry.getKey(), entry.getValue());
		}
		return mappedAttr;
	}

	@Override
	public String[] map(String[] attr) {
		String[] result = new String[attr.length];
		int x = 0;
		for (String a : attr) {
			result[x++] = map(a);
		}
		return result;
	}
}
