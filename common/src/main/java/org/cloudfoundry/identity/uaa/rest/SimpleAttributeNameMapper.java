package org.cloudfoundry.identity.uaa.rest;

import java.util.Collections;
import java.util.Map;

public class SimpleAttributeNameMapper implements AttributeNameMapper {

	private Map<String, String> paramsMap = Collections.<String, String>emptyMap();

	public SimpleAttributeNameMapper(Map<String, String> paramsMap) {
		this.paramsMap = paramsMap;
	}

	@Override
	public String mapToInternal(String attr) {
		String mappedAttr = attr;
		for (Map.Entry<String, String> entry : paramsMap.entrySet()) {
			mappedAttr = mappedAttr.replaceAll(entry.getKey(), entry.getValue());
		}
		return mappedAttr;
	}

	@Override
	public String[] mapToInternal(String[] attr) {
		String[] result = new String[attr.length];
		int x = 0;
		for (String a : attr) {
			result[x++] = mapToInternal(a);
		}
		return result;
	}

	@Override
	public String mapFromInternal(String attr) {
		String mappedAttr = attr;
		for (Map.Entry<String, String> entry : paramsMap.entrySet()) {
			mappedAttr = mappedAttr.replaceAll(entry.getValue(), entry.getKey());
		}
		return mappedAttr;
	}

	@Override
	public String[] mapFromInternal(String[] attr) {
		String[] result = new String[attr.length];
		int x = 0;
		for (String a : attr) {
			result[x++] = mapFromInternal(a);
		}
		return result;
	}
}
