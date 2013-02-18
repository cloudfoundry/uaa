package org.cloudfoundry.identity.uaa.rest;

/**
 * Helper to map attribute names between json requests/responses and internal names that make sense on the server.
 */
public interface AttributeNameMapper {

	String mapToInternal(String attr);

	String[] mapToInternal(String[] attr);

	String mapFromInternal(String attr);

	String[] mapFromInternal(String[] attr);

}
