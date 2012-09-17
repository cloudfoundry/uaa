package org.cloudfoundry.identity.uaa.scim;

/**
 * Helper to map attribute names between json requests/responses and the actual SCIM objects on the server.
 */
public interface AttributeNameMapper {

	String map (String attr);

	String[] map (String[] attr);

}
