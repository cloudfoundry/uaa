package org.cloudfoundry.identity.uaa.spiffe;

/** Org/space/app GUIDs extracted from a Diego instance-identity certificate. */
public record CfInstanceIdentity(String orgId, String spaceId, String appId) {
}
