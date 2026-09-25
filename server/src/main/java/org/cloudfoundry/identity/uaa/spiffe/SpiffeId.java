package org.cloudfoundry.identity.uaa.spiffe;

/** Pure formatter for CF workload SPIFFE IDs. */
public final class SpiffeId {

    private SpiffeId() {
    }

    public static String format(String trustDomain, CfInstanceIdentity identity, String processType) {
        return "spiffe://" + trustDomain
                + "/cf/org/" + identity.orgId()
                + "/space/" + identity.spaceId()
                + "/app/" + identity.appId()
                + "/process/" + processType;
    }
}
