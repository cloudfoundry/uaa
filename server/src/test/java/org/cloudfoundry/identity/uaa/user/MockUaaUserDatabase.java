
package org.cloudfoundry.identity.uaa.user;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import java.util.Collections;
import java.util.function.Function;

public class MockUaaUserDatabase extends InMemoryUaaUserDatabase {
    public MockUaaUserDatabase(Function<UaaUserPrototype, UaaUserPrototype> buildPrototype) {
        super(Collections.singleton(new UaaUser(buildPrototype.apply(
                new UaaUserPrototype()
                        .withExternalId("externalId")
                        .withAuthorities(UaaAuthority.USER_AUTHORITIES)
                        .withOrigin(OriginKeys.UAA)
                        .withZoneId(IdentityZoneHolder.get().getId())
        ))));
    }
}
