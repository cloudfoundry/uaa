/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
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
