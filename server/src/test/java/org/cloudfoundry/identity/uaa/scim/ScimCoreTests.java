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
package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

class ScimCoreTests {

    @Test
    void equals() {
        ScimCore c1 = new ScimUser("c1", "c1", null, null);
        ScimCore c2 = new ScimGroup("c1", null, IdentityZoneHolder.get().getId());
        ScimCore c3 = new ScimUser();
        ScimCore c4 = new ScimGroup();

        assertThat(c1).isNotSameAs(c3)
                .isNotEqualTo("c2");

        assertThat(c2).isNotSameAs(c4)
                .isEqualTo("c1") //NOSONAR equals takes ScimCore or String to check id equals
                .isEqualTo(c1);
        assertThat(c3).isNotSameAs(c4);
    }

    @Test
    void patch() {
        ScimCore c1 = new ScimGroup("Test");
        ScimCore c2 = new ScimGroup();
        ScimMeta meta1 = c1.getMeta();
        ScimMeta meta2 = c2.getMeta();
        Date meta2Timestamp = meta2.getCreated();
        meta1.setCreated(new Date());
        meta1.setVersion(0);
        meta2.setVersion(1);
        meta2.setAttributes(new String[]{"Description"});
        c2.patch(c1);
        assertThat(c2.getMeta().getCreated()).isEqualTo(meta2Timestamp);
        assertThat(meta2.getVersion()).isOne();
        assertThat(meta2.getAttributes()).hasSize(1);
        assertThat(meta2.getAttributes()[0]).isEqualTo("Description");
    }
}
