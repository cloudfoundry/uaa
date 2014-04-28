/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

import org.cloudfoundry.identity.uaa.scim.domain.ScimCoreInterface;
import org.cloudfoundry.identity.uaa.scim.domain.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.domain.ScimUser;
import org.junit.Test;

public class ScimCoreTests {

    @Test
    public void testEquals() {
        ScimCoreInterface c1 = new ScimUser("c1", "c1", null, null);
        ScimCoreInterface c2 = new ScimGroup("c1", null);
        ScimCoreInterface c3 = new ScimUser();
        ScimCoreInterface c4 = new ScimGroup();

        assertEquals(c1, c2);
        assertNotSame(c1, c3);
        assertNotSame(c2, c4);
        assertNotSame(c3, c4);
        assertTrue(c2.equals("c1"));
        assertFalse(c1.equals("c2"));
    }
}
