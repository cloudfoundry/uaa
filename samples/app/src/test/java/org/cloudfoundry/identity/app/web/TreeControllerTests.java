/*******************************************************************************
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
package org.cloudfoundry.identity.app.web;

import static org.junit.Assert.assertEquals;

import org.junit.Ignore;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.ui.ExtendedModelMap;

/**
 * @author Dave Syer
 * 
 */
public class TreeControllerTests {

    private TreeController treeController = new TreeController();

    @Test
    @Ignore
    public void testItems() throws Exception {
        ExtendedModelMap model = new ExtendedModelMap();
        treeController.apps(model, new UsernamePasswordAuthenticationToken("dave", "foo"));
        MapWrapper wrapper = new MapWrapper(model.get("items"));
        System.err.println(wrapper);
        assertEquals("spring", wrapper.get("[0].staging.model"));
    }

}
