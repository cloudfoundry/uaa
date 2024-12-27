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
package org.cloudfoundry.identity.uaa.test;

import org.springframework.test.annotation.ProfileValueSource;
import org.springframework.util.Assert;

/**
 * Simple implementation of {@link ProfileValueSource} that returns an empty
 * String instead of a null value if the
 * property is missing, and otherwise gets it from System properties.
 * 
 * @author Dave Syer
 * 
 */
public class NullSafeSystemProfileValueSource implements ProfileValueSource {

    @Override
    public String get(String key) {
        Assert.hasText(key, "'key' must not be empty");
        return System.getProperty(key, "");
    }

}
