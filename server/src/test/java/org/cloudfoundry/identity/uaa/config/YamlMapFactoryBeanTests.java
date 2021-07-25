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

package org.cloudfoundry.identity.uaa.config;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import org.cloudfoundry.identity.uaa.impl.config.YamlMapFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.YamlProcessor.ResolutionMethod;
import org.junit.Test;
import org.springframework.core.io.AbstractResource;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

/**
 * @author Dave Syer
 * 
 */
public class YamlMapFactoryBeanTests {

    private YamlMapFactoryBean factory = new YamlMapFactoryBean();

    @Test
    public void testSetIgnoreResourceNotFound() {
        factory.setResolutionMethod(YamlMapFactoryBean.ResolutionMethod.OVERRIDE_AND_IGNORE);
        factory.setResources(new FileSystemResource[] { new FileSystemResource("non-exsitent-file.yml") });
        assertEquals(0, factory.getObject().size());
    }

    @Test(expected = IllegalStateException.class)
    public void testSetBarfOnResourceNotFound() {
        factory.setResources(new FileSystemResource[] { new FileSystemResource("non-exsitent-file.yml") });
        assertEquals(0, factory.getObject().size());
    }

    @Test
    public void testGetObject() {
        factory.setResources(new ByteArrayResource[] { new ByteArrayResource("foo: bar".getBytes()) });
        assertEquals(1, factory.getObject().size());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testOverrideAndremoveDefaults() {
        factory.setResources(new ByteArrayResource[] { new ByteArrayResource("foo:\n  bar: spam".getBytes()),
                        new ByteArrayResource("foo:\n  spam: bar".getBytes()) });
        assertEquals(1, factory.getObject().size());
        assertEquals(2, ((Map<String, Object>) factory.getObject().get("foo")).size());
    }

    @Test
    public void testFirstFound() {
        factory.setResolutionMethod(ResolutionMethod.FIRST_FOUND);
        factory.setResources(new Resource[] { new AbstractResource() {
            @Override
            public String getDescription() {
                return "non-existent";
            }

            @Override
            public InputStream getInputStream() throws IOException {
                throw new IOException("planned");
            }
        }, new ByteArrayResource("foo:\n  spam: bar".getBytes()) });
        assertEquals(1, factory.getObject().size());
    }

}
