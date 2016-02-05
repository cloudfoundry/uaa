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

package org.cloudfoundry.identity.uaa.client;

import static org.junit.Assert.assertEquals;

import org.cloudfoundry.identity.uaa.client.SocialClientUserDetails.Source;
import org.junit.Test;

/**
 * @author Dave Syer
 * 
 */
public class SourceTests {

    @Test
    public void testClassifyWellKnownValues() {
        assertEquals(Source.CLOUD_FOUNDRY, Source.classify("http://foo.cloudfoundry.com/userinfo"));
        assertEquals(Source.GITHUB, Source.classify("http://foo.github.com/userinfo"));
        assertEquals(Source.TWITTER, Source.classify("http://foo.twitter.com/userinfo"));
        assertEquals(Source.LINKEDIN, Source.classify("http://foo.linkedin.com/userinfo"));
        assertEquals(Source.GOOGLE, Source.classify("http://foo.google.com/userinfo"));
        assertEquals(Source.GOOGLE, Source.classify("http://foo.googleapis.com/userinfo"));
    }

    @Test
    public void testClassifyTypical() {
        assertEquals("foo", Source.classify("http://www.foo.com/userinfo"));
        assertEquals("foo", Source.classify("http://www.foo.net/userinfo"));
        assertEquals("foo", Source.classify("http://foo.com/userinfo"));
        assertEquals("foo", Source.classify("http://www.foo.net"));
    }

    @Test
    public void testClassifyTwoPartTopLevel() {
        assertEquals("foo", Source.classify("http://www.foo.co.uk/userinfo"));
    }

}
