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

package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.client.SocialClientUserDetails.Source;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Dave Syer
 */
class SourceTests {

    @Test
    void classifyWellKnownValues() {
        assertThat(Source.classify("http://foo.cloudfoundry.com/userinfo")).isEqualTo(Source.CLOUD_FOUNDRY);
        assertThat(Source.classify("http://foo.github.com/userinfo")).isEqualTo(Source.GITHUB);
        assertThat(Source.classify("http://foo.twitter.com/userinfo")).isEqualTo(Source.TWITTER);
        assertThat(Source.classify("http://foo.linkedin.com/userinfo")).isEqualTo(Source.LINKEDIN);
        assertThat(Source.classify("http://foo.google.com/userinfo")).isEqualTo(Source.GOOGLE);
        assertThat(Source.classify("http://foo.googleapis.com/userinfo")).isEqualTo(Source.GOOGLE);
    }

    @Test
    void classifyTypical() {
        assertThat(Source.classify("http://www.foo.com/userinfo")).isEqualTo("foo");
        assertThat(Source.classify("http://www.foo.net/userinfo")).isEqualTo("foo");
        assertThat(Source.classify("http://foo.com/userinfo")).isEqualTo("foo");
        assertThat(Source.classify("http://www.foo.net")).isEqualTo("foo");
    }

    @Test
    void classifyTwoPartTopLevel() {
        assertThat(Source.classify("http://www.foo.co.uk/userinfo")).isEqualTo("foo");
    }

}
