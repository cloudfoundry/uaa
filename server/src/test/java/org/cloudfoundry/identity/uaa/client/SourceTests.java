

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
