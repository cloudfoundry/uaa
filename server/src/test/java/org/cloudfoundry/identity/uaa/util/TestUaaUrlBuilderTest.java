package org.cloudfoundry.identity.uaa.util;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.test.util.ReflectionTestUtils;

public class TestUaaUrlBuilderTest {

    private TestUaaUrlBuilder builder;

    @Before
    public void setup() {
        builder = new TestUaaUrlBuilder();
        ReflectionTestUtils.setField(builder, "systemDomain", "foo.cf.com");
    }

    @Test(expected = RuntimeException.class)
    public void informativeError_whenNoSystemDomain() {
        ReflectionTestUtils.setField(builder, "systemDomain", "");
        builder.build();
    }

    @Test
    public void build_returnsUaaUrl() {
        String url = builder.build();
        Assert.assertEquals("https://uaa.foo.cf.com/", url);
    }

    @Test
    public void setScheme_canChangeScheme() {
        String url = builder.withScheme("http").build();
        Assert.assertEquals("http://uaa.foo.cf.com/", url);
    }

    @Test
    public void setPath_canAddPathStuff() {
        String url = builder.withPath("/oauth/authorize").build();
        Assert.assertEquals("https://uaa.foo.cf.com/oauth/authorize", url);
    }

    @Test
    public void setSubdomain_canAddSubdomain() {
        String url = builder.withSubdomain("my-zone").build();
        Assert.assertEquals("https://my-zone.uaa.foo.cf.com/", url);
    }

    @Test
    public void stringingItAllTogether() {
        String url = builder.withScheme("http")
                            .withPath("/oauth/authorize")
                            .withSubdomain("my-zone").build();
        Assert.assertEquals("http://my-zone.uaa.foo.cf.com/oauth/authorize", url);
    }


    @Test
    public void handlesExtraSlashesProperly() {
        ReflectionTestUtils.setField(builder, "systemDomain", "foo.cf.com/");
        String url = builder.withPath("/oauth/authorize").build();
        Assert.assertEquals("https://uaa.foo.cf.com/oauth/authorize", url);

        ReflectionTestUtils.setField(builder, "systemDomain", "foo.cf.com/");
        String url2 = builder.withPath("oauth/authorize").build();
        Assert.assertEquals("https://uaa.foo.cf.com/oauth/authorize", url2);

        ReflectionTestUtils.setField(builder, "systemDomain", "foo.cf.com");
        String url3 = builder.withPath("oauth/authorize").build();
        Assert.assertEquals("https://uaa.foo.cf.com/oauth/authorize", url3);
    }
}
