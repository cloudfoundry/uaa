package org.cloudfoundry.identity.uaa.oauth.beans;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.RedirectMismatchException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.RedirectResolver;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.assertj.core.api.HamcrestCondition.matching;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * UaaAuthorizationEndpoint uses either UAA's LegacyRedirectResolver or Spring's DefaultRedirectResolver,
 * as provided by the RedirectResolverFactoryBean. This test exists because we want to know the exact
 * behavior of both classes, we want it to be clear where their behavior differs, and because we want
 * to be made aware immediately by unit test failures if there is any behavior change in
 * DefaultRedirectResolver whenever we upgrade the library from which it comes (it changed a lot between
 * v2.3.0 and v2.3.5, for example).
 */
class RedirectResolverTest {
    private RedirectResolver legacyResolver;
    private RedirectResolver springResolver;
    private ClientDetails mockClientDetails;

    @BeforeEach
    void setUp() {
        legacyResolver = new RedirectResolverFactoryBean(true).getObject();
        springResolver = new RedirectResolverFactoryBean(false).getObject();
        mockClientDetails = mock(UaaClientDetails.class);
        when(mockClientDetails.getAuthorizedGrantTypes()).thenReturn(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
    }

    @Test
    void resolveWithDifferentHostCase() {
        mockRegisteredRedirectUri("http://ALL.CAPS.example.com");

        assertResolveRedirect("http://all.caps.example.com",
                is("http://all.caps.example.com"),
                is("http://ALL.CAPS.example.com"));
    }

    @Test
    void resolveWithDifferentSchemeCase() {
        mockRegisteredRedirectUri("HTTP://example.com");

        assertResolveRedirect("http://example.com",
                is("http://example.com"),
                //Spring Upgrade 6.x changes scheme to lowercase UriComponentsBuilder
                is("http://example.com"));
    }

    @Test
    void resolveClientWithUrlWhichHasNoWildcardsAndDoesNotEndInSlash() {
        mockRegisteredRedirectUri("http://uaa.com");

        assertResolveRedirect("http://uaa.com#fragment", is("http://uaa.com#fragment"), is("http://uaa.com"));
        assertResolveRedirect("http://uaa.com", is("http://uaa.com"));
        assertResolveRedirect("http://user:pass@uaa.com", is("http://user:pass@uaa.com"), shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz", is("http://uaa.com/xyz"), shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz/abc/1234", is("http://uaa.com/xyz/abc/1234"), shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com", is("http://subdomain.uaa.com"), shouldThrow());
        assertResolveRedirect("http://subdomain1.subdomain2.subdomain3.uaa.com", is("http://subdomain1.subdomain2.subdomain3.uaa.com"), shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz?foo=bar", is("http://uaa.com/xyz?foo=bar"), shouldThrow());
        assertResolveRedirect("http://uaa.com?foo=bar", is("http://uaa.com?foo=bar"), is("http://uaa.com?foo=bar"));
        assertResolveRedirect("http://uaa.com/xyz?foo=bar#fragment", is("http://uaa.com/xyz?foo=bar#fragment"), shouldThrow());
        assertResolveRedirect("http://uaa.com:8080", shouldThrow());
        assertResolveRedirect("https://uaa.com", shouldThrow());
    }

    @Test
    void resolveClientWithUrlWhichHasNoWildcardsAndHasQueryParam() {
        mockRegisteredRedirectUri("http://uaa.com?a=x&b=y");

        // matches with DefaultRedirectResolver because it is an exact match
        assertResolveRedirect("http://uaa.com?a=x&b=y", shouldThrow(), is("http://uaa.com?a=x&b=y"));

        // matches with DefaultRedirectResolver because has all configured query params and extra query params are ok
        assertResolveRedirect("http://uaa.com?a=x&b=y&foo=bar", shouldThrow(), is("http://uaa.com?a=x&b=y&foo=bar"));

        // matches with DefaultRedirectResolver because query params are exact same keys and value in a different order
        assertResolveRedirect("http://uaa.com?b=y&a=x", shouldThrow(), is("http://uaa.com?b=y&a=x"));

        assertResolveRedirect("http://uaa.com", shouldThrow()); // new matcher needs to have at least ?a=x&b=y
        assertResolveRedirect("http://uaa.com?z=x&b=y", shouldThrow()); // new matcher needs to have at least ?a=x&b=y
    }

    @Test
    void resolveClientWithUrlWhichHasNoWildcardsAndHasPath() {
        mockRegisteredRedirectUri("http://uaa.com/a/b/c");

        assertResolveRedirect("http://uaa.com/a/b/c", is("http://uaa.com/a/b/c"));
        assertResolveRedirect("http://uaa.com/a/./b/./c/.", is("http://uaa.com/a/./b/./c/."), is("http://uaa.com/a/b/c"));
        assertResolveRedirect("http://uaa.com/a/b/c/../c", is("http://uaa.com/a/b/c/../c"), is("http://uaa.com/a/b/c"));
        assertResolveRedirect("http://uaa.com/a/b/../b/c", is("http://uaa.com/a/b/../b/c"), is("http://uaa.com/a/b/c"));
        assertResolveRedirect("http://uaa.com/a/b/c/", is("http://uaa.com/a/b/c/"), shouldThrow());

        mockRegisteredRedirectUri("http://uaa.com/a/b/c/"); // note the trailing slash

        assertResolveRedirect("http://uaa.com/a/b/c/", is("http://uaa.com/a/b/c/"));
        assertResolveRedirect("http://uaa.com/a/./b/./c/./", is("http://uaa.com/a/./b/./c/./"), is("http://uaa.com/a/b/c/"));
        assertResolveRedirect("http://uaa.com/a/./b/./c/.", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/b/c/../c", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/b/../b/c", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/b/c", shouldThrow());
    }

    @Test
    void allSubpathsMatchUsingLegacyMatcher() {
        mockRegisteredRedirectUri("http://example.com/foo");

        assertResolveRedirect("http://example.com/foo", is("http://example.com/foo"));
        assertResolveRedirect("http://example.com/foo/", is("http://example.com/foo/"), shouldThrow());
        assertResolveRedirect("http://example.com/foo/bar", is("http://example.com/foo/bar"), shouldThrow());
        assertResolveRedirect("http://example.com/foo/bar/baz", is("http://example.com/foo/bar/baz"), shouldThrow());
        assertResolveRedirect("http://example.com/foo/../foo/../foo", is("http://example.com/foo/../foo/../foo"), is("http://example.com/foo"));
        assertResolveRedirect("http://example.com/foo/..", shouldThrow());
        assertResolveRedirect("http://example.com/bar", shouldThrow());
    }

    @Test
    void resolveClientWithUrlWhichHasPortAndHasNoWildcardsAndDoesNotEndInSlash() {
        mockRegisteredRedirectUri("http://uaa.com:8080");

        assertResolveRedirect("http://uaa.com:8080", is("http://uaa.com:8080"));
        assertResolveRedirect("http://uaa.com:8080", is("http://uaa.com:8080"));
        assertResolveRedirect("http://user:pass@uaa.com:8080", is("http://user:pass@uaa.com:8080"), shouldThrow());
        assertResolveRedirect("http://uaa.com:8080/xyz", is("http://uaa.com:8080/xyz"), shouldThrow());
        assertResolveRedirect("http://uaa.com:8080/xyz/abc/1234", is("http://uaa.com:8080/xyz/abc/1234"), shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com:8080", is("http://subdomain.uaa.com:8080"), shouldThrow());
        assertResolveRedirect("http://subdomain1.subdomain2.subdomain3.uaa.com:8080", is("http://subdomain1.subdomain2.subdomain3.uaa.com:8080"), shouldThrow());
        assertResolveRedirect("http://uaa.com:8080/xyz?foo=bar", is("http://uaa.com:8080/xyz?foo=bar"), shouldThrow());
        assertResolveRedirect("http://uaa.com:8080?foo=bar", is("http://uaa.com:8080?foo=bar"));
        assertResolveRedirect("http://uaa.com:8080/xyz?foo=bar#fragment", is("http://uaa.com:8080/xyz?foo=bar#fragment"), shouldThrow());
        assertResolveRedirect("http://uaa.com:8080?foo=bar#fragment", is("http://uaa.com:8080?foo=bar#fragment"), is("http://uaa.com:8080?foo=bar"));
        assertResolveRedirect("http://uaa.com:8081", shouldThrow());
        assertResolveRedirect("https://uaa.com:8080", shouldThrow());
    }

    @Test
    void resolveClientWithUrlWhichHasNoWildcardsAndDoesEndInSlash() {
        mockRegisteredRedirectUri("http://uaa.com/");

        assertResolveRedirect("http://uaa.com/", is("http://uaa.com/"));
        assertResolveRedirect("http://user:pass@uaa.com/", is("http://user:pass@uaa.com/"), shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz", is("http://uaa.com/xyz"), shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz/abc/1234", is("http://uaa.com/xyz/abc/1234"), shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com/", is("http://subdomain.uaa.com/"), shouldThrow());
        assertResolveRedirect("http://subdomain1.subdomain2.subdomain3.uaa.com/", is("http://subdomain1.subdomain2.subdomain3.uaa.com/"), shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz?foo=bar", is("http://uaa.com/xyz?foo=bar"), shouldThrow());
        assertResolveRedirect("http://uaa.com/?foo=bar", is("http://uaa.com/?foo=bar"));
        assertResolveRedirect("http://uaa.com/xyz?foo=bar#fragment", is("http://uaa.com/xyz?foo=bar#fragment"), shouldThrow());
        assertResolveRedirect("http://uaa.com/?foo=bar#fragment", is("http://uaa.com/?foo=bar#fragment"), is("http://uaa.com/?foo=bar"));
        assertResolveRedirect("http://uaa.com:8080", shouldThrow());
        assertResolveRedirect("http://uaa.com", shouldThrow());
        assertResolveRedirect("http://uaa.com?foo=bar", shouldThrow());
        assertResolveRedirect("http://uaa.com#foo", shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com", shouldThrow());
        assertResolveRedirect("http://subdomain1.subdomain2.uaa.com", shouldThrow());
        assertResolveRedirect("https://uaa.com", shouldThrow());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://*.uaa.com",
            "http://**.uaa.com"
    })
    void resolveClientWithUrlWhichHasWildcardsOrDoubleWildcardsInTheSubdomainAndDoesNotEndInSlash(String uriPattern) {
        mockRegisteredRedirectUri(uriPattern);

        assertResolveRedirect("http://subdomain.uaa.com", is("http://subdomain.uaa.com"), shouldThrow());
        assertResolveRedirect("http://subdomain1.subdomain2.uaa.com", is("http://subdomain1.subdomain2.uaa.com"), shouldThrow());
        assertResolveRedirect("http://subdomain1.subdomain2.subdomain3.uaa.com", is("http://subdomain1.subdomain2.subdomain3.uaa.com"), shouldThrow());
        assertResolveRedirect("http://user:pass@subdomain.uaa.com", is("http://user:pass@subdomain.uaa.com"), shouldThrow());

        assertResolveRedirect("http://subdomain.evil.com/domain.uaa.com", shouldThrow());
        assertResolveRedirect("http://evil.com/domain.uaa.com", shouldThrow());
        assertResolveRedirect("http://evil.com/uaa.com", shouldThrow());

        assertResolveRedirect("http://subdomain.uaa.com/xyz", shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com/xyz/abc/1234", shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com/xyz?foo=bar", shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com/?foo=bar", shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com?foo=bar", shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com/xyz?foo=bar#fragment", shouldThrow());

        assertResolveRedirect("http://subdomain.uaa.com:8080", shouldThrow());
        assertResolveRedirect("http://uaa.com", shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com#foo", shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com/", shouldThrow());
        assertResolveRedirect("https://subdomain.uaa.com", shouldThrow());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://sub*.uaa.com",
            "http://sub**.uaa.com"
    })
    void resolveClientWithUrlWhichHasConstrainedWildcardsOrDoubleWildcardsInTheSubdomainAndDoesNotEndInSlash(String uriPattern) {
        mockRegisteredRedirectUri(uriPattern);

        assertResolveRedirect("http://subdomain.uaa.com", is("http://subdomain.uaa.com"), shouldThrow());
        assertResolveRedirect("http://subdomain1.subdomain2.uaa.com", is("http://subdomain1.subdomain2.uaa.com"), shouldThrow());
        assertResolveRedirect("http://subdomain1.subdomain2.subdomain3.uaa.com", is("http://subdomain1.subdomain2.subdomain3.uaa.com"), shouldThrow());
        assertResolveRedirect("http://user:pass@subdomain.uaa.com", shouldThrow());
        assertResolveRedirect("http://other.uaa.com", shouldThrow());
    }

    @Test
    void resolveClientWithUrlWhichHasWildcardAsThePath() {
        mockRegisteredRedirectUri("http://uaa.com/*");

        assertResolveRedirect("http://uaa.com/", is("http://uaa.com/"), shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz", is("http://uaa.com/xyz"), shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz?foo=bar", is("http://uaa.com/xyz?foo=bar"), shouldThrow());
        assertResolveRedirect("http://uaa.com/?foo=bar", is("http://uaa.com/?foo=bar"), shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz?foo=bar#fragment", is("http://uaa.com/xyz?foo=bar#fragment"), shouldThrow());
        assertResolveRedirect("http://uaa.com/#fragment", is("http://uaa.com/#fragment"), shouldThrow());

        assertResolveRedirect("http://uaa.com", shouldThrow());
        assertResolveRedirect("http://user:pass@uaa.com", shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz/abc/1234", shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com/", shouldThrow());
        assertResolveRedirect("http://subdomain1.subdomain2.subdomain3.uaa.com/", shouldThrow());
        assertResolveRedirect("http://uaa.com:8080", shouldThrow());
        assertResolveRedirect("http://uaa.com?foo=bar", shouldThrow());
        assertResolveRedirect("http://uaa.com#foo", shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com", shouldThrow());
        assertResolveRedirect("http://subdomain1.subdomain2.uaa.com", shouldThrow());
        assertResolveRedirect("https://uaa.com", shouldThrow());
        assertResolveRedirect("https://uaa.com/", shouldThrow());
    }

    @Test
    void resolveClientWithUrlWhichHasWildcardInThePath() {
        mockRegisteredRedirectUri("http://uaa.com/a/*/b");

        assertResolveRedirect("http://uaa.com/a/zzz/b", is("http://uaa.com/a/zzz/b"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zzz/b?foo=bar", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zzz/b#fragment", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/b", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/b/c", shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz", shouldThrow());
        assertResolveRedirect("http://uaa.com", shouldThrow());
        assertResolveRedirect("http://user:pass@uaa.com/a/zzz/b", shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com/a/zzz/b", shouldThrow());
        assertResolveRedirect("http://subdomain1.subdomain2.subdomain3.uaa.com/a/zzz/b", shouldThrow());
        assertResolveRedirect("http://uaa.com:8080/a/zzz/b", shouldThrow());
        assertResolveRedirect("https://uaa.com/a/zzz/b", shouldThrow());

        mockRegisteredRedirectUri("http://uaa.com/a/z*z/b");

        assertResolveRedirect("http://uaa.com/a/zz/b", is("http://uaa.com/a/zz/b"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zxz/b", is("http://uaa.com/a/zxz/b"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zxxxxz/b", is("http://uaa.com/a/zxxxxz/b"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/z?foo=baz/b", is("http://uaa.com/a/z?foo=baz/b"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/z/z/b", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zxz/b?foo=bar", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zxz/b#foo", shouldThrow());

        mockRegisteredRedirectUri("http://uaa.com/a/z*z/b*c");

        assertResolveRedirect("http://uaa.com/a/zz/bc", is("http://uaa.com/a/zz/bc"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zxz/bxc", is("http://uaa.com/a/zxz/bxc"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zz/b/c", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zxz/bxc?foo=bar", shouldThrow());

        mockRegisteredRedirectUri("http://uaa.com/a/b*");

        assertResolveRedirect("http://uaa.com/a/b", is("http://uaa.com/a/b"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/bzzz", is("http://uaa.com/a/bzzz"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/b?foo=bar", is("http://uaa.com/a/b?foo=bar"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/b#foo", is("http://uaa.com/a/b#foo"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/b/c", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/b/c?foo=bar", shouldThrow());
    }

    @Test
    void resolveClientWithUrlWhichHasDoubleWildcardAsThePath() {
        mockRegisteredRedirectUri("http://uaa.com/**");

        assertResolveRedirect("http://uaa.com", is("http://uaa.com"), shouldThrow());
        assertResolveRedirect("http://uaa.com/", is("http://uaa.com/"), shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz", is("http://uaa.com/xyz"), shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz?foo=bar", is("http://uaa.com/xyz?foo=bar"), shouldThrow());
        assertResolveRedirect("http://uaa.com/?foo=bar", is("http://uaa.com/?foo=bar"), shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz?foo=bar#fragment", is("http://uaa.com/xyz?foo=bar#fragment"), shouldThrow());
        assertResolveRedirect("http://uaa.com/#fragment", is("http://uaa.com/#fragment"), shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz/abc/1234", is("http://uaa.com/xyz/abc/1234"), shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz/abc/1234?foo=bar", is("http://uaa.com/xyz/abc/1234?foo=bar"), shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz/abc/1234?foo=bar#fragment", is("http://uaa.com/xyz/abc/1234?foo=bar#fragment"), shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz/abc/1234#fragment", is("http://uaa.com/xyz/abc/1234#fragment"), shouldThrow());

        assertResolveRedirect("http://user:pass@uaa.com", shouldThrow());
        assertResolveRedirect("http://user:pass@uaa.com/", shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com", shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com/", shouldThrow());
        assertResolveRedirect("http://subdomain1.subdomain2.subdomain3.uaa.com/", shouldThrow());
        assertResolveRedirect("http://uaa.com:8080", shouldThrow());
        assertResolveRedirect("http://uaa.com:8080/", shouldThrow());
        assertResolveRedirect("http://uaa.com?foo=bar", shouldThrow());
        assertResolveRedirect("http://uaa.com#foo", shouldThrow());
        assertResolveRedirect("https://uaa.com", shouldThrow());
        assertResolveRedirect("https://uaa.com/", shouldThrow());
    }

    @Test
    void resolveClientWithUrlWhichHasDoubleWildcardInThePath() {
        // note that this case works as you might expect, but the other cases below work as if you had used a single '*'
        mockRegisteredRedirectUri("http://uaa.com/a/**/b");

        assertResolveRedirect("http://uaa.com/a/b", is("http://uaa.com/a/b"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zzz/b", is("http://uaa.com/a/zzz/b"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/c/d/e/f/b", is("http://uaa.com/a/c/d/e/f/b"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zzz/b?foo=bar", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zzz/b#fragment", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/b/c", shouldThrow());
        assertResolveRedirect("http://uaa.com/xyz", shouldThrow());
        assertResolveRedirect("http://uaa.com", shouldThrow());
        assertResolveRedirect("http://user:pass@uaa.com/a/zzz/b", shouldThrow());
        assertResolveRedirect("http://subdomain.uaa.com/a/zzz/b", shouldThrow());
        assertResolveRedirect("http://subdomain1.subdomain2.subdomain3.uaa.com/a/zzz/b", shouldThrow());
        assertResolveRedirect("http://uaa.com:8080/a/zzz/b", shouldThrow());
        assertResolveRedirect("https://uaa.com/a/zzz/b", shouldThrow());

        mockRegisteredRedirectUri("http://uaa.com/a/z**z/b");

        assertResolveRedirect("http://uaa.com/a/zz/b", is("http://uaa.com/a/zz/b"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zxz/b", is("http://uaa.com/a/zxz/b"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zxxxxz/b", is("http://uaa.com/a/zxxxxz/b"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/z?foo=baz/b", is("http://uaa.com/a/z?foo=baz/b"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/z/x/z/b", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zxx/xx/xxz/b", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/z/z/b", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zxz/b?foo=bar", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zxz/b#foo", shouldThrow());

        mockRegisteredRedirectUri("http://uaa.com/a/z**z/b**c");

        assertResolveRedirect("http://uaa.com/a/zz/bc", is("http://uaa.com/a/zz/bc"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zxz/bxc", is("http://uaa.com/a/zxz/bxc"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/z/x/z/b/x/c", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zz/b/c", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/zxz/bxc?foo=bar", shouldThrow());

        mockRegisteredRedirectUri("http://uaa.com/a/b**");

        assertResolveRedirect("http://uaa.com/a/b", is("http://uaa.com/a/b"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/bzzz", is("http://uaa.com/a/bzzz"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/b?foo=bar", is("http://uaa.com/a/b?foo=bar"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/b#foo", is("http://uaa.com/a/b#foo"), shouldThrow());
        assertResolveRedirect("http://uaa.com/a/b/c", shouldThrow());
        assertResolveRedirect("http://uaa.com/a/b/c?foo=bar", shouldThrow());
    }

    private void mockRegisteredRedirectUri(String allowedRedirectUri) {
        when(mockClientDetails.getRegisteredRedirectUri()).thenReturn(Collections.singleton(allowedRedirectUri));
    }

    private Class<RedirectMismatchException> shouldThrow() {
        return RedirectMismatchException.class;
    }

    // For when the new and legacy implementations should both have the same return value
    private void assertResolveRedirect(String requestedRedirect, Matcher<? super String> matcherForBothNewAndLegacyResult) {
        assertThat(legacyResolver.resolveRedirect(requestedRedirect, mockClientDetails))
                .as("test failed for " + legacyResolver.getClass().getSimpleName())
                .is(matching(matcherForBothNewAndLegacyResult));

        assertThat(springResolver.resolveRedirect(requestedRedirect, mockClientDetails))
                .as("test failed for " + springResolver.getClass().getSimpleName())
                .is(matching(matcherForBothNewAndLegacyResult));
    }

    // For when the new and legacy implementations should have different return values, but neither throws
    private void assertResolveRedirect(String requestedRedirect, Matcher<? super String> matcherForLegacyResult, Matcher<? super String> matcherForNewResult) {
        assertThat(legacyResolver.resolveRedirect(requestedRedirect, mockClientDetails))
                .as("test failed for " + legacyResolver.getClass().getSimpleName())
                .is(matching(matcherForLegacyResult));

        assertThat(springResolver.resolveRedirect(requestedRedirect, mockClientDetails))
                .as("test failed for " + springResolver.getClass().getSimpleName())
                .is(matching(matcherForNewResult));
    }

    // For when the new and legacy implementations should both throw
    private void assertResolveRedirect(String requestedRedirect, Class<? extends Throwable> expectedExceptionClassForBothNewAndLegacyResult) {
        assertThatExceptionOfType(expectedExceptionClassForBothNewAndLegacyResult).isThrownBy(() -> legacyResolver.resolveRedirect(requestedRedirect, mockClientDetails));
        assertThatExceptionOfType(expectedExceptionClassForBothNewAndLegacyResult).isThrownBy(() -> springResolver.resolveRedirect(requestedRedirect, mockClientDetails));
    }

    // For when only the new implementation should throw
    private void assertResolveRedirect(String requestedRedirect, Matcher<? super String> matcherForLegacyResult, Class<? extends Throwable> expectedExceptionClassForNewResult) {
        assertThat(legacyResolver.resolveRedirect(requestedRedirect, mockClientDetails))
                .as("test failed for " + legacyResolver.getClass().getSimpleName())
                .is(matching(matcherForLegacyResult));

        assertThatExceptionOfType(expectedExceptionClassForNewResult).isThrownBy(() -> springResolver.resolveRedirect(requestedRedirect, mockClientDetails));
    }

    // For when only the legacy implementation should throw
    private void assertResolveRedirect(String requestedRedirect, Class<? extends Throwable> expectedExceptionClassForLegacyResult, Matcher<? super String> matcherForNewResult) {
        assertThatExceptionOfType(expectedExceptionClassForLegacyResult).isThrownBy(() -> legacyResolver.resolveRedirect(requestedRedirect, mockClientDetails));

        assertThat(springResolver.resolveRedirect(requestedRedirect, mockClientDetails))
                .as("test failed for " + springResolver.getClass().getSimpleName())
                .is(matching(matcherForNewResult));
    }
}
