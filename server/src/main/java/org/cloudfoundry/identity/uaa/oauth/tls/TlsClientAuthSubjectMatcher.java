package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;

import java.security.cert.X509Certificate;

/** RFC 8705 section 2.1.2 subject binding. Not implemented yet: nothing matches. */
public final class TlsClientAuthSubjectMatcher {

    private TlsClientAuthSubjectMatcher() {
    }

    public static boolean matches(X509Certificate cert, TlsClientAuthConfiguration config) {
        return false;
    }

    public static boolean matchesTrustedProxy(X509Certificate cert, TlsClientAuthConfiguration config) {
        return false;
    }
}
