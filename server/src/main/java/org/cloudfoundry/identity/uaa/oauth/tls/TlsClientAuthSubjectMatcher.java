package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;

import java.security.cert.X509Certificate;

/**
 * Compares a presented client certificate against the single expected subject value configured for
 * a client, per RFC 8705 section 2.1.2.
 *
 * <p>Chain validation (see {@link TlsClientAuthentication#validateClientCert}) establishes only
 * that the certificate was issued by the configured CA. Section 2.1 makes the subject the thing
 * that identifies the client: the client "is successfully authenticated if the subject information
 * in the certificate matches the single expected subject configured or registered for that
 * particular client". Without this comparison, every certificate a shared CA ever issued
 * authenticates as every client trusting that CA.
 */
public final class TlsClientAuthSubjectMatcher {

    private TlsClientAuthSubjectMatcher() {
    }

    /**
     * Whether {@code cert} carries the subject value this client is registered with.
     *
     * <p>Fails closed: an unconfigured, ambiguous (more than one parameter) or unparseable subject
     * binding is not a match.
     */
    public static boolean matches(X509Certificate cert, TlsClientAuthConfiguration config) {
        return false;
    }
}
