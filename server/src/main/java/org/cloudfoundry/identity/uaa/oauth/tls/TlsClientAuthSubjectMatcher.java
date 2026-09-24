package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.security.auth.x500.X500Principal;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

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

    private static final Logger logger = LoggerFactory.getLogger(TlsClientAuthSubjectMatcher.class);

    /** {@code GeneralName} tag numbers from RFC 5280 section 4.2.1.6, as used by the JDK. */
    private static final int SAN_RFC822_NAME = 1;
    private static final int SAN_DNS_NAME = 2;
    private static final int SAN_URI = 6;
    private static final int SAN_IP_ADDRESS = 7;

    private TlsClientAuthSubjectMatcher() {
    }

    /**
     * Whether {@code cert} carries the subject value this client is registered with.
     *
     * <p>Fails closed: an unconfigured, ambiguous (more than one parameter) or unparseable subject
     * binding is not a match.
     */
    public static boolean matches(X509Certificate cert, TlsClientAuthConfiguration config) {
        if (cert == null || config == null) {
            return false;
        }
        List<String> configured = config.configuredSubjectBindings();
        if (configured.size() != 1) {
            // RFC 8705 2.1.2 permits exactly one. Zero means nothing identifies the client; more
            // than one is ambiguous and the spec does not define how to combine them, so rather
            // than pick an interpretation (any-of would be weaker than either alone) refuse.
            logger.debug("tls_client_auth: expected exactly one subject binding parameter, found {}", configured);
            return false;
        }
        return switch (configured.getFirst()) {
            case TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN ->
                    subjectDnMatches(cert, config.getSubjectDn());
            case TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS ->
                    sanMatches(cert, SAN_DNS_NAME, config.getSanDns(), TlsClientAuthSubjectMatcher::equalsIgnoreCase);
            case TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_URI ->
                    sanMatches(cert, SAN_URI, config.getSanUri(), String::equals);
            case TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_EMAIL ->
                    sanMatches(cert, SAN_RFC822_NAME, config.getSanEmail(), String::equals);
            case TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_IP ->
                    sanMatches(cert, SAN_IP_ADDRESS, config.getSanIp(), TlsClientAuthSubjectMatcher::ipAddressesEqual);
            default -> false;
        };
    }

    /**
     * Compares the certificate's subject DN with the registered one.
     *
     * <p>RFC 8705 section 2.1 calls for "a predictable treatment of DN values, such as the
     * distinguishedNameMatch rule from [RFC4517]". {@link LdapName} provides that: it parses the
     * RFC 4514 string form and compares RDN-by-RDN with case-insensitive attribute types, which
     * makes formatting differences (spacing after commas, {@code CN} vs {@code cn}) insignificant
     * while keeping RDN order significant -- a DN is an ordered sequence, and reordering it names
     * a different directory entry.
     *
     * <p>The certificate side is rendered with {@link X500Principal#RFC2253} rather than read as a
     * display string, so both sides go through the same canonical syntax before comparison.
     */
    private static boolean subjectDnMatches(X509Certificate cert, String expectedDn) {
        try {
            LdapName expected = new LdapName(expectedDn);
            LdapName presented = new LdapName(cert.getSubjectX500Principal().getName(X500Principal.RFC2253));
            return expected.equals(presented);
        } catch (InvalidNameException e) {
            // A registered DN that will not parse can never be matched; treat it as no match rather
            // than failing the request with an error, so a misconfigured client is refused the same
            // way as one presenting the wrong certificate.
            logger.warn("tls_client_auth: could not parse a distinguished name for comparison: {}", e.getMessage());
            return false;
        }
    }

    private static boolean sanMatches(X509Certificate cert, int generalNameType, String expected,
            java.util.function.BiPredicate<String, String> comparison) {
        Collection<List<?>> sans;
        try {
            sans = cert.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            logger.warn("tls_client_auth: could not parse subjectAltName extension: {}", e.getMessage());
            return false;
        }
        if (sans == null) {
            return false;
        }
        for (List<?> san : sans) {
            if (san == null || san.size() < 2) {
                continue;
            }
            // Each entry is [Integer type, value]; the type must match too, otherwise a value
            // registered as a dNSName could be satisfied by an email SAN that happens to read the
            // same, which is a different assertion about the certificate.
            if (!(san.get(0) instanceof Integer type) || type != generalNameType) {
                continue;
            }
            if (san.get(1) instanceof String presented && comparison.test(expected, presented)) {
                return true;
            }
        }
        return false;
    }

    private static boolean equalsIgnoreCase(String expected, String presented) {
        return expected.equalsIgnoreCase(presented);
    }

    /**
     * RFC 8705 section 2.1.2 requires IP comparison "to be done in binary format", so that the same
     * address written differently (notably the many legal spellings of an IPv6 address) compares
     * equal. {@link InetAddress#getByName} is used only to parse literals -- both values are
     * already literal addresses, so no name resolution occurs.
     */
    private static boolean ipAddressesEqual(String expected, String presented) {
        try {
            return Arrays.equals(InetAddress.getByName(expected).getAddress(),
                    InetAddress.getByName(presented).getAddress());
        } catch (UnknownHostException e) {
            logger.warn("tls_client_auth: could not parse an IP address for comparison: {}", e.getMessage());
            return false;
        }
    }
}
