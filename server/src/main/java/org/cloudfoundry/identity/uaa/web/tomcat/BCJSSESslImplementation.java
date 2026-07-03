package org.cloudfoundry.identity.uaa.web.tomcat;

import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLUtil;
import org.apache.tomcat.util.net.jsse.JSSEImplementation;

/**
 * A Tomcat {@link org.apache.tomcat.util.net.SSLImplementation} that serves the connector's
 * {@link SSLUtil} from a {@link BCJSSEUtil}, i.e. backed by the FIPS Bouncy Castle JSSE provider
 * (BCJSSE). Referenced from {@link MtlsClientAuthTomcatCustomizer} via the connector's
 * {@code sslImplementationName} so that only this connector uses BCJSSE; every other JVM SSLContext
 * (LDAP, DB, outbound TLS) stays on the default provider.
 */
public final class BCJSSESslImplementation extends JSSEImplementation {

    @Override
    public SSLUtil getSSLUtil(SSLHostConfigCertificate certificate) {
        return new BCJSSEUtil(certificate);
    }
}
