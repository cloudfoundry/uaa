package org.cloudfoundry.identity.uaa.web.tomcat;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import org.apache.tomcat.util.net.SSLContext;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.jsse.JSSEUtil;

/**
 * A {@link JSSEUtil} that builds the connector's {@link SSLContext} from the FIPS Bouncy Castle JSSE
 * provider (BCJSSE) via {@link BCJSSESSLContext}, and declares that TLS 1.3 renegotiable
 * (post-handshake-requestable) client authentication is available -- which is precisely what JSSE
 * cannot do (the reason the connector previously pinned {@code all,-TLSv1.3}).
 *
 * <p>Everything else (keystore loading, {@code trustManagerClassName} handling, cipher/protocol
 * filtering) is inherited from {@link JSSEUtil}/{@link org.apache.tomcat.util.net.SSLUtilBase}.
 */
public final class BCJSSEUtil extends JSSEUtil {

    public BCJSSEUtil(SSLHostConfigCertificate certificate) {
        super(certificate);
    }

    @Override
    public SSLContext createSSLContextInternal(List<String> negotiableProtocols) throws NoSuchAlgorithmException {
        return new BCJSSESSLContext(sslHostConfig.getSslProtocol());
    }

    @Override
    protected boolean isTls13RenegAuthAvailable() {
        return true;
    }
}
