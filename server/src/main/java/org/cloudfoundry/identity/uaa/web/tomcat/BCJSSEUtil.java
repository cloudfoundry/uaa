package org.cloudfoundry.identity.uaa.web.tomcat;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLParameters;

import org.apache.tomcat.util.net.SSLContext;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.jsse.JSSEUtil;

/**
 * A {@link JSSEUtil} that builds the connector's {@link SSLContext} from the FIPS Bouncy Castle JSSE
 * provider (BCJSSE) via {@link BCJSSESSLContext}, and declares that TLS 1.3 renegotiable
 * (post-handshake-requestable) client authentication is available -- which is precisely what JSSE
 * cannot do (the reason the connector previously pinned {@code all,-TLSv1.3}).
 *
 * <p>{@code getImplementedProtocols()}/{@code getImplementedCiphers()} are overridden to source from
 * BCJSSE's own {@code getSupportedSSLParameters()} rather than {@link JSSEUtil}'s private
 * {@code initialise()}, which probes a SunJSSE-backed {@code SSLContext} instead. This matters because
 * {@code SSLUtilBase}'s constructor only strips {@code SSLv2Hello}/{@code TLSv1.3} from the connector's
 * configured protocol set when the <em>implemented</em> set doesn't contain them -- and SunJSSE's
 * implemented set (unlike BCJSSE's) includes {@code SSLv2Hello}, which the BC-backed engine then
 * rejects at handshake time ({@code ProvSSLParameters.setProtocols}: "'protocols' cannot be null, or
 * contain unsupported protocols"), breaking every TLS handshake on this connector.
 *
 * <p>Everything else (keystore loading, {@code trustManagerClassName} handling) is inherited from
 * {@link JSSEUtil}/{@link org.apache.tomcat.util.net.SSLUtilBase}.
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

    @Override
    protected Set<String> getImplementedProtocols() {
        return new HashSet<>(Arrays.asList(supportedSslParameters().getProtocols()));
    }

    @Override
    protected Set<String> getImplementedCiphers() {
        return new HashSet<>(Arrays.asList(supportedSslParameters().getCipherSuites()));
    }

    /**
     * Recomputed on every call, deliberately not cached in an instance field: {@code SSLUtilBase}'s
     * constructor invokes {@link #getImplementedProtocols()}/{@link #getImplementedCiphers()} via
     * dynamic dispatch before this subclass's own field initializers run, so caching here would risk
     * a stale/uninitialized value being read on that first, superclass-constructor-driven call.
     */
    private SSLParameters supportedSslParameters() {
        try {
            BCJSSESSLContext context = new BCJSSESSLContext(sslHostConfig.getSslProtocol());
            context.init(null, null, null);
            return context.getSupportedSSLParameters();
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
