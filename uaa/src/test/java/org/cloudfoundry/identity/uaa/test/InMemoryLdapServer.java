package org.cloudfoundry.identity.uaa.test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.TrustStoreTrustManager;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import jakarta.validation.constraints.NotNull;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

/**
 * In-memory LDAP server that runs on a random port, so that it avoids port collisions.
 * <p>
 * Can be run with or without TLS. Start a server with {@link InMemoryLdapServer#startLdap()}
 * or {@link InMemoryLdapServer#startLdapWithTls(File keystore)}, then obtain the URL of the
 * running LDAP server with {@link InMemoryLdapServer#getUrl()}.
 */
public final class InMemoryLdapServer implements Closeable {
    private static final String JAVAX_NET_SSL_TRUST_STORE = "javax.net.ssl.trustStore";

    private static final String[] DEFAULT_ROOTS = {
            "dc=test,dc=com",
            "olcDatabase=bdb, cn=config",
            "cn=module, cn=config",
            "cn=schema, cn=config"
    };

    private static final URL TRUST_STORE_URL =
            InMemoryLdapServer.class.getClassLoader().getResource("certs/truststore-containing-the-ldap-ca.jks");

    private static final URL LDAP_INIT_LIDF_URL =
            InMemoryLdapServer.class.getClassLoader().getResource("ldap_init.ldif");

    private InMemoryDirectoryServer directoryServer;

    private final boolean tlsEnabled;
    private final File keyStore;

    public static InMemoryLdapServer startLdap() {
        InMemoryLdapServer server = new InMemoryLdapServer();
        server.start();
        server.applyChangesFromLDIF(LDAP_INIT_LIDF_URL);
        return server;
    }

    public static InMemoryLdapServer startLdapWithTls(@NotNull File keyStore) {
        InMemoryLdapServer server = new InMemoryLdapServer(keyStore);
        server.start();
        server.applyChangesFromLDIF(LDAP_INIT_LIDF_URL);
        return server;
    }

    private InMemoryLdapServer() {
        this.tlsEnabled = false;
        this.keyStore = null;
    }

    private InMemoryLdapServer(File keyStore) {
        this.tlsEnabled = true;
        this.keyStore = keyStore;
    }

    public void start() {
        try {
            this.directoryServer = new InMemoryDirectoryServer(buildConfig());
            this.directoryServer.addEntries(new Entry(new DN("cn=schema, cn=config")));
            this.directoryServer.startListening();
        } catch (LDAPException | GeneralSecurityException e) {
            throw new RuntimeException("Server startup failed", e);
        }
    }

    private void applyChangesFromLDIF(URL ldif) {
        try (InputStream inputStream = ldif.openStream()) {
            directoryServer.applyChangesFromLDIF(new LDIFReader(inputStream));
        } catch (LDAPException | IOException e) {
            throw new IllegalStateException("Unable to load LDIF " + ldif, e);
        }
    }

    /**
     * Get the URL of the running LDAP server.
     *
     * @return -
     */
    public String getUrl() {
        var scheme = this.tlsEnabled ? "ldaps" : "ldap";
        return "%s://localhost:%s".formatted(scheme, getBoundPort());
    }

    private Integer getBoundPort() {
        return this.directoryServer.getListenPort();
    }

    public void stop() {
        this.directoryServer.shutDown(true);
    }

    public boolean isRunning() {
        try {
            return this.directoryServer.getConnection().isConnected();
        } catch (LDAPException e) {
            return false;
        }
    }

    private InMemoryDirectoryServerConfig buildConfig() throws LDAPException, GeneralSecurityException {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(DEFAULT_ROOTS);

        List<InMemoryListenerConfig> listenerConfigs = new ArrayList<>();
        config.setEnforceSingleStructuralObjectClass(false);
        config.setEnforceAttributeSyntaxCompliance(true);
        config.setSchema(null);

        if (tlsEnabled) {
            final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());
            KeyStoreKeyManager keyStoreKeyManager = keyStore != null
                    ? new KeyStoreKeyManager(keyStore, "password".toCharArray(), "JKS", null)
                    : null;
            final SSLUtil serverSSLUtil = new SSLUtil(
                    keyStoreKeyManager,
                    new TrustStoreTrustManager(TRUST_STORE_URL.getFile())
            );

            listenerConfigs.add(
                    InMemoryListenerConfig.createLDAPSConfig(
                            "LDAPS",
                            null,
                            0,
                            serverSSLUtil.createSSLServerSocketFactory(),
                            clientSSLUtil.createSSLSocketFactory()
                    )
            );
        } else {
            listenerConfigs.add(InMemoryListenerConfig.createLDAPConfig("LDAP", 0));
        }

        config.setListenerConfigs(listenerConfigs);
        return config;
    }

    @Override
    public void close() {
        stop();
    }

    public static class LdapTrustStoreExtension implements BeforeAllCallback, AfterAllCallback {

        @Override
        public void beforeAll(ExtensionContext context) {
            ExtensionContext.Store store =
                    context.getStore(ExtensionContext.Namespace.create(context.getRequiredTestClass()));
            store.put(JAVAX_NET_SSL_TRUST_STORE, System.getProperty(JAVAX_NET_SSL_TRUST_STORE));

            String trustStoreAbsolutePath = new File(TRUST_STORE_URL.getFile()).getAbsolutePath();
            System.setProperty(JAVAX_NET_SSL_TRUST_STORE, trustStoreAbsolutePath);
        }

        @Override
        public void afterAll(ExtensionContext context) {
            ExtensionContext.Store store =
                    context.getStore(ExtensionContext.Namespace.create(context.getRequiredTestClass()));
            String value = store.get(JAVAX_NET_SSL_TRUST_STORE, String.class);

            if (value != null) {
                System.setProperty(JAVAX_NET_SSL_TRUST_STORE, value);
            } else {
                System.clearProperty(JAVAX_NET_SSL_TRUST_STORE);
            }
        }
    }
}
