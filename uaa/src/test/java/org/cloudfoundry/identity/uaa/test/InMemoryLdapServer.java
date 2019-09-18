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

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

public class InMemoryLdapServer implements Closeable {
    private static final String JAVAX_NET_SSL_TRUST_STORE = "javax.net.ssl.trustStore";

    private static String[] DEFAULT_ROOTS = {
            "dc=test,dc=com",
            "olcDatabase=bdb, cn=config",
            "cn=module, cn=config",
            "cn=schema, cn=config"
    };

    private static File TRUST_STORE = new File(InMemoryLdapServer
            .class
            .getClassLoader()
            .getResource("certs/truststore-containing-the-ldap-ca.jks")
            .getFile());

    private InMemoryDirectoryServer directoryServer;
    private final int port;

    private boolean tlsEnabled;
    private int tlsPort;
    private File keyStore;
    private File trustStore;

    public static InMemoryLdapServer startLdap(int port) {
        ClassLoader classLoader = InMemoryLdapServer.class.getClassLoader();
        InMemoryLdapServer server = new InMemoryLdapServer(port);
        server.start();
        server.applyChangesFromLDIF(classLoader.getResource("ldap_init.ldif"));
        return server;
    }

    public static InMemoryLdapServer startLdapWithTls(int port, int tlsPort, File keyStore) {
        ClassLoader classLoader = InMemoryLdapServer.class.getClassLoader();
        InMemoryLdapServer server = new InMemoryLdapServer(port);
        server.configureStartTLS(tlsPort, keyStore, TRUST_STORE);
        server.start();
        server.applyChangesFromLDIF(classLoader.getResource("ldap_init.ldif"));
        return server;
    }

    private InMemoryLdapServer(int port) {
        this.tlsEnabled = false;
        this.port = port;
    }

    private void configureStartTLS(int tlsPort, File keyStore, File trustStore) {
        this.tlsEnabled = true;
        this.tlsPort = tlsPort;
        this.keyStore = keyStore;
        this.trustStore = trustStore;
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

    public String getLdapBaseUrl() {
        return "ldap://localhost:" + port;
    }

    public String getLdapSBaseUrl() {
        return "ldaps://localhost:" + tlsPort;
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
        listenerConfigs.add(InMemoryListenerConfig.createLDAPConfig("LDAP", port));
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
                    new TrustStoreTrustManager(trustStore)
            );

            listenerConfigs.add(
                    InMemoryListenerConfig.createLDAPSConfig(
                            "LDAPS",
                            null,
                            tlsPort,
                            serverSSLUtil.createSSLServerSocketFactory(),
                            clientSSLUtil.createSSLSocketFactory()
                    )
            );
        }

        config.setListenerConfigs(listenerConfigs);
        return config;
    }

    @Override
    public void close() throws IOException {
        stop();
    }

    public static class LdapTrustStoreExtension implements BeforeAllCallback, AfterAllCallback {

        @Override
        public void beforeAll(ExtensionContext context) {
            ExtensionContext.Store store = context.getStore(ExtensionContext.Namespace.create(context.getRequiredTestClass()));
            store.put(JAVAX_NET_SSL_TRUST_STORE, System.getProperty(JAVAX_NET_SSL_TRUST_STORE));
            System.setProperty(JAVAX_NET_SSL_TRUST_STORE, TRUST_STORE.getAbsolutePath());
        }

        @Override
        public void afterAll(ExtensionContext context) {
            ExtensionContext.Store store = context.getStore(ExtensionContext.Namespace.create(context.getRequiredTestClass()));
            String value = store.get(JAVAX_NET_SSL_TRUST_STORE, String.class);

            if (value != null) {
                System.setProperty(JAVAX_NET_SSL_TRUST_STORE, value);
            } else {
                System.clearProperty(JAVAX_NET_SSL_TRUST_STORE);
            }
        }
    }
}
