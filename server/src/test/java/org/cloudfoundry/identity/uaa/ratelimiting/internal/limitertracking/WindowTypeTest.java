package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

class WindowTypeTest {

    private static final String PACKAGE = WindowTypeTest.class.getPackageName();

    @Test
    void allWindowTypesIsFullyPopulated() {
        assertThat(WindowType.allWindowTypes())
                .hasSize(4)
                .doesNotContainNull()
                .containsExactly(WindowType.NON_GLOBAL.CredentialsID,
                        WindowType.NON_GLOBAL.RemoteAddressID,
                        WindowType.NON_GLOBAL.NoID,
                        WindowType.GLOBAL);
    }

    /**
     * The window types reference both {@code GLOBAL} and the {@code NON_GLOBAL} enum constants.
     * Initializing {@code NON_GLOBAL} first also initializes {@code WindowType} (its superinterface
     * declares default methods), so holding them in an interface field would capture the enum
     * constants while they are still {@code null}. Load the classes in an isolated class loader,
     * touching {@code NON_GLOBAL} first, to force that order.
     */
    @Test
    void allWindowTypesIsFullyPopulatedWhenNonGlobalIsInitializedFirst() throws Exception {
        try (URLClassLoader loader = new URLClassLoader(currentClassPath(), ClassLoader.getPlatformClassLoader())) {
            Class<?> nonGlobal = Class.forName(PACKAGE + ".WindowType$NON_GLOBAL", true, loader);
            assertThat(nonGlobal.getEnumConstants()).hasSize(3);

            Class<?> windowType = Class.forName(PACKAGE + ".WindowType", true, loader);
            Method allWindowTypes = windowType.getMethod("allWindowTypes");

            assertThat((Object[]) allWindowTypes.invoke(null)).hasSize(4).doesNotContainNull();
        }
    }

    private static URL[] currentClassPath() throws Exception {
        List<URL> urls = new ArrayList<>();
        for (String entry : System.getProperty("java.class.path").split(File.pathSeparator)) {
            urls.add(Paths.get(entry).toUri().toURL());
        }
        return urls.toArray(URL[]::new);
    }
}
