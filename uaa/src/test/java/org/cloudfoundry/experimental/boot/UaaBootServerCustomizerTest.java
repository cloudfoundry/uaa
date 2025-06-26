package org.cloudfoundry.experimental.boot;


import org.apache.catalina.Valve;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.valves.ErrorReportValve;
import org.apache.coyote.http11.Http11NioProtocol;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DefaultTestContext
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@TestPropertySource(properties = {"server.http.port = 8081"})
class UaaBootServerCustomizerTest {

    @SpyBean
    UaaBootServerCustomizer customizer;

    @Test
    void customizerAddedReportValve() {
        ArgumentCaptor<TomcatServletWebServerFactory> captor = ArgumentCaptor.forClass(TomcatServletWebServerFactory.class);
        Mockito.verify(customizer, Mockito.atMostOnce()).customize(captor.capture());
        Collection<Valve> valves = captor.getValue().getEngineValves();
        assertThat(valves).isNotEmpty();
        Optional<Valve> valve = valves.stream().filter(v -> v.getClass().equals(ErrorReportValve.class)).findFirst();
        assertThat(valve.isPresent()).isTrue();
        ErrorReportValve errorReportValve = (ErrorReportValve) valve.get();
        assertThat(errorReportValve.isShowReport()).isFalse();
        assertThat(errorReportValve.isShowServerInfo()).isFalse();
    }

    @Test
    void localhostConnectorAdded() throws UnknownHostException {
        ArgumentCaptor<TomcatServletWebServerFactory> captor = ArgumentCaptor.forClass(TomcatServletWebServerFactory.class);
        Mockito.verify(customizer, Mockito.atMostOnce()).customize(captor.capture());
        List<Connector> connectors = captor.getValue().getAdditionalTomcatConnectors();
        assertThat(connectors).isNotEmpty();
        assertThat(connectors).hasSize(1);
        Connector httpConnector = connectors.getFirst();
        assertThat(httpConnector.getProperty("class")).isEqualTo(Http11NioProtocol.class);
        assertThat(httpConnector.getPort()).isEqualTo(8081);
        assertThat(httpConnector.getProperty("connectionTimeout")).isEqualTo(20000);
        assertThat(httpConnector.getProperty("keepAliveTimeout")).isEqualTo(12000);
        assertThat(httpConnector.getProperty("address")).isEqualTo(Inet4Address.getByAddress(new byte[] {127,0,0,1}));
        assertThat(httpConnector.getProperty("bindOnInit")).isEqualTo("true");
        assertThat(httpConnector.getProperty("maxHttpHeaderSize")).isEqualTo(14336);
    }
}