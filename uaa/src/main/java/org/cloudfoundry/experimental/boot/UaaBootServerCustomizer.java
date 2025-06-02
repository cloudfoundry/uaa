package org.cloudfoundry.experimental.boot;

import org.apache.catalina.connector.Connector;
import org.apache.catalina.valves.ErrorReportValve;
import org.apache.coyote.http11.Http11NioProtocol;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.ErrorPage;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.stereotype.Component;

@Component
public class UaaBootServerCustomizer implements
        WebServerFactoryCustomizer<TomcatServletWebServerFactory> {


    @Autowired
    UaaBootConfiguration.ServerHttp serverHttp;

    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        //customize tomcat

        //<error-page> from web.xml
        factory.addErrorPages(
            new ErrorPage(HttpStatus.INTERNAL_SERVER_ERROR, "/error500"),
            new ErrorPage(HttpStatus.NOT_FOUND, "/error404"),
            new ErrorPage(HttpStatus.TOO_MANY_REQUESTS, "/error429"),
            new ErrorPage("/error"),
            new ErrorPage(RequestRejectedException.class, "/rejected")
        );

        //add error report valve
        //https://github.com/cloudfoundry/uaa-release/blob/0be1fa547aa975019b957cd9aafe9ca09edf62d9/jobs/uaa/templates/config/tomcat/tomcat.server.xml.erb#L111-L114
        factory.addEngineValves(getErrorReportValve());

        if (this.serverHttp.port() > 0) {
            factory.addAdditionalTomcatConnectors(
                    getHttpPort(
                            this.serverHttp
                    )
            );
        }
    }

    Connector getHttpPort(UaaBootConfiguration.ServerHttp serverHttp) {
        Connector httpConnector = new Connector("HTTP/1.1");
        httpConnector.setProperty("class", Http11NioProtocol.class.getName());
        httpConnector.setPort(serverHttp.port());
        httpConnector.setProperty("connectionTimeout", "20000");
        httpConnector.setProperty("keepAliveTimeout", String.valueOf(serverHttp.keepAliveTimeout()));
        httpConnector.setProperty("address", serverHttp.address());
        httpConnector.setProperty("bindOnInit", String.valueOf(serverHttp.bindOnInit()));
        httpConnector.setProperty("maxHttpHeaderSize", String.valueOf(serverHttp.maxHttpHeaderSize()));
        return httpConnector;
    }

    ErrorReportValve getErrorReportValve() {
        ErrorReportValve valve = new ErrorReportValve();
        valve.setShowReport(false);
        valve.setShowServerInfo(false);
        return valve;
    }
}