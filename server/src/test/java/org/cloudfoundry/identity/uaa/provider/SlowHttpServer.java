package org.cloudfoundry.identity.uaa.provider;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.cloudfoundry.identity.uaa.test.network.NetworkTestUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.io.File;
import java.util.Date;

public class SlowHttpServer {
    private final Runnable serverRunner;
    private HttpServer httpServer;

    public SlowHttpServer() {
        serverRunner = () -> {
            try {
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_JSON);
                File keystore = NetworkTestUtils.getKeystore(new Date(), 10);
                httpServer = NetworkTestUtils.startHttpsServer(keystore, NetworkTestUtils.keyPass, new SlowSimpleHttpResponseHandler());
            } catch (Exception e) {
                e.printStackTrace();
            }
        };
    }

    public void run() {
        new Thread(serverRunner).run();
    }

    public void stop() {
        if (httpServer != null) {
            httpServer.stop(0);
        }
    }

    private static class SlowSimpleHttpResponseHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange httpExchange) {
            try {
                Thread.sleep(Integer.MAX_VALUE);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    public String getUrl() {
        return "https://127.0.0.1:" + httpServer.getAddress().getPort();
    }
}
