package org.cloudfoundry.identity.uaa.test;

import io.honeycomb.libhoney.EventFactory;
import io.honeycomb.libhoney.HoneyClient;
import io.honeycomb.libhoney.LibHoney;
import org.apache.tomcat.jdbc.pool.ConnectionPool;
import org.apache.tomcat.jdbc.pool.JdbcInterceptor;
import org.apache.tomcat.jdbc.pool.PooledConnection;

import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.UUID;

public class HoneycombJdbcInterceptor extends JdbcInterceptor {
    public static String testRunning;

    private EventFactory honeyCombEventFactory = buildEventFactory();


    @Override
    public void reset(ConnectionPool parent, PooledConnection con) {
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if (honeyCombEventFactory != null) {
            honeyCombEventFactory.createEvent()
                    .addField("testName", testRunning)
                    .addField("sqlArgs", Arrays.toString(args))
                    .send();
        }
        return super.invoke(proxy, method, args);
    }


    private EventFactory buildEventFactory() {
        if (System.getProperty("honeycomb.writekey", "").isEmpty() || System.getProperty("honeycomb.dataset", "").isEmpty()) {
            return null;
        }

        HoneyClient honeyClient = LibHoney.create(
                LibHoney.options()
                        .setWriteKey(System.getProperty("honeycomb.writekey", ""))
                        .setDataset(System.getProperty("honeycomb.dataset", ""))
                        .build()
        );

        String hostName = "";
        try {
            hostName = InetAddress.getLocalHost().getHostName();

        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        return honeyClient.buildEventFactory()
                .addField("testId", UUID.randomUUID().toString())
                .addField("cpuCores", Runtime.getRuntime().availableProcessors())
                .addField("hostname", hostName)
                .build();
    }

}
