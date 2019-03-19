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
import java.util.Map;
import java.util.UUID;

public class HoneycombJdbcInterceptor extends JdbcInterceptor {
    public static String testRunning;

    public static EventFactory honeyCombEventFactory;


    @Override
    public void reset(ConnectionPool parent, PooledConnection con) {
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        try {
            honeyCombEventFactory.createEvent()
                    .addField("testName", testRunning)
                    .addField("sqlArgs", Arrays.toString(args))
                    .send();
        } catch (Exception _) {
        }
        return super.invoke(proxy, method, args);
    }

}
