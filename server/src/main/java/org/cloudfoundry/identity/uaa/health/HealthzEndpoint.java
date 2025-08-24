package org.cloudfoundry.identity.uaa.health;

import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.Statement;

/**
 * Simple controller that just returns "ok" in a request body for the purposes
 * of monitoring health of the application. It also registers a shutdown hook
 * and returns "stopping" and a 503 when the process is shutting down.
 */
@Controller
public class HealthzEndpoint {
    private static Logger logger = LoggerFactory.getLogger(HealthzEndpoint.class);
    private volatile boolean stopping;
    private volatile Boolean wasLastConnectionSuccessful = null;
    private DataSource dataSource;

    public HealthzEndpoint(
            @Value("${uaa.shutdown.sleep:10000}") final long sleepTime,
            final Runtime runtime,
            final DataSource dataSource) {
        Thread shutdownHook = new Thread(() -> {
            stopping = true;
            logger.warn("Shutdown hook received, future requests to this endpoint will return 503");
            try {
                if (sleepTime > 0) {
                    logger.debug("Healthz is sleeping shutdown thread for {} ms.", sleepTime);
                    Thread.sleep(sleepTime);
                }
            } catch (InterruptedException e) {
                logger.warn("Shutdown sleep interrupted.", e);
            }
        });
        runtime.addShutdownHook(shutdownHook);
        this.dataSource = dataSource;
    }

    @GetMapping({"/healthz", "/healthz/**"})
    @ResponseBody
    public String getHealthz(HttpServletResponse response) {
        if (stopping) {
            logger.debug("Received /healthz request during shutdown. Returning 'stopping'");
            response.setStatus(503);
            return "stopping\n";
        } else {
            if (wasLastConnectionSuccessful == null) {
                isDataSourceConnectionAvailable();
                if (wasLastConnectionSuccessful == false) {
                    return "UAA running. Database failed to start.\n";
                }
            }

            if (wasLastConnectionSuccessful) {
                return "ok\n";
            } else {
                response.setStatus(503);
                return "Database Connection failed.\n";
            }
        }
    }

    @Scheduled(fixedRateString = "${uaa.health.db.rate:10000}")
    void isDataSourceConnectionAvailable() {
        try (Connection c = dataSource.getConnection(); Statement statement = c.createStatement()) {
            statement.execute("SELECT 1 from identity_zone;"); //"SELECT 1;" Not supported by HSQLDB
            wasLastConnectionSuccessful = true;
            return;
        } catch (Exception ex) {
            logger.error("Could not establish connection to DB - {}", ex.getMessage());
        }
        wasLastConnectionSuccessful = false;
    }
}
