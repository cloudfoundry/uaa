package org.cloudfoundry.identity.uaa.integration;

import java.util.Iterator;

import com.dumbster.smtp.SimpleSmtpServer;
import com.dumbster.smtp.SmtpMessage;

public class PrintSmtpToScreen {

    public static void main(String... args) throws Exception {
        final SimpleSmtpServer server = SimpleSmtpServer.start(2525);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Stopping SMTP server");
            server.stop();
        }));

        while (!server.isStopped()) {
            Iterator iterator = server.getReceivedEmail();
            while (iterator.hasNext()) {
                SmtpMessage m = (SmtpMessage) iterator.next();
                iterator.remove();
                System.out.println(m.getBody());
            }
            Thread.sleep(250);
        }
    }
}
