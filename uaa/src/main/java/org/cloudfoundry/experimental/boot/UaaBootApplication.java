package org.cloudfoundry.experimental.boot;

import org.cloudfoundry.identity.uaa.UaaApplicationConfiguration;
import org.cloudfoundry.identity.uaa.UaaStatsdConfiguration;
import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import({UaaBootConfiguration.class, UaaApplicationConfiguration.class, UaaStatsdConfiguration.class})
public class UaaBootApplication {
    public static void main(String... args) {
        //make spring boot work with UAA beans
        System.setProperty("spring.main.allow-bean-definition-overriding", "true");
        System.setProperty("spring.main.allow-circular-references", "true");
        //System.setProperty("server.servlet.context-path", "/uaa");

        //debug spring filters
        //System.setProperty("logging.level.org.springframework.security", "TRACE");


        //BELOW ARE INTEGRATION TEST PROPERTIES - NOW SET IN build.gradle
        //String base = System.getProperty(
        //        "uaa.root.dir",
        //        System.getProperty("user.dir")
        //);

        //set up tomcat base directory
        //String tomcatBase = base + "/scripts/boot/tomcat/";
        //new File(tomcatBase+"/work").mkdirs();
        //new File(tomcatBase+"/webapps").mkdirs();
        //System.setProperty("server.tomcat.basedir", tomcatBase);

        //read the uaa.yml file out of the scripts/cargo dir
        //String configPath = base + "/scripts/cargo";
        //System.setProperty("CLOUDFOUNDRY_CONFIG_PATH", configPath);

        //configure sample properties for testing
        //System.setProperty("smtp.host", "localhost");
        //System.setProperty("smtp.port", "2525");
        //System.setProperty("java.security.egd", "file:/dev/./urandom");
        //System.setProperty("spring.profiles.active", "hsqldb");


        //start the application
        SpringApplication application = new SpringApplication(UaaBootApplication.class);
        application.addInitializers(new YamlServletProfileInitializer());
        application.run(args);
    }
}
