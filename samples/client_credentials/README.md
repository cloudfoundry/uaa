# Client Credentials Sample Application

This application is a sample for how you can set up your own application that uses a client credentials grant type. The application is written in java and uses the Spring framework.
Client Credentials grant is typically used for service to service applications.

## Quick Start

Start your UAA

    $ git clone git@github.com:cloudfoundry/uaa.git
    $ cd uaa
    $ ./gradlew run

Verify that the uaa has started by going to http://localhost:8080/uaa

Start the authcode sample application

### Using Gradle:

    $ cd samples/client_credentials
    $ ./gradlew run
    >> 2015-04-24 15:39:15.862  INFO 88632 --- [main] o.s.c.support.DefaultLifecycleProcessor  : Starting beans in phase 0
    >> 2015-04-24 15:39:15.947  INFO 88632 --- [main] s.b.c.e.t.TomcatEmbeddedServletContainer : Tomcat started on port(s): 8888 (http)
    >> 2015-04-24 15:39:15.948  INFO 88632 --- [main] o.c.i.samples.clientcredentials.Application       : Started Application in 4.937 seconds (JVM running for 5.408)


### Using Maven:

    $ cd samples/client_credentials
    $ mvn package
    $ java -jar target/clientcredentials-sample-1.0.0-SNAPSHOT.jar
    >> 2015-04-24 15:39:15.862  INFO 88632 --- [main] o.s.c.support.DefaultLifecycleProcessor  : Starting beans in phase 0
    >> 2015-04-24 15:39:15.947  INFO 88632 --- [main] s.b.c.e.t.TomcatEmbeddedServletContainer : Tomcat started on port(s): 8888 (http)
    >> 2015-04-24 15:39:15.948  INFO 88632 --- [main] o.c.i.samples.clientcredentials.Application       : Started Application in 4.937 seconds (JVM running for 5.408)

You can start the client credentials grant flow by going to http://localhost:8888