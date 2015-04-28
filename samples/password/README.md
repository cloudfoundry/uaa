# Password Grant Sample Application

This application is a sample for how you can set up your own application that uses a password grant type. The application is written in java uses the Spring framework.
Password grant is typically used when there is a high degree of trust between the resource owner and the client.

## Quick Start

Start your UAA

    $ git clone git@github.com:cloudfoundry/uaa.git
    $ cd uaa
    $ ./gradlew run

Verify that the uaa has started by going to http://localhost:8080/uaa

Start the password grant sample application

### Using Gradle:

    $ cd samples/password
    $ ./gradlew run
    >> 2015-04-24 15:39:15.862  INFO 88632 --- [main] o.s.c.support.DefaultLifecycleProcessor  : Starting beans in phase 0
    >> 2015-04-24 15:39:15.947  INFO 88632 --- [main] s.b.c.e.t.TomcatEmbeddedServletContainer : Tomcat started on port(s): 8888 (http)
    >> 2015-04-24 15:39:15.948  INFO 88632 --- [main] o.c.i.samples.password.Application       : Started Application in 4.937 seconds (JVM running for 5.408)


### Using Maven:

    $ cd samples/password
    $ mvn package
    $ java -jar target/password-sample-1.0.0-SNAPSHOT.jar
    >> 2015-04-24 15:39:15.862  INFO 88632 --- [main] o.s.c.support.DefaultLifecycleProcessor  : Starting beans in phase 0
    >> 2015-04-24 15:39:15.947  INFO 88632 --- [main] s.b.c.e.t.TomcatEmbeddedServletContainer : Tomcat started on port(s): 8888 (http)
    >> 2015-04-24 15:39:15.948  INFO 88632 --- [main] o.c.i.samples.password.Application       : Started Application in 4.937 seconds (JVM running for 5.408)

You can start the password grant flow by going to http://localhost:8888

Login with the pre-created UAA user/password of "marissa/koala"