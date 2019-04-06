WildFly Elytron
===============

WildFly Elytron is a new WildFly sub-project which is completely replacing the combination of PicketBox and JAAS as the WildFly client and  server security mechanism.
 
An "elytron" (ĕl´·ĭ·trŏn, plural "elytra") is the hard, protective casing over a wing of certain flying insects (e.g. beetles).

Building From Source
--------------------

```console
$ git clone git@github.com:wildfly-security/wildfly-elytron.git
```

Setup the JBoss Maven Repository
--------------------------------

To use dependencies from JBoss.org, you need to add the JBoss Maven Repositories to your Maven settings.xml. For details see http://community.jboss.org/wiki/MavenGettingStarted-Users

Build with Maven
----------------

The command below builds the project and runs the embedded suite.

```console
$ mvn clean install
```

Issue Tracking
--------------

Bugs and features are tracked within the Elytron Jira project at https://issues.jboss.org/browse/ELY

Contributions
-------------

When submitting bug fixes please start from the 1.3.x branch and submit the pull request against this branch.

All new features and enhancements should be submitted to master only.
https://developer.jboss.org/wiki/GettingStartedWithWildFlyElytron
