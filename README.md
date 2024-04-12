test
WildFly Elytron
===============

[WildFly Elytron](https://wildfly-security.github.io/wildfly-elytron/) is a new WildFly sub-project which is completely replacing the combination of PicketBox and JAAS as the WildFly client and  server security mechanism.
 
An "elytron" (ĕl´·ĭ·trŏn, plural "elytra") is the hard, protective casing over a wing of certain flying insects (e.g. beetles).

Building From Source
--------------------

```console
$ git clone git@github.com:wildfly-security/wildfly-elytron.git
```

Setup the JBoss Maven Repository
--------------------------------

To use dependencies from JBoss.org, you need to add the JBoss Maven Repositories to your Maven settings.xml. For details see [Maven Getting Started - Users](https://developer.jboss.org/docs/DOC-15169)

Build with Maven
----------------

The command below builds the project and runs the embedded suite.

```console
$ mvn clean install
```

Issue Tracking
--------------

Bugs and features are tracked within the Elytron Jira project at https://issues.redhat.com/browse/ELY

Contributions
-------------

All new features and enhancements should be submitted to 2.x branch only.
Our [contribution guide](https://github.com/wildfly-security/wildfly-elytron/blob/2.x/CONTRIBUTING.md) will guide you through the steps for getting started on the WildFly Elytron project and will go through how to format and submit your first PR.
 
For more details, check out our [getting started guide](https://wildfly-security.github.io/wildfly-elytron/getting-started-for-developers/) for developers.

Example Feature Demos
---------------------

Our [elytron-examples](https://github.com/wildfly-security-incubator/elytron-examples) repository contains example demos of WildFly Elytron features.

Get Help
--------
There are a couple ways to get in touch with us.

Feel free to ask questions on the WildFly user [forum](https://groups.google.com/g/wildfly).  

The WildFly Elytron team also has an open chat room where you can listen in and ask questions. Join us on [Zulip chat](https://wildfly.zulipchat.com/#narrow/stream/173102-wildfly-elytron).
