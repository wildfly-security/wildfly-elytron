WildFly Elytron Tool
====================

WildFly Elytron is a new WildFly sub-project which is completely replacing the combination of PicketBox and JAAS as the WildFly client and  server security mechanism.  This project is the command line tool to expose utilities when working with WildFly Elytron.
 
An "elytron" (ĕl´·ĭ·trŏn, plural "elytra") is the hard, protective casing over a wing of certain flying insects (e.g. beetles).

Building From Source
--------------------

> git clone git@github.com:wildfly-security/wildfly-elytron-tool.git

Setup the JBoss Maven Repository
--------------------------------

To use dependencies from JBoss.org, you need to add the JBoss Maven Repositories to your Maven settings.xml. For details see http://community.jboss.org/wiki/MavenGettingStarted-Users

Build with Maven
----------------

The command below builds the project and runs the embedded suite.

<pre>
$ mvn clean install
</pre>

Issue Tracking
--------------

Bugs and features are tracked within the WildFly Elytron Tool GitHub project https://github.com/wildfly-security/wildfly-elytron-tool/issues



