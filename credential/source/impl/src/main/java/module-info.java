module org.wildfly.security.credential.source.impl {

    requires java.security.jgss;
    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.auth;
    requires org.wildfly.security.credential.store;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.x500;
    requires org.wildfly.security;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.credential.source.impl;
}
