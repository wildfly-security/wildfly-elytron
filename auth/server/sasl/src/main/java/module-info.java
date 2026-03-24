module org.wildfly.security.auth.server.sasl {

    requires java.security.sasl;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.sasl;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.auth.server.sasl;
}
