module org.wildfly.security.mechanism {

    requires java.security.sasl;
    requires org.jboss.logging;
    requires org.wildfly.common;
    requires org.wildfly.security.asn1;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.http;
    requires static org.jboss.logging.annotations;

    exports org.wildfly.security.mechanism;
    exports org.wildfly.security.mechanism._private;
}
