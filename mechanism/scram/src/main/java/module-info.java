module org.wildfly.security.mechanism.scram {

    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security.sasl;

    exports org.wildfly.security.mechanism.scram;
}
