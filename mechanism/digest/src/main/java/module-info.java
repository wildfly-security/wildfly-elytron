module org.wildfly.security.mechanism.digest {

    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.mechanism;

    exports org.wildfly.security.mechanism.digest;
}
