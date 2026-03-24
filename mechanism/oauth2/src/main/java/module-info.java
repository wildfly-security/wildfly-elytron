module org.wildfly.security.mechanism.oauth2 {

    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security.sasl;
    requires static jakarta.json;

    exports org.wildfly.security.mechanism.oauth2;
}
