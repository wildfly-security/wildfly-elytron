module org.wildfly.security.http.oidc {

    requires com.fasterxml.jackson.annotation;
    requires com.fasterxml.jackson.core;
    requires com.fasterxml.jackson.databind;
    requires java.security.sasl;
    requires org.apache.httpcomponents.httpclient;
    requires org.apache.httpcomponents.httpcore;
    requires org.jboss.logging;
    requires org.jose4j;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.auth;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.http;
    requires org.wildfly.security.jose.jwk;
    requires org.wildfly.security.jose.util;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security.x500.cert;
    requires org.wildfly.security;
    requires static jakarta.json;
    requires static jakarta.servlet;
    requires static org.jboss.logging.annotations;
    requires static org.kohsuke.metainf_services;

    exports org.wildfly.security.http.oidc;

    provides java.security.Provider
        with org.wildfly.security.http.oidc.WildFlyElytronHttpOidcProvider;
    provides org.wildfly.security.http.HttpServerAuthenticationMechanismFactory
        with org.wildfly.security.http.oidc.OidcMechanismFactory;
    provides org.wildfly.security.http.oidc.ClientCredentialsProvider
        with org.wildfly.security.http.oidc.ClientIdAndSecretCredentialsProvider,
            org.wildfly.security.http.oidc.JWTClientCredentialsProvider,
            org.wildfly.security.http.oidc.JWTClientSecretCredentialsProvider;
}
