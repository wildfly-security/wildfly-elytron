package org.wildfly.security.http.client.mechanism.bearer;

import org.wildfly.security.http.client.mechanism.ElytronHttpClientAuthMechanism;
import org.wildfly.security.mechanism.AuthenticationMechanismException;

import java.net.URI;
import java.net.http.HttpRequest;

public class ElytronHttpClientBearerAuthMechanism implements ElytronHttpClientAuthMechanism {

    @Override
    public HttpRequest evaluateMechanism(URI uri) throws AuthenticationMechanismException {
        return null;
    }
}
