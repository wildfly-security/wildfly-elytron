/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.realm.token.test.util;

public class RsaJwk {
    private String kty;
    private String kid;
    private String alg;
    private String n;
    private String e;

    public RsaJwk() {
    }

    public String getKty() {
        return kty;
    }

    public RsaJwk setKty(String kty) {
        this.kty = kty;
        return this;
    }

    public String getKid() {
        return kid;
    }

    public RsaJwk setKid(String kid) {
        this.kid = kid;
        return this;
    }

    public String getAlg() {
        return alg;
    }

    public RsaJwk setAlg(String alg) {
        this.alg = alg;
        return this;
    }

    public String getN() {
        return n;
    }

    public RsaJwk setN(String n) {
        this.n = n;
        return this;
    }

    public String getE() {
        return e;
    }

    public RsaJwk setE(String e) {
        this.e = e;
        return this;
    }
}
