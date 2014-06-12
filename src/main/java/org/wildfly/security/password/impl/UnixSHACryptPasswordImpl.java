package org.wildfly.security.password.impl;

import org.wildfly.security.password.interfaces.UnixSHACryptPassword;

import java.nio.charset.Charset;

/**
 * @author <a href="mailto:juraci.javadoc@kroehling.de">Juraci Paixão Kröhling</a>
 */
public class UnixSHACryptPasswordImpl implements UnixSHACryptPassword {

    private byte[] salt;
    private int iterationCount;
    private char id;
    private byte[] hash;

    public UnixSHACryptPasswordImpl(UnixSHACryptPassword password) {
        this(password.getSalt(), password.getIterationCount(), password.getId(), password.getHash());
    }

    public UnixSHACryptPasswordImpl(byte[] salt, int iterationCount, char id) {
        this(salt, iterationCount, id, null);
    }

    public UnixSHACryptPasswordImpl(byte[] salt, int iterationCount, char id, byte[] hash) {
        if (id != '5' && id != '6') {
            throw new IllegalArgumentException("The ID for this Unix SHA crypt password was neither 5 nor 6.");
        }

        this.salt = salt;
        this.iterationCount = iterationCount;
        this.id = id;
        this.hash = hash;
    }

    @Override
    public String getAlgorithm() {
        switch (getId()) {
            case '5': return "sha-256-crypt";
            case '6': return "sha-512-crypt";
            // we validate it on the constructor already, but let's check it here as well
            default: throw new IllegalStateException("The ID for this Unix SHA crypt password was neither 5 nor 6.");
        }
    }

    @Override
    public byte[] getSalt() {
        return salt.clone();
    }

    @Override
    public int getIterationCount() {
        return iterationCount;
    }

    @Override
    public char getId() {
        return id;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

    @Override
    public byte[] getHash() {
        return hash.clone();
    }
}
