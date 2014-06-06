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
    private byte[] encoded;
    private Charset charset;

    public UnixSHACryptPasswordImpl(UnixSHACryptPassword password) {
        this.salt = password.getSalt();
        this.iterationCount = password.getIterationCount();
        this.id = password.getId();
        this.encoded = password.getEncoded();
        this.charset = password.getCharset();
    }

    public UnixSHACryptPasswordImpl(byte[] salt, int iterationCount, char id, byte[] encoded, Charset charset) {
        this.salt = salt;
        this.iterationCount = iterationCount;
        this.id = id;
        this.encoded = encoded;
        this.charset = charset;
    }

    public UnixSHACryptPasswordImpl(byte[] salt, int iterationCount, char id, byte[] encoded) {
        this(salt, iterationCount, id, encoded, Charset.forName("UTF-8"));
    }

    @Override
    public byte[] getSalt() {
        return salt;
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
    public Charset getCharset() {
        return charset;
    }

    @Override
    public String getAlgorithm() {
        return "sha-crypt";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return encoded;
    }
}
