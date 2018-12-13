package org.wildfly.security.auth.realm.ldap;

import org.wildfly.common.Assert;
import org.wildfly.common.codec.Base64Alphabet;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.spec.OneTimePasswordSpec;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.NoSuchAttributeException;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.function.Supplier;

import static org.wildfly.security._private.ElytronMessages.log;

/**
 * A {@link CredentialLoader} for loading OTP credentials stored within defined attributes of LDAP entries.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
class OtpCredentialLoader implements CredentialPersister {

    private final String algorithmAttributeName;
    private final String hashAttributeName;
    private final String seedAttributeName;
    private final String sequenceAttributeName;

    OtpCredentialLoader(String algorithmAttributeName, String hashAttributeName, String seedAttributeName, String sequenceAttributeName) {
        Assert.checkNotNullParam("algorithmAttributeName", algorithmAttributeName);
        Assert.checkNotNullParam("hashAttributeName", hashAttributeName);
        Assert.checkNotNullParam("seedAttributeName", seedAttributeName);
        Assert.checkNotNullParam("sequenceAttributeName", sequenceAttributeName);
        this.algorithmAttributeName = algorithmAttributeName;
        this.hashAttributeName = hashAttributeName;
        this.seedAttributeName = seedAttributeName;
        this.sequenceAttributeName = sequenceAttributeName;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
        if (credentialType == PasswordCredential.class) {
            if (algorithmName == null) {
                return SupportLevel.SUPPORTED;
            }
            switch (algorithmName) {
                case OneTimePassword.ALGORITHM_OTP_MD5: return SupportLevel.POSSIBLY_SUPPORTED;
                case OneTimePassword.ALGORITHM_OTP_SHA1: return SupportLevel.POSSIBLY_SUPPORTED;
                case OneTimePassword.ALGORITHM_OTP_SHA_256: return SupportLevel.POSSIBLY_SUPPORTED;
                case OneTimePassword.ALGORITHM_OTP_SHA_384: return SupportLevel.POSSIBLY_SUPPORTED;
                case OneTimePassword.ALGORITHM_OTP_SHA_512: return SupportLevel.POSSIBLY_SUPPORTED;
                default: return SupportLevel.UNSUPPORTED;
            }
        }
        return SupportLevel.UNSUPPORTED;
    }

    @Override
    public ForIdentityLoader forIdentity(DirContext context, String distinguishedName, Attributes attributes) {
        return new ForIdentityLoader(context, distinguishedName, attributes);
    }

    @Override
    public void addRequiredIdentityAttributes(Collection<String> attributes) {
        attributes.add(algorithmAttributeName);
        attributes.add(hashAttributeName);
        attributes.add(seedAttributeName);
        attributes.add(sequenceAttributeName);
    }

    private class ForIdentityLoader implements IdentityCredentialPersister {

        private final DirContext context;
        private final String distinguishedName;
        private final Attributes attributes;

        public ForIdentityLoader(DirContext context, String distinguishedName, Attributes attributes) {
            this.context = context;
            this.distinguishedName = distinguishedName;
            this.attributes = attributes;
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec, final Supplier<Provider[]> providers) {
            if (credentialType != PasswordCredential.class) {
                return SupportLevel.UNSUPPORTED;
            }
            Attribute algorithmAttribute = attributes.get(algorithmAttributeName);
            Attribute hashAttribute = attributes.get(hashAttributeName);
            Attribute seedAttribute = attributes.get(seedAttributeName);
            Attribute sequenceAttribute = attributes.get(sequenceAttributeName);

            if (algorithmAttribute != null && hashAttribute != null && seedAttribute != null && sequenceAttribute != null && (algorithmName == null || algorithmAttribute.contains(algorithmName))) {
                return SupportLevel.SUPPORTED;
            }
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec, Supplier<Provider[]> providers) {
            if (credentialType != PasswordCredential.class) {
                return null;
            }
            try {
                Attribute algorithmAttribute = attributes.get(algorithmAttributeName);
                Attribute hashAttribute = attributes.get(hashAttributeName);
                Attribute seedAttribute = attributes.get(seedAttributeName);
                Attribute sequenceAttribute = attributes.get(sequenceAttributeName);

                if (algorithmAttribute == null || algorithmName != null && ! algorithmAttribute.contains(algorithmName) || hashAttribute == null || seedAttribute == null || sequenceAttribute == null) {
                    return null;
                }

                Object algorithm = algorithmAttribute.get();
                Object hash = hashAttribute.get();
                Object seed = seedAttribute.get();
                Object sequence = sequenceAttribute.get();

                if (algorithm == null || hash == null || seed == null || sequence == null || ! (algorithm instanceof String) || ! (hash instanceof String) || ! (seed instanceof String) || ! (sequence instanceof String)) {
                    return null;
                }

                PasswordFactory passwordFactory = PasswordFactory.getInstance((String) algorithm, providers);
                Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(
                                CodePointIterator.ofString((String) hash)
                                        .base64Decode(Base64Alphabet.STANDARD, false).drain(),
                                (String) seed,
                                Integer.parseInt((String) sequence)));
                if (credentialType.isAssignableFrom(PasswordCredential.class)) {
                    return credentialType.cast(new PasswordCredential(password));
                }

            } catch (NamingException | InvalidKeySpecException | NoSuchAlgorithmException e) {
                if (log.isTraceEnabled()) log.trace("Getting OTP credential of type "
                        + credentialType.getName() + " failed. dn=" + distinguishedName, e);
            }
            return null;
        }

        @Override
        public boolean getCredentialPersistSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
            return OtpCredentialLoader.this.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec).mayBeSupported();
        }

        @Override
        public void persistCredential(final Credential credential) throws RealmUnavailableException {
            OneTimePassword password = credential.castAndApply(PasswordCredential.class, c -> c.getPassword(OneTimePassword.class));
            try {
                Attributes attributes = new BasicAttributes();
                attributes.put(algorithmAttributeName, password.getAlgorithm());
                attributes.put(hashAttributeName, ByteIterator.ofBytes(password.getHash()).base64Encode().drainToString());
                attributes.put(seedAttributeName, password.getSeed());
                attributes.put(sequenceAttributeName, Integer.toString(password.getSequenceNumber()));

                context.modifyAttributes(distinguishedName, DirContext.REPLACE_ATTRIBUTE, attributes);
            } catch (NamingException e) {
                throw log.ldapRealmCredentialPersistingFailed(credential.toString(), distinguishedName, e);
            }
        }

        @Override public void clearCredentials() throws RealmUnavailableException {
            try {
                Attributes attributes = new BasicAttributes();
                attributes.put(new BasicAttribute(algorithmAttributeName));
                attributes.put(new BasicAttribute(hashAttributeName));
                attributes.put(new BasicAttribute(seedAttributeName));
                attributes.put(new BasicAttribute(sequenceAttributeName));

                context.modifyAttributes(distinguishedName, DirContext.REMOVE_ATTRIBUTE, attributes);
            } catch (NoSuchAttributeException e) {
                // ignore if already clear
            } catch (NamingException e) {
                throw log.ldapRealmCredentialClearingFailed(distinguishedName, e);
            }
        }
    }
}
