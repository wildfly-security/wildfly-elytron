/*
 * JBoss, Home of Professional Open Source
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.ldap;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.wildfly.security.auth.provider.ldap.AttributeMapping;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.MapAttributes;

import javax.naming.InvalidNameException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.ldap.LdapName;

import java.util.Arrays;

/**
 * Test case to test creating and removing identities in LDAP
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class ModifiabilityTest {

    @ClassRule
    public static DirContextFactoryRule dirContextFactory = new DirContextFactoryRule();
    private static SecurityRealm realm;

    @BeforeClass
    public static void createRealm() throws InvalidNameException {

        Attributes attributes = new BasicAttributes(true); // ldap attributes of new identity
        BasicAttribute objectClass = new BasicAttribute("objectClass");
        objectClass.add("top");
        objectClass.add("inetOrgPerson");
        objectClass.add("person");
        objectClass.add("organizationalPerson");
        attributes.put(objectClass);
        attributes.put(new BasicAttribute("sn", "aaa"));
        attributes.put(new BasicAttribute("cn", "bbb"));
        attributes.put(new BasicAttribute("description", "new user"));

        realm = LdapSecurityRealmBuilder.builder()
            .setDirContextFactory(dirContextFactory.create())
            .identityMapping()
                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                .setRdnIdentifier("uid")
                .map(AttributeMapping.from("uid").to("userName"), // mapping ldap attributes to elytron attributes
                     AttributeMapping.from("cn").to("firstName"),
                     AttributeMapping.from("sn").to("lastName"),
                     AttributeMapping.from("description").to("description"),
                     AttributeMapping.from("telephoneNumber").to("phones"),
                     AttributeMapping.fromFilter("ou=Finance,dc=elytron,dc=wildfly,dc=org", "(&(objectClass=groupOfNames)(member={0}))", "CN").asRdn("OU").to("businessArea"))
                .setNewIdentityParent(new LdapName("dc=elytron,dc=wildfly,dc=org"))
                .setNewIdentityAttributes(attributes)
                .build()
            .build();
    }

    @Test
    public void testCreateDelete() throws RealmUnavailableException, InterruptedException {
        ModifiableRealmIdentity identity = (ModifiableRealmIdentity) realm.getRealmIdentity("myNewIdentity", null, null);
        Assert.assertFalse(identity.exists());
        identity.create();

        identity = (ModifiableRealmIdentity) realm.getRealmIdentity("myNewIdentity", null, null);
        Assert.assertTrue(identity.exists());
        identity.delete();

        identity = (ModifiableRealmIdentity) realm.getRealmIdentity("myNewIdentity", null, null);
        Assert.assertFalse(identity.exists());
    }

    @Test
    public void testCreateDeleteEscaped() throws RealmUnavailableException, InterruptedException {
        String horribleIdentityName = " escape testing identity name , \\ # + < > ; \" = / * ( ) . & - _ [ ] ` ~ | @ $ % ^ ? : { } ! ' ";

        ModifiableRealmIdentity identity = (ModifiableRealmIdentity) realm.getRealmIdentity(horribleIdentityName, null, null);
        Assert.assertFalse(identity.exists());
        identity.create();

        identity = (ModifiableRealmIdentity) realm.getRealmIdentity(horribleIdentityName, null, null);
        Assert.assertTrue(identity.exists());
        identity.delete();

        identity = (ModifiableRealmIdentity) realm.getRealmIdentity(horribleIdentityName, null, null);
        Assert.assertFalse(identity.exists());
    }

    @Test
    public void testAttributeSetting() throws Exception {
        ModifiableRealmIdentity identity = (ModifiableRealmIdentity) realm.getRealmIdentity("myNewAttributesIdentity");
        Assert.assertFalse(identity.exists());
        identity.create();

        MapAttributes newAttributes = new MapAttributes();
        newAttributes.addFirst("userName", "JohnSmithsNewIdentity");
        newAttributes.addFirst("firstName", "John");
        newAttributes.addFirst("lastName", "Smith");
        newAttributes.addAll("phones", Arrays.asList("123456", "654321"));
        identity.setAttributes(newAttributes);

        identity = (ModifiableRealmIdentity) realm.getRealmIdentity("myNewAttributesIdentity");
        Assert.assertFalse(identity.exists());

        identity = (ModifiableRealmIdentity) realm.getRealmIdentity("JohnSmithsNewIdentity");
        Assert.assertTrue(identity.exists());

        org.wildfly.security.authz.Attributes attributes = identity.getAuthorizationIdentity().getAttributes();
        Assert.assertEquals("JohnSmithsNewIdentity", attributes.get("userName").get(0));
        Assert.assertEquals("John", attributes.get("firstName").get(0));
        Assert.assertEquals("Smith", attributes.get("lastName").get(0));
        Assert.assertEquals(0, attributes.get("description").size());
        Assert.assertEquals(2, attributes.get("phones").size());
    }

    @Test
    public void testAttributeSettingEscaped() throws Exception {
        ModifiableRealmIdentity identity = (ModifiableRealmIdentity) realm.getRealmIdentity(" myNewAttributesIdentity , \\ # + < > ; \" = / * ( ) . & - _ [ ] ` ~ | @ $ % ^ ? : { } ! '");
        Assert.assertFalse(identity.exists());
        identity.create();

        MapAttributes newAttributes = new MapAttributes();
        newAttributes.addFirst("userName", " JohnSmithsNewIdentity , \\ # + < > ; \" = / * ( ) . & - _ [ ] ` ~ | @ $ % ^ ? : { } ! '");
        newAttributes.addFirst("firstName", "John");
        newAttributes.addFirst("lastName", "Smith");
        newAttributes.addAll("phones", Arrays.asList("123456", "654321"));
        identity.setAttributes(newAttributes);

        identity = (ModifiableRealmIdentity) realm.getRealmIdentity(" myNewAttributesIdentity , \\ # + < > ; \" = / * ( ) . & - _ [ ] ` ~ | @ $ % ^ ? : { } ! '");
        Assert.assertFalse(identity.exists());

        identity = (ModifiableRealmIdentity) realm.getRealmIdentity(" JohnSmithsNewIdentity , \\ # + < > ; \" = / * ( ) . & - _ [ ] ` ~ | @ $ % ^ ? : { } ! '");
        Assert.assertTrue(identity.exists());

        org.wildfly.security.authz.Attributes attributes = identity.getAuthorizationIdentity().getAttributes();
        Assert.assertEquals(" JohnSmithsNewIdentity , \\ # + < > ; \" = / * ( ) . & - _ [ ] ` ~ | @ $ % ^ ? : { } ! '", attributes.get("userName").get(0));
        Assert.assertEquals("John", attributes.get("firstName").get(0));
        Assert.assertEquals("Smith", attributes.get("lastName").get(0));
        Assert.assertEquals(0, attributes.get("description").size());
        Assert.assertEquals(2, attributes.get("phones").size());
    }

}
