/*
 * JBoss, Home of Professional Open Source
 * Copyright 2017 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.tool;

import java.util.Random;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

/**
 * Test for "credential-store" command where are tested aliasNames and aliasValues which contains special characters, null or
 * empty values.
 *
 * @author Hynek Švábek <hsvabek@redhat.com>
 */
public class CredentialStoreCommandInputTest extends AbstractCommandTest {

    protected static final String SPECIAL_CHARS = "@!#?$%^&*()%+-{}<>|\"";
    protected static final String CHINESE_CHARS = "用戶名";
    protected static final String ARABIC_CHARS = "اسمالمستخدم";
    protected static final String JAPANESE_CHARS = "ユーザー名";
    protected static final int COUNT_OF_CHARACTERS = 8192;

    @Override
    protected String getCommandType() {
        return CredentialStoreCommand.CREDENTIAL_STORE_COMMAND;
    }

    @Test
    public void testChineseCharacters() throws Exception {
        testCharactersAliasNameAndAliasValue(CHINESE_CHARS);
    }

    @Test
    public void testArabicCharacters() throws Exception {
        testCharactersAliasNameAndAliasValue(ARABIC_CHARS);
    }

    @Test
    public void testJapaneseCharacters() throws Exception {
        testCharactersAliasNameAndAliasValue(JAPANESE_CHARS);
    }

    @Test
    public void testSpecialCharacters() throws Exception {
        testCharactersAliasNameAndAliasValue(SPECIAL_CHARS);
    }

    @Test
    public void testLongAliasNameOrValue() throws Exception {
        Random random = new Random();
        String longString = random.ints(32, 127).limit(COUNT_OF_CHARACTERS)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
        testCharactersAliasNameAndAliasValue(longString);
    }

    @Test
    public void testNullValue() throws Exception {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String[] aliasNames = { null, "testalias1", null };
        String[] aliasValues = { "secretValue", null, null };

        for (int i = 0; i < aliasNames.length; i++) {
            try {
                createStoreAndAddAliasAndCheck(storageLocation, storagePassword, aliasNames[i], aliasValues[i]);
            } catch (RuntimeException e) {
                if (!(e.getCause() instanceof NullPointerException)) {
                    Assert.fail("It must fail with NullPointerException.");
                }
            }
        }
    }

    @Test
    @Ignore("https://issues.jboss.org/browse/ELY-1054")
    public void testEmptyValue() throws Exception {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String[] aliasNames = { "", "testalias1", "" };
        String[] aliasValues = { "secretValue", "", "" };

        for (int i = 0; i < aliasNames.length; i++) {
            try {
                createStoreAndAddAliasAndCheck(storageLocation, storagePassword, aliasNames[i], aliasValues[i]);
            } catch (RuntimeException e) {
                if (!(e.getCause() instanceof NullPointerException)) {
                    Assert.fail("It must fail because of there is forbidden to use empty alias name or value.");
                }
            }
        }
    }

    private void testCharactersAliasNameAndAliasValue(String specialChars) throws Exception {
        String storageLocation = getStoragePathForNewFile();

        String storagePassword = "cspassword";
        String[] aliasNames = { specialChars, "testalias1", specialChars };
        String[] aliasValues = { "secretValue", specialChars, specialChars };

        for (int i = 0; i < aliasNames.length; i++) {
            createStoreAndAddAliasAndCheck(storageLocation, storagePassword, aliasNames[i], aliasValues[i]);
        }
    }
}
