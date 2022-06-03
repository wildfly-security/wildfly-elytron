/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.wildfly.security.tool.help;

import org.aesh.readline.terminal.formatting.CharacterType;
import org.aesh.readline.terminal.formatting.Color;
import org.aesh.readline.terminal.formatting.TerminalColor;
import org.aesh.readline.terminal.formatting.TerminalString;
import org.aesh.readline.terminal.formatting.TerminalTextStyle;

/**
 * General section of Elytron help command
 * All Elytron help command sections should extend this one
 *
 * @author <a href="mailto:pberan@redhat.com">Petr Beran</a>
 */
public abstract class HelpSection {

    final int leftPadding = 4;
    final int lineWidth = 120;
    final int textWidth = lineWidth - leftPadding;

    /**
     * Displays help of specific section
     */
    public abstract void printHelp();

    /**
     * Formats and prints a simple block of text
     * For printing commands see {@link CommandsSection}
     *
     * @param text Text to print
     */
    protected void formatAndPrintText(final CharSequence text) {
        final StringBuilder stringBuilder = new StringBuilder();
        CharSequence contentText = text;
        while(0 < contentText.length()) {
            appendGap(stringBuilder, leftPadding);

            // If the text fits one line, simply append it and end the while loop
            if (contentText.length() <= textWidth) {
                stringBuilder.append(contentText);
                stringBuilder.append(System.lineSeparator());
                break;
            }

            int lineIndex = checkForWhitespaceIndex(contentText, textWidth);

            // Append the text that fits on a single line and remove it from the contentText
            stringBuilder.append(contentText.subSequence(0,lineIndex));
            contentText = contentText.subSequence(lineIndex+1, contentText.length());
            stringBuilder.append(System.lineSeparator());
        }
        System.out.print(stringBuilder);
    }

    /**
     * Formats headers across all sections
     *
     * @param sectionTitle Title to format
     * @return Formatted section title
     */
    protected String formatTitle(String sectionTitle) {
        TerminalColor terminalColor = new TerminalColor(Color.CYAN, Color.DEFAULT, Color.Intensity.BRIGHT);
        return new TerminalString(sectionTitle.toUpperCase(), terminalColor, new TerminalTextStyle(CharacterType.BOLD)).toString();
    }

    /**
     * Finds the index of text that still fits on a single line and is a whitespace.
     * We don't want to break words at the end of the line
     *
     * @param text Text to iterate
     * @param maxWidth Max width of the line, start of the iteration
     * @return Last whitespace index before the end of the line
     */
    protected int checkForWhitespaceIndex(CharSequence text, int maxWidth) {
        int lastWhitespaceIndex = maxWidth;
        while (0 <= lastWhitespaceIndex && !Character.isWhitespace(text.charAt(lastWhitespaceIndex))) {
            lastWhitespaceIndex--;
        }
        return lastWhitespaceIndex;
    }

    /**
     * Appends a gap of certain width
     *
     * @param text Text to which the gap should be appended
     * @param gapWidth Width of the gap
     */
    protected void appendGap(StringBuilder text, int gapWidth) {
        for (int i = 0; i < gapWidth; i++){
            text.append(' ');
        }
    }
}
