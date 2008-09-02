/*
 * Copyright 2008 Netflix, Inc.
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

package net.oauth.client;

import java.io.IOException;
import net.oauth.OAuth;
import net.oauth.OAuthMessage;

/**
 * An HTTP response, encapsulated as an OAuthMessage.
 * 
 * @author John Kristian
 */
public abstract class OAuthResponseMessage extends OAuthMessage {

    protected OAuthResponseMessage(String method, String URL)
            throws IOException {
        super(method, URL, NO_PARAMETERS);
    }

    protected void decodeWWWAuthenticate(String header) {
        for (OAuth.Parameter parameter : decodeAuthorization(header)) {
            if (!"realm".equalsIgnoreCase(parameter.getKey())) {
                addParameter(parameter);
            }
        }
    }

    @Override
    protected void completeParameters() throws IOException {
        addParameters(OAuth.decodeForm(getBodyAsString()));
    }

    /**
     * Decide whether a message with the given Content-Type can be decoded as
     * OAuth parameters.
     */
    protected boolean isDecodable(String contentType) {
        if (contentType != null) {
            int sep = contentType.indexOf(';');
            String mimeType = (sep < 0) ? contentType : contentType.substring(
                    0, sep);
            mimeType = mimeType.trim();
            if ("text/html".equalsIgnoreCase(mimeType)) {
                return false;
            }
        }
        return true;
    }
}
