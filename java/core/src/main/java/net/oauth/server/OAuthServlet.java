/*
 * Copyright 2007 Netflix, Inc.
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

package net.oauth.server;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.oauth.OAuth;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;

/**
 * Utility methods for servlets that implement OAuth.
 * 
 * @author John Kristian
 */
public class OAuthServlet {

    /**
     * Extract the parts of the given request that are relevant to OAuth.
     * Parameters include OAuth Authorization headers and the usual request
     * parameters in the query string and/or form encoded body. The header
     * parameters come first, followed by the rest in the order they came from
     * request.getParameterMap().
     * 
     * @param URL
     *            the official URL of this service; that is the URL a legitimate
     *            client would use to compute the digital signature. If this
     *            parameter is null, this method will try to reconstruct the URL
     *            from the HTTP request; which may be wrong in some cases.
     */
    public static OAuthMessage getMessage(HttpServletRequest request, String URL) {
        if (URL == null) {
            URL = request.getRequestURL().toString();
        }
        return new OAuthMessage(request.getMethod(), URL,
                getParameters(request));
    }

    private static List<Map.Entry<String, String>> getParameters(
            HttpServletRequest request) {
        List<Map.Entry<String, String>> list = new ArrayList<Map.Entry<String, String>>();
        for (Enumeration headers = request.getHeaders("Authorization"); headers
                .hasMoreElements();) {
            String header = headers.nextElement().toString();
            for (OAuth.Parameter parameter : OAuthMessage
                    .decodeAuthorization(header)) {
                if (!parameter.getKey().equalsIgnoreCase("realm")) {
                    list.add(parameter);
                }
            }
        }
        for (Object e : request.getParameterMap().entrySet()) {
            Map.Entry entry = (Map.Entry) e;
            String name = entry.getKey().toString();
            for (String value : (String[]) entry.getValue()) {
                list.add(new OAuth.Parameter(name, value));
            }
        }
        return list;
    }

    /** Reconstruct the requested URL, complete with query string (if any). */
    public static String getRequestURL(HttpServletRequest request) {
        StringBuffer url = request.getRequestURL();
        String queryString = request.getQueryString();
        if (queryString != null) {
            url.append("?").append(queryString);
        }
        return url.toString();
    }

    public static void handleException(HttpServletResponse response,
            Exception e, String realm) throws IOException, ServletException {
        if (e instanceof OAuthProblemException) {
            OAuthProblemException problem = (OAuthProblemException) e;
            Object httpCode = problem.getParameters().get(
                    OAuthProblemException.HTTP_STATUS_CODE);
            if (httpCode == null) {
                httpCode = PROBLEM_TO_HTTP_CODE.get(problem.getProblem());
            }
            if (httpCode == null) {
                httpCode = SC_FORBIDDEN;
            }
            response.reset();
            response.setStatus(Integer.parseInt(httpCode.toString()));
            OAuthMessage message = new OAuthMessage(null, null, problem
                    .getParameters().entrySet());
            response.addHeader("WWW-Authenticate", message
                    .getAuthorizationHeader(realm));
            sendForm(response, message.getParameters());
        } else if (e instanceof IOException) {
            throw (IOException) e;
        } else if (e instanceof ServletException) {
            throw (ServletException) e;
        } else if (e instanceof RuntimeException) {
            throw (RuntimeException) e;
        } else {
            throw new ServletException(e);
        }
    }

    private static final Integer SC_FORBIDDEN = new Integer(
            HttpServletResponse.SC_FORBIDDEN);

    private static final Map<String, Integer> PROBLEM_TO_HTTP_CODE = new HashMap<String, Integer>();
    static {
        Integer SC_BAD_REQUEST = new Integer(HttpServletResponse.SC_BAD_REQUEST);
        Integer SC_SERVICE_UNAVAILABLE = new Integer(
                HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        PROBLEM_TO_HTTP_CODE.put("version_rejected", SC_BAD_REQUEST);
        PROBLEM_TO_HTTP_CODE.put("parameter_absent", SC_BAD_REQUEST);
        PROBLEM_TO_HTTP_CODE.put("parameter_rejected", SC_BAD_REQUEST);
        PROBLEM_TO_HTTP_CODE.put("timestamp_refused", SC_BAD_REQUEST);
        PROBLEM_TO_HTTP_CODE.put("signature_method_rejected", SC_BAD_REQUEST);
        PROBLEM_TO_HTTP_CODE
                .put("consumer_key_refused", SC_SERVICE_UNAVAILABLE);
    }

    /** Send the given parameters as a form-encoded response body. */
    public static void sendForm(HttpServletResponse response,
            Iterable<? extends Map.Entry> parameters) throws IOException {
        response.resetBuffer();
        response.setContentType(OAuth.FORM_ENCODED + ";charset="
                + OAuth.ENCODING);
        OAuth.formEncode(parameters, response.getOutputStream());
    }

}
