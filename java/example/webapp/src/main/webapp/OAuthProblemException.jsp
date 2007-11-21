<%@page import="java.util.Map"%>
<%@page import="net.oauth.OAuthProblemException"%>
<%@page import="net.oauth.example.consumer.webapp.CookieConsumer"%>
<HTML>
<body>
<jsp:include page="/banner.jsp" />
OAuthProblemException:<br/>
<form>
<table>
<%
    OAuthProblemException p = (OAuthProblemException) request.getAttribute("OAuthProblemException");
    for (Map.Entry<String, Object> parameter : p.getParameters().entrySet()) {
        Object v = parameter.getValue();
        if (v != null) {
        String value = v.toString();
        %>
    <tr valign="top">
        <td align="right"><%=CookieConsumer.htmlEncode(parameter.getKey())%>:&nbsp;</td>
        <td><%
            if (value == null) {
                %>&nbsp;<%
            } else if (value.length() < 60 && value.indexOf('\n') < 0) {
                %><%=CookieConsumer.htmlEncode(value)%><%
            } else {
                %><textarea cols="60" rows="4" wrap="off" readonly="true"><%=CookieConsumer.htmlEncode(value)%></textarea><%
            }
            %></td>
    </tr><%
        }
    }
%>
</table>
</form>
</body>
</HTML>
