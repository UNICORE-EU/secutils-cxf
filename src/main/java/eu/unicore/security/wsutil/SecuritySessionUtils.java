/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.wsutil;

import java.io.ByteArrayInputStream;

import javax.xml.namespace.QName;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.headers.Header;
import org.apache.cxf.helpers.DOMUtils;
import org.w3c.dom.Element;


/**
 * Utility classes for creating session header element and checking up the current message context. 
 * @author B. Schuller
 * @author K. Benedyczak
 */
public class SecuritySessionUtils
{
	//header namespace
	public static final String SESSION_HDR_NS="http://www.unicore.eu/unicore/ws";

	//header element name
	public static final String SESSION_HEADER="SecuritySession";

	public final static QName headerQName=new QName(SESSION_HDR_NS,SESSION_HEADER);

	public final static QName idQName=new QName(SESSION_HDR_NS,"ID");
	public final static QName ltQName=new QName(SESSION_HDR_NS,"Lifetime");

	/**
	 * Client side: context key of a url of a destination endpoint
	 */
	public static final String SESSION_TARGET_URL="unicore-security-session-target-url";
	
	/**
	 * Server side: used to store the session ID in the security tokens
	 */
	public static final String SESSION_ID_KEY="unicore-security-session-id";

	/**
	 * Server and client side. On the server side used to mark that the security tokens were taken 
	 * from an existing session. On client side marks that session is used for the outgoing call and the value is 
	 * the session id. 
	 */
	public static final String REUSED_MARKER_KEY="reused-unicore-security-session";
	
	/**
	 * 
	 * @param sessionID
	 * @param lifetime - if larger than -1, the lifetime info will be added to the element
	 * @return
	 */
	public static Header buildHeader(String sessionID, long lifetime) {
		//TODO - use DOM API directly
		Element headerEl=null;
		StringBuilder sb=new StringBuilder();
		sb.append("<sid:"+SESSION_HEADER+" xmlns:sid=\""+SESSION_HDR_NS+"\">");
		sb.append("<sid:ID>"+sessionID+"</sid:ID>");
		if (lifetime > -1)
			sb.append("<sid:Lifetime>"+lifetime+"</sid:Lifetime>");
		sb.append("</sid:"+SESSION_HEADER+">");
		try{
			byte[] asBytes = sb.toString().getBytes();
			headerEl = DOMUtils.readXml(new ByteArrayInputStream(asBytes)).getDocumentElement();
		}catch(Exception e){
			throw new RuntimeException(e);
		}
		
		return new Header(headerQName, headerEl);
	}

	public static boolean haveSessionID(SoapMessage message)
	{
		return message.getContextualProperty(REUSED_MARKER_KEY) != null;
	}

	public static String getSecuritySessionID(SoapMessage message)
	{
		String sessionID=null;
		Header header=message.getHeader(SecuritySessionUtils.headerQName);
		if(header!=null){
			Element hdr = (Element) header.getObject();		
			if(hdr!=null)
				sessionID = hdr.getTextContent(); 
		}
		return sessionID;
	}
}
