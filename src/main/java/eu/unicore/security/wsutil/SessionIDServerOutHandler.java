/*********************************************************************************
 * Copyright (c) 2013 Forschungszentrum Juelich GmbH 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * (1) Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the disclaimer at the end. Redistributions in
 * binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * 
 * (2) Neither the name of Forschungszentrum Juelich GmbH nor the names of its 
 * contributors may be used to endorse or promote products derived from this 
 * software without specific prior written permission.
 * 
 * DISCLAIMER
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ********************************************************************************/

package eu.unicore.security.wsutil;

import java.io.ByteArrayInputStream;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.message.MessageUtils;
import org.apache.cxf.phase.Phase;
import org.w3c.dom.Element;

/**
 * A server-side handler that writes the security session header.
 * 
 * The outgoing session ID can be provided manually using a thread-local 
 *  
 * @author schuller
 * @author K. Benedyczak
 */
public class SessionIDServerOutHandler extends AbstractSoapInterceptor {

	private static final ThreadLocal<String>sessionIDs=new ThreadLocal<String>();

	/**
	 * used to store the session ID in the security tokens
	 */
	public static final String SESSION_ID_KEY="unicore-security-session-id";

	/**
	 * used to mark that the security tokens were taken from an existing session
	 */
	public static final String REUSED_MARKER_KEY="reused-unicore-security-session";

	/*
	 * this is placed into the message to indicate that the client understands
	 * session IDs. In this way, the server will not create new sessions all the time for
	 * "old" clients that do not know about sessions
	 */
	public static final String SESSION_ID_REQUEST="request-new-unicore-security-session";

	//header namespace
	public static final String CG_HEADER_NS="http://www.unicore.eu/unicore/ws";

	//header element name
	public static final String CG_HEADER="SecuritySessionID";

	public final static QName headerQName=new QName(CG_HEADER_NS,CG_HEADER);

	public SessionIDServerOutHandler() {
		super(Phase.PRE_PROTOCOL);
	}

	public synchronized void handleMessage(SoapMessage message) {
		try{
			if(!MessageUtils.isOutbound(message))
				return;
			
			String sessionID=getSessionID();
			
			if(sessionID==null){
				return;
			}
			
			Element header=buildHeader(sessionID);
			if(header == null)return;

			List<Header> h = message.getHeaders();
			h.add(new Header(headerQName,header));
		}
		finally{
			clear();
		}
	}
	
	public Element buildHeader(String sessionID) {
		Element header=null;
		try{
			if(sessionID==null) return null;

			StringBuilder sb=new StringBuilder();
			sb.append("<sid:"+CG_HEADER+" xmlns:sid=\""+CG_HEADER_NS+"\">");
			sb.append(sessionID);
			sb.append("</sid:"+CG_HEADER+">");
			try{
				header= DOMUtils.readXml(
						new ByteArrayInputStream(sb.toString().getBytes())).getDocumentElement();
			}catch(Exception e){
				throw new RuntimeException(e);
			}
		}catch(Exception e){

		}

		return header;
	}

	public static void setSessionID(String sessionID){
		sessionIDs.set(sessionID);
	}

	public static String getSessionID(){
		return sessionIDs.get();
	}
	
	public static void clear(){
		sessionIDs.remove();
	}

}

