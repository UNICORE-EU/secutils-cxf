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

import java.util.List;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.message.MessageUtils;
import org.apache.cxf.phase.Phase;
import org.w3c.dom.Element;

import eu.unicore.security.wsutil.client.SessionIDOutHandler;

/**
 * A server-side handler that writes the security session header.
 * 
 * The outgoing session ID can be provided manually using a thread-local 
 *  
 * @author schuller
 * @author K. Benedyczak
 */
public class SessionIDServerOutHandler extends AbstractSoapInterceptor {

	private static final ThreadLocal<SecuritySession>sessions=new ThreadLocal<SecuritySession>();

	public SessionIDServerOutHandler() {
		super(Phase.PRE_PROTOCOL);
	}

	public synchronized void handleMessage(SoapMessage message) {
		try{
			if(!MessageUtils.isOutbound(message))
				return;
			
			SecuritySession session=sessions.get();

			if(session==null){
				return;
			}
			String sessionID=session.getSessionID();
			long lifetime=session.getLifetime();
			
			Element header=SessionIDOutHandler.buildHeader(sessionID, lifetime);
			if(header == null)return;

			List<Header> h = message.getHeaders();
			h.add(new Header(SessionIDOutHandler.headerQName,header));
		}
		finally{
			clear();
		}
	}

	public static void setSession(SecuritySession session){
		sessions.set(session);
	}

	public static void clear(){
		sessions.remove();
	}

}


