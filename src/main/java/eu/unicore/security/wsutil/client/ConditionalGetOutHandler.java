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

package eu.unicore.security.wsutil.client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.message.MessageUtils;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Element;

import eu.unicore.util.Log;

/**
 * A WS client handler that allows to perform a "conditional get", i.e. 
 * clients use this to ask the the server to *not* send resource property data 
 * if they have not changed. This mimics the corresponding HTTP mechanism 
 * (ETag and last-modified)
 * 
 * The Etag and last-modified values must be put into thread-local storage before making the WS call
 * 
 * @author schuller
 */
public class ConditionalGetOutHandler extends AbstractSoapInterceptor {

	private static final Logger logger = Log.getLogger(Log.CLIENT,ConditionalGetOutHandler.class);

	private static final ThreadLocal<String>etags=new ThreadLocal<String>();
	private static final ThreadLocal<String>lastModified=new ThreadLocal<String>();

	//header namespace
	public static final String CG_HEADER_NS="http://www.unicore.eu/unicore/ws";

	//header element name
	public static final String CG_HEADER="ConditionalGet";

	private final static QName headerQName=new QName(CG_HEADER_NS,CG_HEADER);

	public ConditionalGetOutHandler() {
		super(Phase.PRE_PROTOCOL);
		getBefore().add(DSigOutHandler.class.getName());
	}


	public Element buildHeader() {
		Element header=null;
		try{
			String etag=etags.get();
			String modifiedTime=lastModified.get();
			if(etag == null && modifiedTime == null) return null;

			StringBuilder sb=new StringBuilder();
			sb.append("<cget:"+CG_HEADER+" xmlns:cget=\""+CG_HEADER_NS+"\">");
			if(etag!=null)sb.append("<cget:IfNoneMatch>"+etag+"</cget:IfNoneMatch>");
			if(modifiedTime!=null)sb.append("<cget:IfModifiedSince>"+modifiedTime+"</cget:IfModifiedSince>");

			sb.append("</cget:"+CG_HEADER+">");
			try{
				InputStream is = new ByteArrayInputStream(sb.toString().getBytes());
				header = StaxUtils.read(is).getDocumentElement();
			}catch(Exception e){
				throw new RuntimeException(e);
			}

			if(logger.isDebugEnabled()){
				logger.debug("(Re-)initialised outhandler");
				try{
					ByteArrayOutputStream bos = new ByteArrayOutputStream();
					StaxUtils.writeTo(header, bos);
					logger.debug(bos.toString());
				}catch(Exception e){
					logger.warn("",e);
				}
			}
		}catch(Exception e){

		}

		return header;
	}

	public synchronized void handleMessage(SoapMessage message) {
		try{
			if(!MessageUtils.isOutbound(message))
				return;

			Element header=buildHeader();
			if(header == null)return;

			List<Header> h = message.getHeaders();
			h.add(new Header(headerQName,header));
		}
		finally{
			etags.remove();
			lastModified.remove();
		}
	}

	public static void setEtag(String etag){
		etags.set(etag);
	}

	public static void setLastModified(String time){
		lastModified.set(time);
	}

}


