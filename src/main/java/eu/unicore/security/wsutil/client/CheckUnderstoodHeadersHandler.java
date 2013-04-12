/*********************************************************************************
 * Copyright (c) 2006-2012 Forschungszentrum Juelich GmbH 
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

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.xml.namespace.QName;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.ws.addressing.Names;

/**
 * A hack to let wsrflite accept various handlers. XFire doesn't 
 * seem to search for understood headers in service's handlers, 
 * only in global ones.
 * This class is thread safe, i.e. one can dynamically add or remove QNames at runtime.
 * 
 * @author schuller
 * @author golbi
 */
public class CheckUnderstoodHeadersHandler extends AbstractSoapInterceptor {

	private final Set<QName> understoodHeaders=new HashSet<QName>();
	private final ReadWriteLock rwLock = new ReentrantReadWriteLock();
	
	//default headers that the stack understands. This can be
	//important what talking to clients/servers that are not XFire,
	//and which set the SOAP mustUnderstand flag on these headers
	public static final QName[] defaultHeaders =new QName[]{
		Names.WSA_ACTION_QNAME,
		Names.WSA_ADDRESS_QNAME,
		Names.WSA_FROM_QNAME,
		Names.WSA_TO_QNAME,
		Names.WSA_FAULTTO_QNAME,
		Names.WSA_REPLYTO_QNAME,
		Names.WSA_MESSAGEID_QNAME,
		Names.WSA_RELATESTO_QNAME,
	}; 
	
	/**
	 * add a handler which claims to understand the default list of headers
	 * @see CheckUnderstoodHeadersHandler#defaultHeaders
	 */
	public CheckUnderstoodHeadersHandler()
	{
		super(Phase.PRE_PROTOCOL);
		addUnderstoodHeaders(defaultHeaders);
	}
	
	public void addUnderstoodHeaders(QName[] qn){
		rwLock.writeLock().lock();
		for(int l=0;l<qn.length;l++)understoodHeaders.add(qn[l]);
		rwLock.writeLock().unlock();
	}

	@Override
	public Set<QName> getUnderstoodHeaders() {
		rwLock.readLock().lock();
		Set<QName> ret = new HashSet<QName>();
		ret.addAll(understoodHeaders);
		rwLock.readLock().unlock();
		return ret;
	}

	@Override
	public void handleMessage(SoapMessage message) throws Fault {
	}
	
}
