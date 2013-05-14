/*********************************************************************************
 * Copyright (c) 2006 Forschungszentrum Juelich GmbH 
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

import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.jws.WebMethod;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.interceptor.Interceptor;
import org.apache.cxf.message.Message;
import org.apache.log4j.Logger;

import eu.unicore.security.wsutil.OperationsRequiringSignature;
import eu.unicore.security.wsutil.RequiresSignature;
import eu.unicore.util.Log;
import eu.unicore.util.httpclient.DefaultClientConfiguration;
import eu.unicore.util.httpclient.IClientConfiguration;

/**
 * Extends {@link eu.unicore.security.wsutil.client.WSClientFactory}. 
 * Clients returned by this factory has, in addition to what is set up by the parent class,
 * ETD and digital signature handlers configured. Also all other additional handlers which 
 * are configured in the {@link IClientConfiguration} are installed.
 * 
 * @author schuller
 * @author golbi
 */
public class UnicoreWSClientFactory extends WSClientFactory
{
	private static final Logger logger=Log.getLogger(Log.CLIENT, UnicoreWSClientFactory.class);

	protected final IClientConfiguration security;
	private ContextDSigDecider decider;
	
	/**
	 * Uses {@link JSR181ServiceFactory} and {@link AbstractClientConfiguration} what
	 * means that whole security is turned off.
	 */
	public UnicoreWSClientFactory(){
		this(new DefaultClientConfiguration());
	}
	
	/**
	 * Constructor allowing to set all parameters. 
	 * @param serviceFactory {@link ServiceFactory} to be used
	 * @param sec security and client settings
	 */
	public UnicoreWSClientFactory(IClientConfiguration sec){
		super(sec);
		this.security=(IClientConfiguration) securityProperties;
	}
	
	@Override
	protected void initHandlers(){
		super.initHandlers();
		decider = new ContextDSigDecider();
		
		IClientConfiguration security = (IClientConfiguration) securityProperties;
		
		addHandlers(outHandlers, security.getOutHandlerClassNames());
		if (security.doSignMessage()){
			outHandlers.add(new OnDemandSAAJOutInterceptor(decider));
			outHandlers.add(new DSigOutHandler(security.getCredential(), decider));
		}
			
		if (security.getETDSettings() != null)
			outHandlers.add(new ExtendedTDOutHandler(security));

		addHandlers(inHandlers, security.getInHandlerClassNames());
	}
	
	@SuppressWarnings("unchecked")
	private Class<Interceptor<? extends Message>>loadClass(String name) throws ClassNotFoundException{
		IClientConfiguration security = (IClientConfiguration) securityProperties;
		if(security.getClassLoader()!=null){
			return (Class<Interceptor<? extends Message>>)Class.forName(name,true,security.getClassLoader());
		}
		else{
			return (Class<Interceptor<? extends Message>>)Class.forName(name);
		}
	}
	
	private void addHandlers(List<Interceptor<? extends Message>> list, String[] handlers) {
		if (handlers == null) 
			return;
		for (String className: handlers) {
			if (className!=null && className.length()!=0) {
				try{
					Class<? extends Interceptor<? extends Message>> clazz=loadClass(className);
					Interceptor<? extends Message> h=(Interceptor<? extends Message>)clazz.newInstance();
					if(h instanceof Configurable){
						//initialise the handler with our client security properties
						((Configurable) h).configure((IClientConfiguration) securityProperties);
					}
					list.add(h);
					logger.debug("Sucessfully added security handler <"+className+">");
				}catch(Exception e){
					logger.error("Could not setup security handler <"+className+"!", e);
				}
			}
			else logger.debug("No security handlers added.");
		}
	}

	@Override
	protected <T> void setupProxyInterface(Class<T> iFace, Client xfireClient)
	{
		super.setupProxyInterface(iFace, xfireClient);
		xfireClient.getRequestContext().put(ContextDSigDecider.SIGNED_OPERATIONS, 
				getOperationsToSign(iFace));
	}

	public static <T> Set<String> getOperationsToSign(Class<T> iFace)
	{
		Set<String> opsToSign = new HashSet<String>();
		OperationsRequiringSignature list = 
			iFace.getAnnotation(OperationsRequiringSignature.class);
		if (list != null)
			for (String s: list.operations())
				opsToSign.add(s);
		Method[] methods = iFace.getMethods();
		for (Method m: methods)
		{
			if (m.getAnnotation(RequiresSignature.class) != null)
			{
				WebMethod wm = m.getAnnotation(WebMethod.class);
				if (wm != null && wm.action() != null && 
						!wm.action().equals(""))
				{
					opsToSign.add(wm.action());
					continue;
				} else
				{
					logger.warn("Method <" + m.getName() + "> is marked as requiring a " +
							"signature but no SOAP action is defined for it. " +
							"This method invocations won't be signed.");
				}
					
			}
		}
		return opsToSign;
	}
}
