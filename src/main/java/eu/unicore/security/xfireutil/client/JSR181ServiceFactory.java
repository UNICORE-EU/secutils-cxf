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
 

package eu.unicore.security.xfireutil.client;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import javax.jws.WebMethod;
import javax.jws.WebService;
import javax.xml.namespace.QName;

import org.codehaus.xfire.addressing.AddressingOperationInfo;
import org.codehaus.xfire.addressing.EndpointReference;
import org.codehaus.xfire.service.OperationInfo;
import org.codehaus.xfire.service.Service;
import org.codehaus.xfire.transport.TransportManager;
import org.codehaus.xfire.xmlbeans.XmlBeansServiceFactory;


/**
 * process JSR181 annotations to setup the service
 * @author schuller
 */
public class JSR181ServiceFactory extends XmlBeansServiceFactory {
	
	private String to;
	private EndpointReference replyTo;
	private EndpointReference faultTo;
	
	public JSR181ServiceFactory() {
		super();
	}

	public JSR181ServiceFactory(TransportManager arg0) {
		super(arg0);
	}

	public void setTo(String to){this.to=to;}
	
	public void setReplyTo(EndpointReference to){this.replyTo=to;}
	
	public void setFaultTo(EndpointReference to){this.faultTo=to;}
	
	/**
	 * Generate OperationInfo, such as the WSAddressing action
	 */
	@Override
	protected OperationInfo addOperation(Service endpoint, Method method, String style) {
		OperationInfo oi=super.addOperation(endpoint, method, style);
		String inAction=getAction(oi);
		AddressingOperationInfo aoi=new AddressingOperationInfo(inAction,oi);
		aoi.setInAction(inAction);
		if(to!=null)aoi.setTo(to);
		if(replyTo!=null)aoi.setReplyTo(replyTo);
		if(faultTo!=null)aoi.setFaultTo(faultTo);
		//TODO others...
		oi.setProperty(AddressingOperationInfo.ADDRESSING_OPERATION_KEY,aoi);
		return oi;
	}

	/**
	 * retrieves the wsa:Action
	 */
	@Override
	protected String getAction(OperationInfo oi){
		Method m=oi.getMethod();
		WebMethod wsrfInfo=(WebMethod)m.getAnnotation(WebMethod.class);
		if(wsrfInfo==null){
			return super.getAction(oi);
		}
		return wsrfInfo.action();
	}
	/**
	 * checks whether the given method should be exposed as a webservice,
	 * these have to be annotated with the WebMethod annotation
	 */
	@Override
    protected boolean isValidMethod(final Method method)
    {
    	if(method.getAnnotation(WebMethod.class)==null)return false;
    	return super.isValidMethod(method);
    }

    /**
     * get the target namespace
     */
    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    protected String getTargetNamespace(Class clazz){
    	WebService ws=(WebService)clazz.getAnnotation(WebService.class);
    	if(ws==null) return super.getTargetNamespace(clazz);
    	return ws.targetNamespace();
    }
    
    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public Service create(Class clazz, String name, String namespace, Map properties)
    {
    	if(properties==null)properties=new HashMap();
    	QName portType = (QName) properties.get(PORT_TYPE);
    	if(portType==null){
    		portType=getPortType(clazz);
    		if(portType!=null)properties.put(PORT_TYPE,portType);
    	}
    	return super.create(clazz,name,namespace,properties);
    }
    
    /**
     * return the porttype
     */
    protected QName getPortType(Class<?> clazz){
    	WebService ws=(WebService)clazz.getAnnotation(WebService.class);
    	if(ws!=null) {
    		return new QName(getTargetNamespace(clazz),ws.portName());
    	}
    	return null;
    }
    
}
