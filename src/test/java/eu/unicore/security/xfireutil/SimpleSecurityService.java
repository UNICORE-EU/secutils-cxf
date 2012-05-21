/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 16, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.xfireutil;

import java.rmi.RemoteException;

import javax.jws.WebMethod;
import javax.jws.WebService;

/**
 * @author K. Benedyczak
 */
@WebService()
@OperationsRequiringSignature(operations={"TestSignature2Action"})
public interface SimpleSecurityService
{
	@WebMethod()
	public String TestIP() throws RemoteException;
	@WebMethod()
	public String TestConsignor() throws RemoteException;
	@WebMethod()
	public String TestUser() throws RemoteException;
	@WebMethod()
	public String TestEffectiveUser() throws RemoteException;
	@WebMethod()
	public String TestETDIssuer() throws RemoteException;
	@WebMethod()
	public String TestETDLastSubject() throws RemoteException;
	@WebMethod()
	public String TestHTTPCreds() throws RemoteException;
	@WebMethod()
	public String TestPreference() throws RemoteException;
	
	@RequiresSignature
	@WebMethod(action="TestSignatureAction")
	public String TestSignature() throws RemoteException;
	@WebMethod(action="TestSignature2Action")
	public String TestSignature2() throws RemoteException;
	
	public static final String test_action="SomeTestActionValue";
	
	@WebMethod(action=test_action)
	public String TestAction() throws RemoteException;
}
