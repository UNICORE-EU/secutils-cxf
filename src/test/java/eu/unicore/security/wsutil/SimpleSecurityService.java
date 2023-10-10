/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 16, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil;

import java.rmi.RemoteException;

import jakarta.jws.WebMethod;
import jakarta.jws.WebService;

@WebService(targetNamespace="http://cxfutil.security.unicore.eu")
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
	public String TestHTTPCreds() throws RemoteException;
	@WebMethod()
	public String TestBearerToken() throws RemoteException;
	@WebMethod()
	public String TestPreference() throws RemoteException;
	@WebMethod(action="TestSignature2Action")
	public String TestSignature2() throws RemoteException;
	
	public static final String test_action="SomeTestActionValue";
	
	@WebMethod(action=test_action)
	public String TestAction() throws RemoteException;

	@WebMethod()
	public String TestSessionID() throws RemoteException;
}
