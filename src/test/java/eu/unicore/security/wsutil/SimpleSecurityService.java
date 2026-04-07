package eu.unicore.security.wsutil;

import java.rmi.RemoteException;

import jakarta.jws.WebMethod;
import jakarta.jws.WebService;

@WebService(targetNamespace="http://cxfutil.security.unicore.eu")
public interface SimpleSecurityService
{
	@WebMethod()
	public String TestHTTPCreds() throws RemoteException;
	@WebMethod()
	public String TestBearerToken() throws RemoteException;
	
	public static final String test_action="SomeTestActionValue";
	
	@WebMethod(action=test_action)
	public String TestAction() throws RemoteException;

	@WebMethod()
	public String TestSessionID() throws RemoteException;
}
