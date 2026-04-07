package eu.unicore.security.wsutil;

import java.rmi.RemoteException;
import java.util.Calendar;

import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlString;

import eu.unicore.security.HTTPAuthNTokens;
import eu.unicore.security.SecurityTokens;
import eu.unicore.security.UserAttributeHandler;
import eu.unicore.security.wsutil.client.OAuthBearerTokenOutInterceptor;
import eu.unicore.security.wsutil.client.WSClientFactory;
import jakarta.annotation.Resource;
import jakarta.jws.WebService;
import jakarta.xml.ws.WebServiceContext;
import jakarta.xml.ws.handler.MessageContext;


@WebService(endpointInterface="eu.unicore.security.wsutil.SimpleSecurityService")
public class SimpleSecurityServiceImpl implements SimpleSecurityService
{

	public static SecurityTokens lastCallTokens;
	
	@Resource
	private WebServiceContext context;

	private SecurityTokens getTokens()
	{
		MessageContext ctx = context.getMessageContext();
		SecurityTokens tokens = (SecurityTokens)ctx.get(SecurityTokens.KEY);
		lastCallTokens=tokens;
		return tokens;
	}

	@Override
	public String TestHTTPCreds() throws RemoteException
	{
		SecurityTokens tokens = getTokens();
		HTTPAuthNTokens a = (HTTPAuthNTokens) tokens.getContext().get(
				SecurityTokens.CTX_LOGIN_HTTP);
		return a.getUserName() + "-" + a.getPasswd();
	}

	@Override
	public String TestBearerToken() throws RemoteException
	{
		System.out.println("XX");
		SecurityTokens tokens = getTokens();
		String bearer = (String) tokens.getContext().get(
				OAuthBearerTokenOutInterceptor.TOKEN_KEY);
		return "Got OAuth Bearer token: " + bearer;
	}

	@Override
	public String TestAction() throws RemoteException
	{
		//return the action as retrieved from by the AuthIn handler
		return (String)getTokens().getContext().get(SecurityTokens.CTX_SOAP_ACTION);
	}

	@Override
	public String TestSessionID(){
		return (String)getTokens().getContext().get(WSClientFactory.UNICORE_SECURITY_SESSION_TARGET_URL);
	}
	
	public static String currentRepresentation="test123";
	public static Calendar lastMod=Calendar.getInstance();

	public static class SimpleUserAttributeHandler implements UserAttributeHandler 
	{
		@Override
		public void processUserDefinedAttribute(String name, String nameFormat, 
				XmlObject[]values, SecurityTokens tokens)
		{
			tokens.getContext().put("PREF_" + name, ((XmlString)values[0]).getStringValue());
		}
	}
}
