package eu.unicore.security.wsutil;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.namespace.QName;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.logging.log4j.Logger;

import eu.unicore.security.HTTPAuthNTokens;
import eu.unicore.security.SecurityTokens;
import eu.unicore.security.UserAttributeHandler;
import eu.unicore.security.wsutil.client.OAuthBearerTokenOutInterceptor;
import eu.unicore.util.Log;

/**
 * 
 * @author K. Benedyczak
 */
class AuthInHandler extends AbstractSoapInterceptor
{
	private static final Logger logger = Log.getLogger(Log.SECURITY, AuthInHandler.class);
	private final boolean useHTTPBasic;
	private final List<UserAttributeHandler> userAttributeHandlers = new ArrayList<>();
	private final Set<QName>qnameSet=new HashSet<>();

	/**
	 * Constructs instance of the handler. It will accept assertions in the header element
	 * without the actor set. Note that by default out handlers do not set the actor so
	 * this version should be used in most cases.
	 * @param useGatewayAssertions if true then consignor assertions from gateway 
	 * will be honored.
	 * @param useSSLData if true and no valid assertion from gateway is found then
	 * SSL/TLS certificates will be tried.
	 * @param extractHTTPData if true then HTTP Basic Auth data will be extracted and
	 * injected into context.
	 * @param gatewayC if not null then consignor assertions will be verified. This
	 * make sense only when useGatewayAssertions is true otherwise is ignored.
	 * @param sessionStore security session storage
	 */
	AuthInHandler(boolean useGatewayAssertions, boolean useSSLData,
			boolean extractHTTPData, X509Certificate gatewayC)
	{
		this(useGatewayAssertions, useSSLData, extractHTTPData, gatewayC, null);
	}

	/**
	 * Constructs instance of the handler.
	 * @param useGatewayAssertions if true then consignor/user assertions from gateway 
	 * will be honored.
	 * @param useSSLData if true and no valid assertion from gateway is found then
	 * SSL/TLS certificates will be tried.
	 * @param extractHTTPData if true then HTTP Basic Auth data will be extracted and
	 * injected into context.
	 * @param gatewayC if not null then consignor assertions will be verified. This
	 * make sense only when useGatewayAssertions is true otherwise is ignored.
	 * @param actor Name of this service as used in WSSecurity actor field.
	 * @param sessionStore security session storage
	 */
	private AuthInHandler(boolean useGatewayAssertions, boolean useSSLData,
			boolean extractHTTPData, X509Certificate gatewayC, String actor)
	{
		super(Phase.PRE_INVOKE);
		this.useHTTPBasic = extractHTTPData;
	}
	
	void addUserAttributeHandler(UserAttributeHandler uh){
		userAttributeHandlers.add(uh);
	}
	
	@Override
	public Set<QName> getUnderstoodHeaders()
	{
		return qnameSet;
	}

	@Override
	public void handleMessage(SoapMessage ctx)
	{
		SecurityTokens mainToken = new SecurityTokens();
		process(ctx, mainToken);
		ctx.put(SecurityTokens.KEY, mainToken);
	}

	/**
	 * process AuthN info from the message and put it into the SecurityToken 
	 * @param ctx -incoming message
	 * @param mainToken - security tokens for this request
	 */
	private void process(SoapMessage ctx, SecurityTokens mainToken){

		if (useHTTPBasic)
		{
			HTTPAuthNTokens fromHttp = getHTTPCredentials(ctx);
			if (fromHttp != null)
			{
				mainToken.getContext().put(
						SecurityTokens.CTX_LOGIN_HTTP, fromHttp);
			}
			// OAuth token
			String bearer = CXFUtils.getBearerToken(ctx);
			if(bearer != null){
				logger.debug("Have OAuth bearer token.");
				mainToken.getContext().put(OAuthBearerTokenOutInterceptor.TOKEN_KEY, bearer);
			}
		}

		mainToken.getContext().put(SecurityTokens.CTX_SCOPE_KEY, 
				SecurityTokens.SCOPE_REQUEST);			
		mainToken.getContext().put(SecurityTokens.CTX_SOAP_ACTION, 
				getSOAPAction(ctx));
	}

	private HTTPAuthNTokens getHTTPCredentials(SoapMessage message)
	{
		return CXFUtils.getHTTPCredentials(message);
	}

	private String getSOAPAction(SoapMessage message){
		String action=CXFUtils.getAction(message);
				
		if (action != null){
			logger.debug("Setting SOAP action to '{}'", action);
		}
		return action;
	}

}
