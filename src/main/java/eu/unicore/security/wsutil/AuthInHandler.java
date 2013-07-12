/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.ICM file for licencing information.
 *
 * Created on May 31, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;

import org.apache.commons.codec.binary.Base64;
import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.common.util.StringUtils;
import org.apache.cxf.headers.Header;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.transport.http.AbstractHTTPDestination;
import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.Element;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AttributeStatementType;
import xmlbeans.org.oasis.saml2.assertion.AttributeType;
import xmlbeans.org.oasis.saml2.assertion.AuthnStatementType;
import xmlbeans.org.oasis.saml2.assertion.SubjectLocalityType;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.FormatMode;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.security.HTTPAuthNTokens;
import eu.unicore.security.SecurityTokens;
import eu.unicore.security.UnicoreSecurityFactory;
import eu.unicore.security.UserAttributeHandler;
import eu.unicore.security.consignor.ConsignorAPI;
import eu.unicore.security.consignor.ConsignorAssertion;
import eu.unicore.security.user.UserAssertion;
import eu.unicore.security.wsutil.client.SessionIDOutHandler;
import eu.unicore.util.Log;

/**
 * Security in-handler for UNICORE. Extracts consignor and user information
 * from the SOAP header.<br>
 * Processes
 * <ul>
 * <li>Consignor SAML assertions
 * <li>User SAML assertions
 * <li>WSA Action (not really authN part but it is handy to do it here) 
 * <li>As a fall back it can use certificates from the transport layer
 * <li>HTTP auth data is also extracted from the request.
 * </ul>
 * Note that all above sources of authN data can be turned off. The first one  
 * should be coming from the gateway.
 * <p>
 * The resulting data is feed into {@link SecurityTokens} class which is injected into 
 * request context. The raw tokens are populated along with user and consignor
 * fields.
 * <p>
 * NOTE: this handler must be invoked before handlers that relies on
 * authentication data, so make sure to invoke <br>
 * <code> after(AuthNInHandler.class.getName());</code><br>
 * in the constructor of any such handler.
 * <p>
 * WARNING: Never use this handler without consignor assertions verification turned on,
 * when access to the service is possible not exclusively through the gataway (i.e. the 
 * service is not protected by firewall)! Doing so effectively turns off the whole authentication,
 * as anyone can attach a fake "gateway" assertion in her/his request.
 * <p>
 * WARNING: This class doesn't verify neither the certificate obtained from the transport layer nor
 * from Consignor's assertion (gateway should verify them). 
 * Therefore the HTTPS server must be properly configured to verify clients if usage of SSL data is turned on.  
 * 
 * @author K. Benedyczak
 */
public class AuthInHandler extends AbstractSoapInterceptor
{
	protected static final Logger logger = Log.getLogger(Log.SECURITY, AuthInHandler.class);
	
	public static final String SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
	/**
	 * Under this key in the context of SecurityTokens all saml assertions that were not consumed by
	 * this handler will be stored. So all assertions except Consignor and User.
	 */
	public static final String RAW_SAML_ASSERTIONS_KEY = AuthInHandler.class.getName() + 
			".RAW_SAML_ASSERTIONS";

	private boolean useGatewayAssertions;
	private boolean useHTTPBasic;
	private boolean useSSLData;
	private X509Certificate gatewayC;
	private boolean verifyConsignor;
	private String actor;

	private boolean sessionsEnabled=true;
	
	// session time to expiry in millis
	private long sessionLifetime = 60*60*1000;
	
	private List<UserAttributeHandler> userAttributeHandlers = new ArrayList<UserAttributeHandler>();
	
	private final Set<QName>qnameSet=new HashSet<QName>();
	
	/**
	 * store security tokens keyed by security session ID
	 * 
	 * TODO setup expiry thread
	 */
	private static final ConcurrentHashMap<String, SecuritySession>sessions=
			new ConcurrentHashMap<String, SecuritySession>();
	
	/**
	 * stores number of sessions per user (identified as effective DN + Client IP)
	 * If this exceeds a threshold, the least-recently-used sessiop is removed
	 */
	private static final ConcurrentHashMap<String, AtomicInteger>sessionsPerUser=
			new ConcurrentHashMap<String, AtomicInteger>();
	
	private int maxSessionsPerUser=100;

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
	 */
	public AuthInHandler(boolean useGatewayAssertions, boolean useSSLData,
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
	 */
	public AuthInHandler(boolean useGatewayAssertions, boolean useSSLData,
			boolean extractHTTPData, X509Certificate gatewayC, String actor)
	{
		super(Phase.PRE_INVOKE);
		qnameSet.add(new QName(WSSecHeader.WSSE_NS_URI,WSSecHeader.WSSE_LN));

		this.useGatewayAssertions = useGatewayAssertions;
		this.useHTTPBasic = extractHTTPData;
		this.useSSLData = useSSLData;
		verifyConsignor = false;
		if (gatewayC != null && useGatewayAssertions)
		{
			this.gatewayC = gatewayC;
			verifyConsignor = true;
		}
		this.actor = actor;
	}

	
	public boolean isSessionsEnabled() {
		return sessionsEnabled;
	}

	public void setSessionsEnabled(boolean sessionsEnabled) {
		this.sessionsEnabled = sessionsEnabled;
	}

	/**
	 * set the session lifetime in millis
	 * 
	 * @param lifetime
	 */
	public void setSessionLifetime(long lifetime) {
		this.sessionLifetime=lifetime;
	}

	public void addUserAttributeHandler(UserAttributeHandler uh){
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
		String sessionID=getSecuritySessionID(ctx);
		SecuritySession session = getOrCreateSession(ctx, sessionID);
		SecurityTokens mainToken = session.getTokens();
		if(sessionID==null)
		{
			process(ctx, mainToken);
		}
		ctx.put(SecurityTokens.KEY, mainToken);
		
		// in case it's a new session, increment the session counter
		if(!Boolean.TRUE.equals(mainToken.getContext().get(SessionIDOutHandler.REUSED_MARKER_KEY))){
			String userKey=getUserKey(mainToken);
			AtomicInteger i = getOrCreateSessionCounter(userKey);
			int l=i.incrementAndGet();
			// if the max count is exceeded, expel the least recently used session
			if(l>maxSessionsPerUser){
				i.decrementAndGet();
				expelLRUSession(userKey);
			}
		}
	}

	/**
	 * get the stored session, or create a new one if required
	 *  
	 * @param message
	 * @param sessionID
	 * @return
	 */
	protected SecuritySession getOrCreateSession(SoapMessage message, String sessionID){
		SecuritySession session = null;
		SecurityTokens tokens=null;
		
		if(sessionID!=null){
			session=sessions.get(sessionID);
			if(session==null || session.isExpired()){
				// got a session ID from the client, but no session: fault
				sessionID=null;
				Fault f = new Fault((Throwable)null); // null is OK
				f.setStatusCode(432); // unassigned according to IANA ;)
				f.setMessage("No (valid) security session found, please (re-)send full security data!");
				throw f;
			}
			tokens=session.getTokens();
			tokens.getContext().put(SessionIDOutHandler.REUSED_MARKER_KEY, Boolean.TRUE);
		}
		else{
			tokens=new SecurityTokens();
			sessionID=UUID.randomUUID().toString();
			tokens.getContext().put(SessionIDOutHandler.SESSION_ID_KEY, sessionID);
			session = new SecuritySession(sessionID, tokens, sessionLifetime);
			sessions.put(sessionID, session);
		}
		if(sessionID!=null){
			// make sure session info goes to the client
			SessionIDServerOutHandler.setSession(session);
		}
		return session;
	}
	
	/**
	 * process AuthN info from the message and put it into the SecurityToken 
	 * @param ctx -incoming message
	 * @param mainToken - security tokens for this request
	 */
	protected void process(SoapMessage ctx, SecurityTokens mainToken){

		if (useHTTPBasic)
		{
			HTTPAuthNTokens fromHttp = getHTTPCredentials(ctx);
			if (fromHttp != null)
			{
				mainToken.getContext().put(
						SecurityTokens.CTX_LOGIN_HTTP, fromHttp);
			}
		}

		ConsignorAssertion cAssertion = null;
		Element uAssertion = null;
		if (ctx.hasHeaders())
		{
			List<Element> assertions = extractSAMLAssertions(ctx);

			if (useGatewayAssertions)
				cAssertion = getConsignorAssertion(assertions);
			uAssertion = getUserAssertion(assertions);
			mainToken.getContext().put(RAW_SAML_ASSERTIONS_KEY, assertions);
		}

		processConsignor(cAssertion, mainToken, ctx);

		if (uAssertion != null)
		{
			try{
				processUser(uAssertion, mainToken);
			}catch(IOException i){
				throw new Fault(i);
			}
		}

		mainToken.getContext().put(SecurityTokens.CTX_SCOPE_KEY, 
				SecurityTokens.SCOPE_REQUEST);			
		mainToken.getContext().put(SecurityTokens.CTX_SOAP_ACTION, 
				getSOAPAction(ctx));
	}
	
	protected List<Element> extractSAMLAssertions(SoapMessage message)
	{
		List<Header> headers=message.getHeaders();
		List<Element> assertions = new ArrayList<Element>();
		
		if (headers.size()==0)
		{
			logger.debug("No SOAP header");
			return assertions;
		} 

		Element wsSecEl = null;
		if (actor != null)
		{
			WSSecHeader utilActor = new WSSecHeader(actor, true);
			wsSecEl = utilActor.findWSSecElement(headers);
		}
		if (wsSecEl == null)
		{
			WSSecHeader utilNoActor = new WSSecHeader(true);
			wsSecEl = utilNoActor.findWSSecElement(headers);
		}

		
		//This list can contain GW consignor assertion and also other ones inserted by 
		//older clients (new clients should insert assertions under wssec:Security element)
		
		List<Element> directAssertions = new ArrayList<Element>();
		for(Header h: headers){
			if(SAML2_NS.equals(h.getName().getNamespaceURI()) && "Assertion".equals(h.getName().getLocalPart())){
				directAssertions.add((Element)h.getObject());
			}
		}
		assertions.addAll(directAssertions);
		
		if (wsSecEl != null)
		{
			assertions.addAll(DOMUtils.getChildrenWithName(wsSecEl, SAML2_NS, "Assertion"));
			if (assertions.size() == 0)
				logger.debug("No assertion found in the wssec:Security element");
		} else
			logger.debug("No valid WS Security element found in SOAP header");
		return assertions;
	}

	protected void processUser(Element uAssertion, SecurityTokens mainToken) throws IOException
	{
		logger.debug("Found user assertion in request");
		UserAssertion userA = processUserAssertion(uAssertion);
		X509Certificate[] user = extractCertPath(userA);
		if (user == null)
		{
			X500Principal userP = extractDN(userA);
			mainToken.setUserName(userP);
			if (logger.isDebugEnabled())
				logger.debug("Requested USER (retrived as a DN): " + 
						X500NameUtils.getReadableForm(userP.getName()));
		} else
		{
			mainToken.setUser(user);
			if (logger.isDebugEnabled())
				logger.debug("Requested USER (retrieved as a full certificate): " +
						CertificateUtils.format(
							user[0], FormatMode.COMPACT_ONE_LINE));
		}

		//extract any additional attributes and process them
		AttributeStatementType[] attributes=userA.getXMLBean().getAttributeStatementArray();
		if( attributes!=null && userAttributeHandlers.size()>0){
			for(AttributeStatementType attrStatement: attributes){
				for(AttributeType attr: attrStatement.getAttributeArray()){
					String nameFormat=attr.getNameFormat();
					if(UserAssertion.ROLE_NAME_FORMAT.equals(nameFormat))continue;
					String name=attr.getName();
					XmlObject[] values=attr.getAttributeValueArray();
					for(UserAttributeHandler h: userAttributeHandlers){
						h.processUserDefinedAttribute(name, nameFormat, values, mainToken);
					}
				}
			}
		}

	}
	
	protected void processConsignor(ConsignorAssertion cAssertion, SecurityTokens mainToken, SoapMessage message)
	{
		if (cAssertion == null && useGatewayAssertions)
			logger.debug("No consignor info in request -> " +
			"request didn't come through a gateway");
		X509Certificate[] consignor = null;
		String clientIP = null;
		
		if (cAssertion != null && useGatewayAssertions)
		{
			consignor = processConsignorAssertion(cAssertion);
			if (consignor != null){
				logger.debug("Using consignor info from Gateway.");
				clientIP = extractIPFromConsignorAssertion(cAssertion);
			}
		}

		if (cAssertion == null && useSSLData)
		{
			consignor = getSSLCertPath(message);
			clientIP = getClientIP(message);
			if (consignor != null)
				logger.debug("Using consignor info from SSL connection.");
		}

		if (logger.isDebugEnabled() && consignor != null)
			logger.debug("Consignor: " + X500NameUtils.getReadableForm(
					consignor[0].getSubjectX500Principal()));
		if (consignor == null)
			logger.debug("No valid Consignor info received, request is not authenticated.");
		else
			mainToken.setConsignor(consignor);
		
		mainToken.setClientIP(clientIP);
	}	

	protected X509Certificate[] getSSLCertPath(SoapMessage message)
	{
		return CXFUtils.getSSLCerts(message);
	}

	protected String getClientIP(SoapMessage message)
	{
		return CXFUtils.getClientIP(message);
	}

	protected String extractIPFromConsignorAssertion(ConsignorAssertion cAssertion)
	{
		AuthnStatementType[] authNs = cAssertion.getXMLBean().getAuthnStatementArray();
		if (authNs == null || authNs.length == 0)
			return null;
		SubjectLocalityType loc = authNs[0].getSubjectLocality();
		if (loc == null)
			return null;
		return loc.getAddress();
	}

	protected HTTPAuthNTokens getHTTPCredentials(SoapMessage message)
	{
		HttpServletRequest req =(HttpServletRequest)message.get(AbstractHTTPDestination.HTTP_REQUEST);
		if (req == null)
			return null; 
		String aa = req.getHeader("Authorization");
		if (aa == null)
			return null;
		if (aa.length() < 7)
		{
			logger.warn("Ignoring too short Authorization header element in " +
					"HTTP request: " + aa);
			return null;
		}
		String encoded = aa.substring(6);
		String decoded = new String(Base64.decodeBase64(encoded.getBytes()
				));
		String []split = decoded.split(":");
		if (split.length > 2)
		{
			logger.warn("Ignoring malformed Authorization HTTP header element" +
					" (to many ':' after decode: " + decoded + ")");
			return null;
		}
		if (split.length == 2)
			return new HTTPAuthNTokens(split[0], split[1]);
		else if (split.length == 1)
			return new HTTPAuthNTokens(split[0], null);
		else
		{
			logger.warn("Ignoring malformed Authorization HTTP header element" +
			" (empty string after decode)");
			return null;
		}
	}


	protected Element getUserAssertion(List<Element> assertions)
	{
		for (int i=assertions.size()-1; i>=0; i--)
		{
			Element a = (Element) assertions.get(i);
			List<Element> ass=DOMUtils.getChildrenWithName(a, SAML2_NS, "AttributeStatement");
			if(ass.size()==0)continue;
			Element as = ass.get(0);
			if (as == null) continue;
			
			List<Element> attrs = DOMUtils.getChildrenWithName(as, SAML2_NS, "Attribute");
			for (Element attr: attrs)
			{
				String a1 = attr.getAttribute("Name");
				String a2 = attr.getAttribute("NameFormat");
				if (StringUtils.isEmpty(a1)|| StringUtils.isEmpty(a2))
					continue;

				if (a1.equals("USER") && a2.equals("urn:unicore:subject-role"))
				{
					assertions.remove(i);
					return a;
				}
			}

		}
		return null;
	}

	/**
	 * Returns parsed but not verified in any way consignor assertion. The
	 * first assertion is tried and returned if looks like consignor i.e. has a proper
	 * attribute tag.
	 * @param assertions
	 * @return
	 */
	protected ConsignorAssertion getConsignorAssertion(List<Element> assertions)
	{
		if (assertions.size() == 0) 
			return null;
		
		try
		{
			ByteArrayOutputStream os=new ByteArrayOutputStream();
			CXFUtils.writeXml(assertions.get(0), os);
			AssertionDocument aDoc = AssertionDocument.Factory.parse(os.toString());
			ConsignorAssertion ca = new ConsignorAssertion(aDoc);
			assertions.remove(0);
			return ca;
		} catch (Exception e)
		{
			logger.debug("The first assertion is not a valid CONSIGNOR " +
					"assertion, ignoring: "	+ e.getMessage());
			return null;
		}
	}

	protected X509Certificate[] processConsignorAssertion(ConsignorAssertion consignorA)
	{
		X509Certificate[] cert = consignorA.getConsignor();
		if (verifyConsignor)
		{
			if (!consignorA.isSigned())
			{
				logger.warn("Consignor assertion is "
						+ "unsigned. Probably gateway is not "
						+ "configured properly to sign consignor"
						+ " assertions. Either fix gateway "
						+ "configuration or turn off signature "
						+ "checking in this server's configuration");
				return null;
			}
			ConsignorAPI engine = UnicoreSecurityFactory.getConsignorAPI();
			eu.unicore.security.ValidationResult res = engine.verifyConsignorToken(
					consignorA, gatewayC);
			if (!res.isValid())
			{
				String subject = (cert == null || cert.length == 0) ? "null" : 
					X500NameUtils.getReadableForm(cert[0].getSubjectX500Principal());
				logger.warn("Consignor assertion is "
						+ "invalid (probably FAKED): "
						+ res.getInvalidResaon()
						+ ", inserted consignor was: "
						+ subject);
				return null;
			}
			logger.debug("Successfully verified consignor assertion.");
		}

		if (cert == null)
			logger.debug("Anonymous CONSIGNOR");
		return cert;
	}

	protected UserAssertion processUserAssertion(Element assertion)
	{
		UserAssertion userA;
		try
		{
			ByteArrayOutputStream os=new ByteArrayOutputStream();
			DOMUtils.writeXml(assertion, os);
			AssertionDocument aDoc = AssertionDocument.Factory.parse(os.toString());
			userA = new UserAssertion(aDoc);
			return userA;
		} catch (Exception e)
		{
			logger.warn("The USER assertion is invalid, ignoring: "
					+ e.getMessage());
			return null;
		}
	}	

	protected X509Certificate[] extractCertPath(UserAssertion userA)
	{
		X509Certificate[] cert = userA.getSubjectFromConfirmation();
		if (cert == null)
			logger.debug("USER retrieved, but no certificate is given.");
		return cert;
	}

	protected X500Principal extractDN(UserAssertion userA) throws IOException
	{
		String userDN = userA.getSubjectName();
		return X500NameUtils.getX500Principal(userDN);
	}
	
	
	protected String getSOAPAction(SoapMessage message){
		String action=CXFUtils.getAction(message);
				
		if (logger.isDebugEnabled() && action != null){
			logger.debug("Setting SOAP action to '" + action + "'");
		}
		return action;
	}
	
	protected String getSecuritySessionID(SoapMessage message)
	{
		String sessionID=null;
		Header header=message.getHeader(SessionIDOutHandler.headerQName);
		if(header!=null){
			Element hdr = (Element) header.getObject();		
			if(hdr!=null)
				sessionID = hdr.getTextContent(); 
		}
		return sessionID;
	}
	

	protected String getUserKey(SecurityTokens tokens){
		return tokens.getConsignorName()+"@"+tokens.getClientIP();
	}
	
	protected synchronized AtomicInteger getOrCreateSessionCounter(String userKey){
		AtomicInteger i=sessionsPerUser.get(userKey);
		if(i==null){
			i=new AtomicInteger();
			sessionsPerUser.put(userKey, i);
		}
		return i;
	}
	
	protected void expelLRUSession(String key){
		SecuritySession lru=null;
		for(SecuritySession session: sessions.values()){
			if(!key.equals(session.getUserKey()))continue;
			if(lru==null || lru.getLastAccessed()>session.getLastAccessed()){
				lru=session;
			}
		}
		if(lru!=null){
			sessions.remove(lru.getSessionID());
		}
	}
}
