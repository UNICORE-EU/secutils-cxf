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


package eu.unicore.security.xfireutil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.phase.Phase;
import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.security.SecurityTokens;
import eu.unicore.security.SelfCallChecker;
import eu.unicore.security.TrustDelegationException;
import eu.unicore.security.UnicoreSecurityFactory;
import eu.unicore.security.ValidationResult;
import eu.unicore.security.etd.ETDApi;
import eu.unicore.security.etd.TrustDelegation;
import eu.unicore.util.Log;

/**
 * Checks trust delegation<br/>
 *
 * Expects security context in the message context, so this depends
 * on a security in handler such as {@link AuthInHandler} being present.
 * <p> 
 * Rules:
 * <ul>
 *   <li>This handler checks for SAML trust delegation tokens in message header, and places 
 * the TD chain in the security context.</li>
 *   <li>If USER identity is present (as obtained by the {@link AuthInHandler},
 *   then TD chain is checked if its issuer is the same as this user. If not then 
 *   trust delegation status in security message context is set to invalid. Otherwise
 *   TD is processed.
 *   <li>If USER identity is not present then TD is not processed 
 *   (useful when client want to invoke request on its own and to send TD for further use).</li>
 *   <li>TD processing: the TD chain is checked for validity (regardelss of whether user 
 *   and consignor differ - it's because delegation may be required for further actions)  
 * </ul>
 * The data is stored in security context ({@link SecurityTokens}).
 * The call to this object getEffectiveUser method will return the correct user.
 * It will be consignor identity if TD was not present or was invalid or was not checked as 
 * User and Consignor are the same.
 * It will be other then consignor identity iff TD is present and was validated. 
 * 
 * @see AuthInHandler
 * @see SecurityTokens
 * 
 * @author schuller
 * @author golbi
 */
public class ETDInHandler extends AbstractSoapInterceptor
{
	public static final String SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

	private static final Logger logger = Log.getLogger(Log.SECURITY, ETDInHandler.class);

	private final SelfCallChecker selfCallChecker;
	private final boolean useTDIssuerAsUser;
	private X509CertChainValidator validator;

	/**
	 * Creates a new handler for checking trust delegation.
	 * @param selfCallChecker checker used to accept self calls. May be null.
	 */
	public ETDInHandler(SelfCallChecker selfCallChecker, X509CertChainValidator validator)
	{
		this(selfCallChecker, false, validator);
	}

	/**
	 * Creates a new handler for checking trust delegation.
	 * @param selfCallChecker checker used to accept self calls. May be null.
	 */
	public ETDInHandler(SelfCallChecker selfCallChecker, boolean useTDIssuerAsUser, 
			X509CertChainValidator validator)
	{
		super(Phase.PRE_INVOKE);
		getAfter().add(AuthInHandler.class.getName());
		this.selfCallChecker = selfCallChecker;
		this.useTDIssuerAsUser = useTDIssuerAsUser;
		this.validator = validator;
	}

	public void handleMessage(SoapMessage ctx)
	{
		SecurityTokens securityTokens = (SecurityTokens) ctx.get(SecurityTokens.KEY);
		if (securityTokens == null)
		{
			logger.error("No security info in headers. Wrong configuration: " +
					AuthInHandler.class.getCanonicalName() + " handler" +
			" must be configure before this ETD handler.");
			return;
		}

		//store the trust delegation chain for later use
		List<TrustDelegation> tdTokens = getTrustAssertionsFromHeader(
				securityTokens.getContext());
		securityTokens.setTrustDelegationTokens(tdTokens);
		//initially invalid
		securityTokens.setTrustDelegationValidated(false);
		securityTokens.setConsignorTrusted(false);

		X509Certificate consignor = securityTokens.getConsignorCertificate();
		if (consignor == null)
		{
			logger.debug("No CONSIGNOR information present (it means that request wasn't " +
				"authenticated!). Trust Delegations won't be further processed.");
			return;
		}
		
		String etdIssuerName = getIssuerName(tdTokens);
		if (etdIssuerName == null)
		{
			logger.debug("No ETD tokens are present.");
			if (securityTokens.getUserName() == null || 
					X500NameUtils.equal(securityTokens.getUserName(), 
						consignor.getSubjectX500Principal().getName()))
			{
				logger.debug("Performing the request with the " +
					"Consignor's identity.");
				securityTokens.setConsignorTrusted(true);
			} else
			{
				logger.warn("Got request with User set to " + securityTokens.getUserName() + 
						" without a TD! Consignor is " + 
						X500NameUtils.getReadableForm(consignor.getSubjectX500Principal()));
			}
			return;
		}

		X500Principal requestedUser = securityTokens.getUserName();
		if (requestedUser != null)
		{
			if (!X500NameUtils.equal(requestedUser, etdIssuerName))
			{
				logger.warn("Trust delegation is present but its initial issuer " +
						"differ from the requested user. Trust delegation tokens won't " +
						"be verified and delegation status is set to invalid. TD Issuer: " + 
						X500NameUtils.getReadableForm(etdIssuerName) + " Requested user: " + 
						X500NameUtils.getReadableForm(requestedUser));
				return;
			}	
		} else
		{
			if (useTDIssuerAsUser)
			{
				if(logger.isDebugEnabled()){
					logger.debug("TD was found but there is no User assertion. " +
							"Using (for UNICORE clients backwards compatibility) " +
							"TD chain issuer as a User on whose behalf " +
							"the request will be performed.");
				}
				X509Certificate[] certs = getIssuer(tdTokens);
				if (certs != null)
				{
					securityTokens.setUser(certs);
				} else
				{
					try{
						securityTokens.setUserName(X500NameUtils.getX500Principal(etdIssuerName));
					}catch(IOException e){
						throw new Fault(e);
					}
				}
			} else
			{
				logger.debug("No user was requested so TD won't be checked. " +
						"Performing the request with Consignor's identity.");
				securityTokens.setConsignorTrusted(true);
				return;
			}
		}

		if (logger.isDebugEnabled())
		{
			logger.debug("ETD issuer: " + etdIssuerName + "\nConsignor: " + 
					X500NameUtils.getReadableForm(consignor.getSubjectX500Principal()));
			
			if (X500NameUtils.equal(consignor.getSubjectX500Principal(), etdIssuerName))
			{
				logger.debug("User and consignor equal.");
			} else
			{
				logger.debug("User and consignor differ.");
			}
		}
		//ok now check if TD is valid and store a flag for later policy check
		checkDelegation(securityTokens, tdTokens);
	}

	protected void checkDelegation(SecurityTokens securityTokens, List<TrustDelegation> tdTokens)
			throws TrustDelegationException
	{
		String userName=securityTokens.getUserName().getName();
		if(logger.isDebugEnabled()){
			logger.debug("Checking trust delegation issued by <"+userName+">");
		}
		X509Certificate consignor = securityTokens.getConsignorCertificate();

		//now really check the SAML stuff
		boolean validTD = checkSuppliedTD(userName, tdTokens);
		boolean consignorTrusted = checkIfConsignorTrusted(validTD, tdTokens, 
				consignor, userName);
		securityTokens.setTrustDelegationValidated(validTD);
		securityTokens.setConsignorTrusted(consignorTrusted);
		if (validTD && consignorTrusted)
		{
			//delegation is valid (i.e. it is from the user previously set in SecurityTokens)
			//but securityTokens do not have information about a full user's certificate.
			//so let's set it. It is especially important in case we have a user using proxy.
			X509Certificate[] tdIssuer = tdTokens.get(0).getIssuerFromSignature();
			if (securityTokens.getUser() == null || securityTokens.getUser().length < tdIssuer.length)
				securityTokens.setUser(tdIssuer);
		}
	}

	/**
	 * Returns true only in three cases: if consignor==user or 
	 * if consignor has trust delegated by user or if this is internal server call.
	 * from the user.
	 * @param tdGenericValidity
	 * @param tdTokens
	 * @param consignor
	 * @param user
	 * @return
	 */
	protected boolean checkIfConsignorTrusted(boolean tdGenericValidity, 
			List<TrustDelegation> tdTokens, X509Certificate consignor, String user)
	{
		String consignorDN = consignor.getSubjectX500Principal().getName();
		if (X500NameUtils.equal(consignor.getSubjectX500Principal(), user))
			return true;
		if (!tdGenericValidity || tdTokens.size() == 0)
			return false;
		if (selfCallChecker != null && selfCallChecker.isSelfCall(consignor))
		{
			logger.debug("Accept message by server as valid trust delegation.");
			return true;
		}
		ETDApi etd = UnicoreSecurityFactory.getETDEngine();
		return etd.isSubjectInChain(tdTokens, consignorDN);
	}
	
	/**
	 * check validity of a chain of SAML trust delegation assertions without paying
	 * attention of the target.
	 * 
	 * @param user - the original user, requested
	 * @param td
	 * @return
	 */
	protected boolean checkSuppliedTD(String user, List<TrustDelegation> td)
	{
		if (td.size() == 0)
			return false;
		String delegationTarget = td.get(td.size()-1).getSubjectDN();
		if(logger.isDebugEnabled())
		{
			logger.debug("Got TD of <"+user+"> to <"+delegationTarget+">, " +
				"dumping the TD chain");
			int i = 0;
			for(TrustDelegation t: td)
			{
				logger.debug("(Entry " + i++ + ") issuer: " + t.getIssuerDN()
						+ " receiver: " + t.getSubjectDN() +
						" custodian: " + t.getCustodianDN());
			}
		}
		ETDApi etd = UnicoreSecurityFactory.getETDEngine();
		ValidationResult res = etd.isTrustDelegated(td, delegationTarget, user, validator);
		if(logger.isDebugEnabled()){
			logger.debug("Validation of supplied TD result: " + res.isValid());
		}
		if (res.isValid())
		{
			return true;
		}
		else
		{
			logger.warn("Unsuccessful TD validation (" + 
						user + " to " + delegationTarget +"), reason: " + 
						res.getInvalidResaon());
			return false;
		}

	}


	/**
	 * extract trust delegation assertions from the header
	 * @param header
	 * @return
	 */
	protected List<TrustDelegation> getTrustAssertionsFromHeader(Map<String, Object> secCtx)
	{
		ArrayList<TrustDelegation> ret = new ArrayList<TrustDelegation>();
		@SuppressWarnings("unchecked")
		List<Element> assertions = ((secCtx == null) ? 
				null : (List<Element>)secCtx.get(AuthInHandler.RAW_SAML_ASSERTIONS_KEY));
		if (assertions == null || assertions.size() == 0)
			return ret;

		for (int i=0; i<assertions.size(); i++)
		{
			ByteArrayOutputStream os=new ByteArrayOutputStream();
			try
			{
				CXFUtils.writeXml(assertions.get(i), os);
				//bruteforce - try to parse - if ok, than use it.
				TrustDelegation tmp;
			
				AssertionDocument aDoc = AssertionDocument.Factory.parse(os.toString());
				tmp = new TrustDelegation(aDoc);
				ret.add(tmp);
			} catch (Exception e)
			{
				logger.trace("Ignoring non-parsable as trust delegation assertion: " + 
						e.getMessage());
			}
		}
		if(logger.isDebugEnabled())logger.debug("TD chain length " + ret.size());
		return ret;
	}

	/**
	 * get the X500 name of the issuer
	 * 
	 * @param tdTokens
	 * @return
	 */
	protected String getIssuerName(List<TrustDelegation> tdTokens)
	{
		if (tdTokens == null || tdTokens.size() == 0)
			return null;
		try
		{
			return tdTokens.get(0).getIssuerDN();
		} catch (Exception e)
		{
			logger.warn("Can't parse ETD assertion issuer name: " + e.toString());
			return null;
		}
	}

	/**
	 * get the X509 certificate of the issuer
	 * 
	 * @param tdTokens
	 * @return
	 */
	protected X509Certificate[] getIssuer(List<TrustDelegation> tdTokens)
	{
		if (tdTokens == null || tdTokens.size() == 0)
			return null;
		try
		{
			return tdTokens.get(0).getIssuerFromSignature();
		} catch (Exception e)
		{
			return null;
		}
	}
}

