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


package eu.unicore.security.wsutil;

import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.phase.Phase;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Element;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.emi.security.authn.x509.proxy.ProxyUtils;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.security.SecurityTokens;
import eu.unicore.security.SelfCallChecker;
import eu.unicore.security.TrustDelegationException;
import eu.unicore.security.UnicoreSecurityFactory;
import eu.unicore.security.ValidationResult;
import eu.unicore.security.etd.ETDApi;
import eu.unicore.security.etd.TrustDelegation;
import eu.unicore.util.Log;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;

/**
 * 
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
 *   then TD chain is checked if its custodian is the same as this user. If not then 
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
	private X509CertChainValidator validator;
	private X509CertChainValidator trustedDelegationIssuers;

	/**
	 * Creates a new handler for checking trust delegation.
	 * @param selfCallChecker checker used to accept self calls. May be null.
	 */
	public ETDInHandler(SelfCallChecker selfCallChecker, X509CertChainValidator validator,
			X509CertChainValidator trustedDelegationIssuers)
	{
		super(Phase.PRE_INVOKE);
		getAfter().add(AuthInHandler.class.getName());
		this.selfCallChecker = selfCallChecker;
		this.validator = validator;
		this.trustedDelegationIssuers = trustedDelegationIssuers;
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
		
		if(Boolean.TRUE.equals(securityTokens.getContext().get(SecuritySessionUtils.REUSED_MARKER_KEY))){
			return;
		}
		
		try{
			doCheck(securityTokens);
		}catch(Exception ex){
			throw new Fault(ex);
		}
	}
	
	protected void doCheck(SecurityTokens securityTokens )throws Exception
	{
		//store the trust delegation chain for later use
		List<TrustDelegation> tdTokens = getTrustAssertionsFromHeader(
				securityTokens.getContext());
		securityTokens.setTrustDelegationTokens(tdTokens);
		//initially invalid
		securityTokens.setTrustDelegationValidated(false);
		securityTokens.setConsignorTrusted(false);

		String consignor = securityTokens.getConsignorName();
		if (consignor == null)
		{
			logger.debug("No CONSIGNOR information present (it means that request wasn't authenticated!). Trust Delegations won't be further processed.");
			return;
		}
		
		String etdIssuerName = getIssuerName(tdTokens);
		
		if (etdIssuerName == null)
		{
			logger.debug("No ETD tokens are present.");
			if (securityTokens.getUserName() == null || 
					X500NameUtils.equal(securityTokens.getUserName(), consignor))
			{
				logger.debug("Performing the request with the Consignor's identity.");
				securityTokens.setConsignorTrusted(true);
			} else if (securityTokens.isConsignorUsingProxy() && 
					X500NameUtils.equal(securityTokens.getUserName(),
							securityTokens.getConsignorRealName()))
			{
				logger.debug("Performing the request with the Consignor's identity " +
						"(handling proxy which is used by consignor).");
				securityTokens.setConsignorTrusted(true);
				securityTokens.setUserName(consignor);
			} else
			{
				logger.warn("Got request with User set to {} without a TD! Consignor is {}",
						X500NameUtils.getReadableForm(securityTokens.getUserName()),
						X500NameUtils.getReadableForm(consignor));
			}
			return;
		}

		boolean etdIssuerIsDn = isIssuerDN(tdTokens);
		
		String etdCustodianName = getCustodianName(tdTokens);
		String requestedUser = securityTokens.getUserName();
		if (requestedUser != null)
		{
			if (!X500NameUtils.equal(requestedUser, etdCustodianName))
			{
				logger.warn("Trust delegation is present but its custodian " +
						"differ from the requested user. Trust delegation tokens won't " +
						"be verified and delegation status is set to invalid. TD Custodian: {}" + 
						 " Requested user: {}",
						 X500NameUtils.getReadableForm(etdCustodianName), 
						 X500NameUtils.getReadableForm(requestedUser));
				return;
			}
		} else
		{
			logger.debug("No user was requested so TD won't be checked. " +
					"Performing the request with Consignor's identity.");
			securityTokens.setConsignorTrusted(true);
			return;
		}

		if (logger.isDebugEnabled())
		{
			String readableIssuer = etdIssuerIsDn ? X500NameUtils.getReadableForm(etdIssuerName) : 
				etdIssuerName;
			logger.debug("ETD initial issuer: " + readableIssuer + 
					"\nConsignor: " + 
					X500NameUtils.getReadableForm(consignor) + "\nETD custodian: " +
					X500NameUtils.getReadableForm(etdCustodianName));
			
			if (X500NameUtils.equal(consignor, etdCustodianName))
			{
				logger.debug("ETD custodian and consignor are equal");
			} else if (etdIssuerIsDn && securityTokens.isConsignorUsingProxy() && 
					X500NameUtils.equal(securityTokens.getConsignorRealName(), etdIssuerName))
			{
				logger.debug("ETD issuer and consignor are equal after handling a proxy");
			} else
			{
				logger.debug("ETD issuer and consignor are different");
			}
		}
		//ok now check if TD is valid and store a flag for later policy check
		checkDelegation(securityTokens, tdTokens);
	}

	protected void checkDelegation(SecurityTokens securityTokens, List<TrustDelegation> tdTokens)
			throws TrustDelegationException
	{
		String userName=securityTokens.getUserName();
		logger.debug("Checking trust delegation, expected custodian is <{}>",
					()->X500NameUtils.getReadableForm(userName));
		String consignor = securityTokens.getConsignorName();

		//now really check the SAML stuff
		boolean validTD = checkSuppliedTD(userName, tdTokens);
		boolean consignorTrusted = checkIfConsignorTrusted(validTD, securityTokens.isConsignorUsingProxy(), 
				tdTokens, securityTokens.getConsignorRealName(), consignor, userName);
		securityTokens.setTrustDelegationValidated(validTD);
		securityTokens.setConsignorTrusted(consignorTrusted);
		if (validTD && consignorTrusted)
		{
			//Let's correct the user in case of proxies: it is different from what was requested
			X509Certificate[] etdInitialIssuerCC = getIssuer(tdTokens);
			if (securityTokens.isSupportingProxy() && ProxyUtils.isProxy(etdInitialIssuerCC))
			{
				securityTokens.setUser(new X509Certificate[] {
						ProxyUtils.getEndUserCertificate(etdInitialIssuerCC)});
			}
		}
		logger.debug("Final SecurityTokens after ETD processing:\n{}", 
					()->securityTokens.toString());
	}

	/**
	 * Returns true only in three cases: if consignor==user or 
	 * if consignor has trust delegated by user or if this is internal server call.
	 * from the user.
	 */
	protected boolean checkIfConsignorTrusted(boolean tdGenericValidity, boolean consignorIsProxy, 
			List<TrustDelegation> tdTokens, String realConsignor, 
			String consignor, String user)
	{
		if (X500NameUtils.equal(realConsignor, user))
			return true;
		if (selfCallChecker != null && selfCallChecker.isSelfCall(consignor))
		{
			logger.debug("Accept message by server as valid trust delegation.");
			return true;
		}
		if (!tdGenericValidity || tdTokens.size() == 0)
			return false;
		
		ETDApi etd = UnicoreSecurityFactory.getETDEngine();
		
		//here we have three cases: delegation was done to the proxy cert as the receiver
		// or to the EEC as the receiver
		if (etd.isSubjectInChain(tdTokens, realConsignor))
			return true;
		// or delegation was done to the EEC but consignor is using proxy derived from this EEC.
		if (consignorIsProxy && etd.isSubjectInChain(tdTokens, consignor))
			return true;
		return false;
	}
	
	/**
	 * check validity of a chain of SAML trust delegation assertions without paying
	 * attention of the target.
	 * 
	 * @param user - the original user, requested
	 * @param td
	 */
	protected boolean checkSuppliedTD(String user, List<TrustDelegation> td)
	{
		if (td.size() == 0)
			return false;
		String delegationTarget = td.get(td.size()-1).getSubjectName();
		if(logger.isDebugEnabled())
		{
			logger.debug("Got TD to <{}>, dumping the TD chain", delegationTarget);
			int i = 0;
			for(TrustDelegation t: td)
			{
				logger.debug("(Entry {}) issuer: {} receiver: {} custodian: {}",
						i, t.getIssuerName(), t.getSubjectName(), t.getCustodianDN());
			}
		}
		ETDApi etd = UnicoreSecurityFactory.getETDEngine();
		Collection<X509Certificate>trustedIssuers = new HashSet<X509Certificate>();
		if (trustedDelegationIssuers != null)
			Collections.addAll(trustedIssuers, trustedDelegationIssuers.getTrustedIssuers());
		ValidationResult res = etd.isTrustDelegated(td, delegationTarget, user, validator, trustedIssuers);
		logger.debug("Validation of supplied TD result: {}", res.isValid());
		if (res.isValid())
		{
			return true;
		}
		else
		{
			logger.warn("Unsuccessful TD validation ({} to {}), reason: {}",
						user, delegationTarget, res.getInvalidResaon());
			return false;
		}

	}

	/**
	 * extract trust delegation assertions from the header
	 * @param secCtx
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
	 */
	protected String getIssuerName(List<TrustDelegation> tdTokens)
	{
		if (tdTokens == null || tdTokens.size() == 0)
			return null;
		try
		{
			return tdTokens.get(0).getIssuerName();
		} catch (Exception e)
		{
			logger.warn("Can't parse ETD assertion issuer name: " + e.toString());
			return null;
		}
	}
	
	protected boolean isIssuerDN(List<TrustDelegation> tdTokens)
	{
		if (tdTokens == null || tdTokens.size() == 0)
			return false;
		try
		{
			return SAMLConstants.NFORMAT_DN.equals(tdTokens.get(0).getIssuerNameFormat());
		} catch (Exception e)
		{
			logger.warn("Can't parse ETD assertion issuer name format: " + e.toString());
			return false;
		}
	}
	
	protected String getCustodianName(List<TrustDelegation> tdTokens)
	{
		if (tdTokens == null || tdTokens.size() == 0)
			return null;
		try
		{
			return tdTokens.get(0).getCustodianDN();
		} catch (Exception e)
		{
			logger.warn("Can't parse ETD assertion custodian name: " + e.toString());
			return null;
		}
	}
	
	/**
	 * get the X509 certificate of the issuer
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

