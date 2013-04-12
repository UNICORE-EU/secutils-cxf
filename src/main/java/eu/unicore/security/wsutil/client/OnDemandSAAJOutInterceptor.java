package eu.unicore.security.wsutil.client;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.saaj.SAAJOutInterceptor;

import eu.unicore.security.wsutil.DSigDecider;

/**
 * this subclass of the CXF {@link SAAJOutInterceptor} only builds
 * the SAAJ representation if a signature is required
 *
 * @author schuller
 */
public class OnDemandSAAJOutInterceptor extends SAAJOutInterceptor {

	private final DSigDecider decider;
	
	public OnDemandSAAJOutInterceptor(DSigDecider decider){
		super();
		this.decider=decider;
	}
	
	public void handleMessage(SoapMessage message){
		if(decider==null || decider.isMessageDSigCandidate(message)){
			super.handleMessage(message);
		}
	}
	
	
}
