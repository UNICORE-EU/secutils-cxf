package eu.unicore.security.xfireutil;

import org.apache.cxf.message.Message;

/**
 * Implementation of this interface decides whether for the given request/response
 * message should be processed by DSig stack. Depending on context it may be used
 * to check if the incoming message DOM should be build (only if the DOM is build the 
 * digital signature of the message is verified) or if the outgoing message should be 
 * signed.
 * <p>
 * This interface is used in {@link DSigParseInHandler} and in {@link DSigOutHandler}. 
 * @author K. Benedyczak
 */
public interface DSigDecider
{
	/**
	 * Returns true iff for the message there should be DSig processing enabled. 
	 * @param ctx context of current message
	 * @return
	 */
	public boolean isMessageDSigCandidate(Message ctx);

}
