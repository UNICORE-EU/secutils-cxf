package eu.unicore.security.wsutil.client;

import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;

import org.apache.cxf.clustering.FailoverFeature;
import org.apache.cxf.clustering.FailoverTargetSelector;
import org.apache.cxf.clustering.RetryStrategy;
import org.apache.cxf.message.Exchange;
import org.apache.cxf.message.Message;
import org.apache.cxf.transport.Conduit;
import org.apache.cxf.transport.http.HTTPConduit;

/**
 * Handle retries of failed WS calls
 * 
 * @author schuller
 */
public class RetryFeature extends FailoverFeature{

	private final WSClientFactory factory;
	
	private boolean enabled=true;
	
	private final Set<Class<? extends Throwable>>exceptionClasses = new HashSet<Class<? extends Throwable>>();
	
	private final Set<ExceptionChecker>exceptionCheckers = new HashSet<ExceptionChecker>();
	
	public RetryFeature(WSClientFactory factory) {
		super();
		this.factory=factory;
		setStrategy(new RetryStrategy());
		setTargetSelector(new MyTargetSelector(this));
	}

	public Set<Class<? extends Throwable>> getRecoverableExceptions() {
		return exceptionClasses;
	}

	public Set<ExceptionChecker> getExceptionCheckers() {
		return exceptionCheckers;
	}

	public void setMaxRetries(int maxRetries){
		getStrategy().setMaxNumberOfRetries(maxRetries);
	}

	public int getMaxRetries(){
		return getStrategy().getMaxNumberOfRetries();
	}


	public void setDelayBetweenRetries(long delay){
		getStrategy().setDelayBetweenRetries(delay);
	}

	public long getDelayBetweenRetries(){
		return getStrategy().getDelayBetweenRetries();
	}
	
	public RetryStrategy getStrategy()  {
		return (RetryStrategy)super.getStrategy();
	}

	public boolean isEnabled() {
		return enabled;
	}

	/**
	 * enable/disable the retry handler
	 */
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	/**
	 * return <code>true</code> iff the failed call should be re-tried<br/>
	 * By default, the request will be re-tried in case of one of the 
	 * following errors: 
	   <ul>
	   		<li>ResourceUnavailableFault</li>
	   		<li>IOException</li>
	   </ul> 
	 * @param ex
	 * @return
	 */
	public boolean requiresFailover(Throwable ex){
		if(!enabled)return false;
		
		boolean retry=false;
		for(Class<? extends Throwable>c: exceptionClasses){
			retry = retry | c.isAssignableFrom(ex.getClass());
		}
		for(ExceptionChecker c: exceptionCheckers){
			retry = retry | c.requiresFailover(ex);
		}
		
		return retry;
	}

	public static class MyTargetSelector extends FailoverTargetSelector{
		RetryFeature feature;

		public MyTargetSelector(RetryFeature feature){
			this.feature=feature;
		}
		
		@Override
		public Conduit selectConduit(Message message) {
			Conduit c=super.selectConduit(message);
			// as the retry code deletes the existing HTTPConduit,
			// our settings (TLS etc) are lost, so we need to re-init
			if(c!=null && c instanceof HTTPConduit){
				feature.factory.setupHTTPParams((HTTPConduit)c);
			}
			return c;
		}
		
		// mostly opy&paste the original code to add a hook for our own exception
		// exception checks -> TODO add a CXF change request?
		@Override
		protected boolean requiresFailover(Exchange exchange) {
			Exception ex = getException(exchange);
			getLogger().log(Level.FINE,
					"CHECK_LAST_INVOKE_FAILED",
					new Object[] {ex != null});
			Throwable curr = ex;
			boolean failover = false;
			while (curr != null) {
				failover = feature.requiresFailover(curr);
				curr = curr.getCause();
			}
			if (ex != null) {
				getLogger().log(Level.INFO,
						"CHECK_FAILURE_IN_TRANSPORT",
						new Object[] {ex, failover});
			}
			return failover;
		}

		protected Exception getException(Exchange exchange) {
			if (exchange.getInFaultMessage() != null) {
				return exchange.getInFaultMessage().getContent(Exception.class);
			} else if (exchange.getOutFaultMessage() != null) {
				return exchange.getOutFaultMessage().getContent(Exception.class);
			} else if (exchange.getInMessage() != null) {
				return exchange.getInMessage().getContent(Exception.class);
			}
			return null;
		}
	}
	
	
	public static interface ExceptionChecker {
		
		public boolean requiresFailover(Throwable ex);
		
	}
	
}
