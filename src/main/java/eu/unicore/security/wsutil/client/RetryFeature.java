package eu.unicore.security.wsutil.client;

import java.net.SocketTimeoutException;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import java.util.logging.Level;

import org.apache.cxf.clustering.FailoverFeature;
import org.apache.cxf.clustering.FailoverTargetSelector;
import org.apache.cxf.clustering.RetryStrategy;
import org.apache.cxf.message.Exchange;
import org.apache.cxf.message.Message;
import org.apache.cxf.transport.Conduit;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transport.http.HTTPException;
import org.apache.log4j.Logger;

import eu.unicore.util.Log;


/**
 * Handle retries of failed WS calls
 * 
 * @author schuller
 */
public class RetryFeature extends FailoverFeature {

	private static final Logger log = Log.getLogger(Log.CLIENT, RetryFeature.class); 
	
	private final WSClientFactory factory;
	
	private boolean enabled=true;
	
	private boolean retryImmediately = false; 
	
	private final Set<Class<? extends Throwable>>exceptionClasses = new HashSet<Class<? extends Throwable>>();
	
	private final Set<ExceptionChecker>exceptionCheckers = new HashSet<ExceptionChecker>();
	
	public RetryFeature(WSClientFactory factory) {
		super();
		this.factory=factory;
		setStrategy(new IncreasingBackoffStrategy());
		setTargetSelector(new MyTargetSelector());
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
		long res=0;
		if(retryImmediately){
			retryImmediately=false;
		}
		else{
			res=getStrategy().getDelayBetweenRetries();
		}
		if(log.isDebugEnabled()){
			log.debug("Will retry "+(res>0?"in "+res/1000+" sec.":"immediately."));
		}
		return res;
	}
	
	public void setRetryImmediately(){
		retryImmediately=true;
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
	 */
	public boolean requiresFailover(Throwable ex){
		if(!enabled)return false;
		boolean retry = false;
		
		// do NOT retry socket read timouts! This could lead 
		// to duplicate actions (e.g. job submits) 
		if(ex instanceof SocketTimeoutException){
			return false;
		}
			
		for(Class<? extends Throwable>c: exceptionClasses){
			if(c.isAssignableFrom(ex.getClass())){
				retry = true;
			}
		}
		
		for(ExceptionChecker c: exceptionCheckers){
			if(c.requiresFailover(ex)){
				retry = true;
			}
		}
		
		if(log.isDebugEnabled()){
			log.debug("Got "+(retry?"":"non-")+"recoverable exception "+ex.getClass().getName());
		}
		
		return retry;
	}

	public class MyTargetSelector extends FailoverTargetSelector{
		
		@Override
		protected long getDelayBetweenRetries() {
			return RetryFeature.this.getDelayBetweenRetries();
		}

		@Override
		public Conduit selectConduit(Message message) {
			Conduit c=super.selectConduit(message);
			// as the retry code deletes the existing HTTPConduit,
			// our settings (TLS etc) are lost, so we need to re-init
			if(c!=null && c instanceof HTTPConduit){
				RetryFeature.this.factory.setupHTTPParams((HTTPConduit)c);
			}
			return c;
		}
		
		// mostly copy&paste the original code to add a hook for our own exception
		// exception checks -> TODO add a CXF change request?
		@Override
		protected boolean requiresFailover(Exchange exchange, Exception ex) {
			getLogger().log(Level.FINE,
					"CHECK_LAST_INVOKE_FAILED",
					new Object[] {ex != null});
			Throwable curr = ex;
			if(curr==null)curr = getException(exchange);
			boolean failover = false;
			while (curr != null) {
				boolean isInvalidSession = false;
				if(curr.getMessage() != null && curr.getMessage().contains("432")){
					isInvalidSession = true;
				}
				if(curr instanceof HTTPException){
					int s=((HTTPException)curr).getResponseCode();
					if(s == 432){
						isInvalidSession = true;
					}
				}
				
				if(isInvalidSession){
					clearSessionID(exchange);
					RetryFeature.this.setRetryImmediately();
					if(log.isDebugEnabled()){
						log.debug("Received alert: No valid security session, retrying ... ");
					}
					return true;
				}
				
				failover = RetryFeature.this.requiresFailover(curr);
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
			} else if (exchange.getOutMessage() != null) {
				return exchange.getOutMessage().getContent(Exception.class);
			}
			return null;
		}

		protected void clearSessionID(Exchange exchange){
			SessionIDOutHandler.setSkip(true);
		}
	}
	

	
	public static interface ExceptionChecker {
		
		public boolean requiresFailover(Throwable ex);
		
	}

	// mostly copy&paste the original RetryStrategy to compute the delay
	// based on the current number of attempts TODO add a CXF change request?
	public static class IncreasingBackoffStrategy extends RetryStrategy {
	    private int counter=0;
	    private int factor=1;
	    private static Random rand = new Random(); 
	    
	    protected boolean stillTheSameAddress() {
	        if (getMaxNumberOfRetries() == 0) {
	            return true;
	        }
	        if(counter==0)factor=1;
	        increaseFactor();
	        // let the target selector move to the next address
	        // and then stay on the same address for maxNumberOfRetries
	        if (++counter <= getMaxNumberOfRetries()) {
	            return true;    
	        } else {
	            counter = 0;
	            return false;
	        }
	    }
	    
	    // trivial but maybe useful for subclassing later
	    protected void increaseFactor(){
	    	 factor=2*factor;
	    }
	   
	    /**
	     * add some randomness to the delay, and increase it
	     * based on the current number of attempts 
	     */
		@Override
		public long getDelayBetweenRetries() {
			long base = super.getDelayBetweenRetries();
			if(base<=0)return 0;
			
			int r = rand.nextInt((int)base/10);
			return factor*(base+r);
		}
	    
	    
	}
	
}
