/**
 * 
 */
package cz.foxon.auth;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;

import com.thingworx.logging.LogUtilities;
import com.thingworx.metadata.annotations.ThingworxConfigurationTableDefinition;
import com.thingworx.metadata.annotations.ThingworxConfigurationTableDefinitions;
import com.thingworx.metadata.annotations.ThingworxDataShapeDefinition;
import com.thingworx.metadata.annotations.ThingworxFieldDefinition;
import com.thingworx.security.authentication.AuthenticationUtilities;
import com.thingworx.security.authentication.AuthenticatorException;
import com.thingworx.security.authentication.CustomAuthenticator;

/**
 * Simple authentication for ThingWorx platform that authenticates user send in
 * custom header.
 * 
 * ThingWorx - Custom Authenticators Overview:
 * https://support.ptc.com/appserver/cs/view/solution.jsp?n=CS244163&lang=en_US
 * Where To Find ThingWorx Documentation (Developer Guide):
 * https://support.ptc.com/appserver/cs/view/solution.jsp?n=CS232833&art_lang=en&posno=1&q=developer&ProductFamily=ThingWorx%7CNRN%7CAxeda&source=search
 * Testing extensions and SDKs outside of ThingWorx within an IDE:
 * https://support.ptc.com/appserver/cs/view/solution.jsp?n=CS215376&art_lang=en&posno=8&q=debug&ProductFamily=ThingWorx%7CNRN%7CAxeda&source=search
 * Using the Eclipse IDE to debug an Extension running in ThingWorx:
 * https://support.ptc.com/appserver/cs/view/solution.jsp?n=CS219756&art_lang=en&posno=1&q=debug&ProductFamily=ThingWorx%7CNRN%7CAxeda&source=search
 *
 * @since 2016-10-13
 * @author Jan Gabriel <jan.gabriel@foxon.cz>
 */

@ThingworxConfigurationTableDefinitions(tables = {
		@ThingworxConfigurationTableDefinition(name = "Settings", description = "Settings for header.", isMultiRow = false, ordinal = 0, dataShape = @ThingworxDataShapeDefinition(fields = {
				@ThingworxFieldDefinition(name = "Header", description = "Please provide header for user look up.", baseType = "STRING", ordinal = 0, aspects = {
						"isRequired:true", "defaultValue:iv-user", "friendlyName:Header" }) })) })

public class HeaderAuth extends CustomAuthenticator {

	private static final long serialVersionUID = 2020112423369327803L;
	private static String  user;
	protected static Logger _logger = LogUtilities.getInstance().getApplicationLogger(HeaderAuth.class);
	
	
	public HeaderAuth() {
		/*
		 * Constructor
		 * 
		 * Called by JVM Upon importing extension into ThingWorx, a copy of this
		 * method is sent to the authentication manager so it knows there is
		 * another authenticator to challenge. When the authentication manager
		 * determines by priority that this is the right authenticator, it
		 * instantiates a new instance. Any static data for each new
		 * authenticator instance should be thread safe (final) to avoid causing
		 * deadlocks. Best to avoid putting very much logic here, even calls to
		 * get configuration or instance data (use authenticate method instead).
		 */
	}

	@Override
	public void authenticate(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
			throws AuthenticatorException {
		/*
		 * Authenticate
		 * 
		 * This method needs to throw an Exception or else the authentication
		 * manager will never know there was an error and will always
		 * authenticate the user’s credentials. Sets setCredentials() or throws
		 * AuthenticatorException.
		 */
		try {
			AuthenticationUtilities.validateEnabledThingworxUser(HeaderAuth.user);
			this.setCredentials(HeaderAuth.user);
		} catch (Exception e) {
			this.setRequiresChallenge(false);
			throw new AuthenticatorException(
					"Provided username is not valid, " + HeaderAuth.class.getSimpleName() + " failed to login!");
		}
	}

	@Override
	public void issueAuthenticationChallenge(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
			throws AuthenticatorException {
		/*
		 * IssueAuthenticationChallenge
		 * 
		 * This may not be used at all, or it may be used for alerting or
		 * logging. Handles logic which follows authentication fail (e.g.
		 * logging an error: _logger.error). In order to invoke this method,
		 * ensure setRequiresChallenge(true) is in authenticate method before
		 * throwing the exception. ThingworxBasicAuthenticator grabs the
		 * responses and sets some header in this method, then calling the
		 * pop-up box which requests users attempt login again.
		 * ThingworxFormAuthenticator redirects users to plain form login
		 * prompts with return statuses displayed.
		 */
		throw new AuthenticatorException(
				"Either header or provided user is invalid, " + HeaderAuth.class.getSimpleName() + " failed to login!");
	}

	@Override
	public boolean matchesAuthRequest(HttpServletRequest httpRequest) throws AuthenticatorException {
		/*
		 * MatchesAuthRequest
		 * 
		 * This method determines if this authenticator is valid for the
		 * authentication request type and return true if so.
		 */
		
		String header = (String) getConfigurationSetting("Settings", "Header");
		String user = httpRequest.getHeader(header);

		if (user == null) {
			this.setRequiresChallenge(false);
			throw new AuthenticatorException("Invalid or missing " + header + " header, " + HeaderAuth.class.getSimpleName() + " failed to login!");
		}
		
		HeaderAuth.user = user;
		return true;
	}

}
