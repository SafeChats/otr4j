package net.java.otr4j.protocol;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.logging.*;

import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.session.SessionID;

public class DummyOtrEngineHost implements OtrEngineHost {

	public DummyOtrEngineHost(OtrPolicy policy) {
		this.policy = policy;
	}

	private static Logger logger = Logger.getLogger(DummyOtrEngineHost.class
			.getName());
	private OtrPolicy policy;
	public String lastInjectedMessage;

	public OtrPolicy getSessionPolicy(SessionID ctx) {
		return this.policy;
	}

	public void injectMessage(SessionID sessionID, String msg) {

		this.lastInjectedMessage = msg;
		String msgDisplay = (msg.length() > 10) ? msg.substring(0, 10) + "..."
				: msg;
		logger.info("IM injects message: " + msgDisplay);
	}

	public void showError(SessionID sessionID, String error) {
		logger.severe("IM shows error to user: " + error);
	}

	public void showWarning(SessionID sessionID, String warning) {
		logger.warning("IM shows warning to user: " + warning);
	}

	public KeyPair getSessionKeyPair(SessionID sessionID) {
		logger.info("IM generates a DSA key pair.");
		try {
			KeyPairGenerator kg = KeyPairGenerator.getInstance("DSA");
			return kg.genKeyPair();

		} catch (NoSuchAlgorithmException e) {
			return null;
		}
	}

	public Boolean getSessionIsAuthenticated(SessionID sessionID) {
		return false;
	}

	public void sessionStatusChanged(SessionID sessionID) {
		// don't care
	}

}