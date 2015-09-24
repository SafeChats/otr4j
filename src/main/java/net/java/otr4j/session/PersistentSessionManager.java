package net.java.otr4j.session;

import net.java.otr4j.OtrEngineHost;

public class PersistentSessionManager {
    public interface Storage {
        void saveSessionState(SessionID sessionID, String state);
    }

    private PersistentSessionManager() {}

    /**
     * Loads session from given state.
     */
    public static Session loadSession(SessionID sessionID, OtrEngineHost host, String state) {
        if (state != null) {
            SessionState stateObject = null;
            try {
                stateObject = SessionStateSerializer.deserialize(state);
            } catch (Exception e) {
                e.printStackTrace();
            }

            if (stateObject != null &&
                    stateObject.sessionStatus == SessionStatus.ENCRYPTED &&
                    stateObject.ess != null) {
                SessionImpl session = new SessionImpl(sessionID, host);
                session.applyState(stateObject);

                return session;
            }
        }
        return null;
    }

    /**
     * Automatically saves session state to given storage when state changes.
     */
    public static void watchSessionState(Session session, final Storage storage) {
        final SessionImpl sessionImpl = (SessionImpl)session;
        sessionImpl.setSessionListener(new SessionListener() {
            @Override
            public void onStateChanged(Session session) {
                SessionState state = sessionImpl.getState();

                try {
                    String stateStr = SessionStateSerializer.serialize(state);
                    storage.saveSessionState(session.getSessionID(), stateStr);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    public static void unwatchSessionState(Session session) {
        ((SessionImpl)session).setSessionListener(null);
    }
}
