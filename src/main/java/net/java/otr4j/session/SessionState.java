package net.java.otr4j.session;

import com.google.gson.annotations.SerializedName;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;

public class SessionState {
    @SerializedName("sessionStatus")
    SessionStatus sessionStatus;

    @SerializedName("sessionKeys")
    SessionKeys[][] sessionKeys;

    @SerializedName("oldMacKeys")
    List<byte[]> oldMacKeys;

    @SerializedName("remotePublicKey")
    PublicKey remotePublicKey;

    @SerializedName("senderTag")
    InstanceTag senderTag;

    @SerializedName("receiverTag")
    InstanceTag receiverTag;

    @SerializedName("ess")
    BigInteger ess;
}
