package net.java.otr4j.session;

import com.google.gson.*;
import net.java.otr4j.crypto.OtrCryptoEngine;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.lang.reflect.Type;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.*;

class SessionStateSerializer {
    static String serialize(SessionState state) {
        return gson().toJson(state);
    }

    static SessionState deserialize(String str) {
        try {
            return gson().fromJson(str, SessionState.class);
        } catch (JsonSyntaxException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static Gson gson() {
        return new GsonBuilder()
                .registerTypeAdapter(InstanceTag.class, new InstanceTagJsonSerializer())
                .registerTypeHierarchyAdapter(SessionKeys.class, new SessionKeysJsonSerializer())
                .registerTypeAdapter(byte[].class, new ByteArrayJsonSerializer())
                .registerTypeHierarchyAdapter(Key.class, new KeyJsonSerializer())
                .registerTypeAdapter(SessionStatus.class, new SessionStatusSerializer())
                .create();
    }

    private static class InstanceTagJsonSerializer
            implements JsonSerializer<InstanceTag>, JsonDeserializer<InstanceTag> {

        @Override
        public JsonElement serialize(InstanceTag tag, Type type, JsonSerializationContext context) {
            return new JsonPrimitive(tag.getValue());
        }

        @Override
        public InstanceTag deserialize(JsonElement json, Type type, JsonDeserializationContext context)
                throws JsonParseException {
            return new InstanceTag(json.getAsInt());
        }
    }

    private static class KeyJsonSerializer
            implements JsonSerializer<Key>, JsonDeserializer<Key> {

        private static final String DSA_PUBLIC_KEY = "dsaPublicKey";
        private static final String DSA_PRIVATE_KEY = "dsaPrivateKey";
        private static final String DH_PUBLIC_KEY = "dhPublicKey";
        private static final String DH_PRIVATE_KEY = "dhPrivateKey";

        private static final String PROP_KEY_TYPE = "type";
        private static final String PROP_KEY_DATA = "data";

        interface KeyGenerator {
            Key generate(KeyFactory keyFactory, KeySpec keySpec) throws InvalidKeySpecException;
        }

        class PublicKeyGenerator implements KeyGenerator {
            @Override
            public Key generate(KeyFactory keyFactory, KeySpec keySpec) throws InvalidKeySpecException {
                return keyFactory.generatePublic(keySpec);
            }
        }

        class PrivateKeyGenerator implements KeyGenerator {
            @Override
            public Key generate(KeyFactory keyFactory, KeySpec keySpec) throws InvalidKeySpecException {
                return keyFactory.generatePrivate(keySpec);
            }
        }

        interface KeySerializer {
            JsonElement serialize(Key key, JsonSerializationContext context);
            Key deserialize(JsonElement jsonElement, JsonDeserializationContext context);
        }

        abstract class DSAKeySerializer implements KeySerializer {
            private final KeyGenerator keyGenerator;

            public DSAKeySerializer(KeyGenerator keyGenerator) {
                this.keyGenerator = keyGenerator;
            }

            @Override
            public JsonElement serialize(Key key, JsonSerializationContext context) {
                EncodedKeySpec keySpec = createKeySpec(key.getEncoded());
                return context.serialize(keySpec.getEncoded());
            }

            @Override
            public Key deserialize(JsonElement json, JsonDeserializationContext context) {
                byte[] encodedKey = context.deserialize(json, byte[].class);
                if (encodedKey == null) {
                    return null;
                }

                EncodedKeySpec keySpec = createKeySpec(encodedKey);

                try {
                    KeyFactory keyFactory = KeyFactory.getInstance("DSA");
                    return keyGenerator.generate(keyFactory, keySpec);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (InvalidKeySpecException e) {
                    e.printStackTrace();
                }
                return null;
            }

            abstract protected EncodedKeySpec createKeySpec(byte[] encodedKey);
        }

        class DSAPublicKeySerializer extends DSAKeySerializer {
            public DSAPublicKeySerializer() {
                super(new PublicKeyGenerator());
            }

            @Override
            protected EncodedKeySpec createKeySpec(byte[] encodedKey) {
                return new X509EncodedKeySpec(encodedKey);
            }
        }

        class DSAPrivateKeySerializer extends DSAKeySerializer {
            public DSAPrivateKeySerializer() {
                super(new PrivateKeyGenerator());
            }

            @Override
            protected EncodedKeySpec createKeySpec(byte[] encodedKey) {
                return new PKCS8EncodedKeySpec(encodedKey);
            }
        }

        abstract class DHKeySerializer implements KeySerializer {
            private final KeyGenerator keyGenerator;

            public DHKeySerializer(KeyGenerator keyGenerator) {
                this.keyGenerator = keyGenerator;
            }

            @Override
            public JsonElement serialize(Key key, JsonSerializationContext context) {
                BigInteger keyVal = getKeyVal(key);
                return new JsonPrimitive(keyVal);
            }

            @Override
            public Key deserialize(JsonElement json, JsonDeserializationContext context) {
                BigInteger keyVal = json.getAsBigInteger();
                if (keyVal == null) {
                    return null;
                }

                KeySpec keySpec = createKeySpec(keyVal, OtrCryptoEngine.MODULUS, OtrCryptoEngine.GENERATOR);

                try {
                    KeyFactory keyFactory = KeyFactory.getInstance("DH");
                    return keyGenerator.generate(keyFactory, keySpec);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (InvalidKeySpecException e) {
                    e.printStackTrace();
                }
                return null;
            }

            abstract protected BigInteger getKeyVal(Key key);
            abstract protected KeySpec createKeySpec(BigInteger keyVal, BigInteger mod, BigInteger gen);
        }

        class DHPublicKeySerializer extends DHKeySerializer {
            public DHPublicKeySerializer() {
                super(new PublicKeyGenerator());
            }

            @Override
            protected BigInteger getKeyVal(Key key) {
                return ((DHPublicKey)key).getY();
            }

            @Override
            protected KeySpec createKeySpec(BigInteger keyVal, BigInteger mod, BigInteger gen) {
                return new DHPublicKeySpec(keyVal, mod, gen);
            }
        }

        class DHPrivateKeySerializer extends DHKeySerializer {
            public DHPrivateKeySerializer() {
                super(new PrivateKeyGenerator());
            }

            @Override
            protected BigInteger getKeyVal(Key key) {
                return ((DHPrivateKey)key).getX();
            }

            @Override
            protected KeySpec createKeySpec(BigInteger keyVal, BigInteger mod, BigInteger gen) {
                return new DHPrivateKeySpec(keyVal, mod, gen);
            }
        }

        @Override
        public JsonElement serialize(Key key, Type type, JsonSerializationContext context) {
            String keyType = getKeyType(key);
            KeySerializer keySerializer = createKeySerializer(keyType);

            JsonObject json = new JsonObject();
            json.addProperty(PROP_KEY_TYPE, keyType);
            json.add(PROP_KEY_DATA, keySerializer.serialize(key, context));

            return json;
        }

        @Override
        public Key deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext context)
                throws JsonParseException {
            JsonObject json = jsonElement.getAsJsonObject();

            String keyType = json.getAsJsonPrimitive(PROP_KEY_TYPE).getAsString();

            KeySerializer keySerializer = createKeySerializer(keyType);
            return keySerializer.deserialize(json.get(PROP_KEY_DATA), context);
        }

        private String getKeyType(Key key) {
            if (key instanceof DHPublicKey) {
                return DH_PUBLIC_KEY;
            } else if (key instanceof DHPrivateKey) {
                return DH_PRIVATE_KEY;
            } else if (key instanceof DSAPublicKey) {
                return DSA_PUBLIC_KEY;
            } else if (key instanceof DSAPrivateKey) {
                return DSA_PRIVATE_KEY;
            }
            throw new IllegalArgumentException("unknown key type");
        }

        private KeySerializer createKeySerializer(String keyType) {
            if (DH_PUBLIC_KEY.equals(keyType)) {
                return new DHPublicKeySerializer();
            } else if (DH_PRIVATE_KEY.equals(keyType)) {
                return new DHPrivateKeySerializer();
            } else if (DSA_PUBLIC_KEY.equals(keyType)) {
                return new DSAPublicKeySerializer();
            } else if (DSA_PRIVATE_KEY.equals(keyType)) {
                return new DSAPrivateKeySerializer();
            }
            throw new IllegalArgumentException("unknown key type");
        }
    }

    private static class SessionKeysJsonSerializer
            implements JsonSerializer<SessionKeys>, JsonDeserializer<SessionKeys> {

        private static final String PROP_LOCAL_KEY = "localKey";
        private static final String PROP_LOCAL_KEY_ID = "localKeyId";
        private static final String PROP_REMOTE_KEY = "remoteKey";
        private static final String PROP_REMOTE_KEY_ID = "remoteKeyId";
        private static final String PROP_IS_USED_MAC_KEY = "isUsedMacKey";
        private static final String PROP_SENDING_CTR = "sendingCtr";
        private static final String PROP_RECEIVING_CTR = "receivingCtr";

        @Override
        public JsonElement serialize(SessionKeys sessionKeys, Type type, JsonSerializationContext context) {
            JsonObject json = new JsonObject();

            json.add(PROP_SENDING_CTR, context.serialize(sessionKeys.getSendingCtr()));
            json.add(PROP_RECEIVING_CTR, context.serialize(sessionKeys.getReceivingCtr()));

            json.add(PROP_LOCAL_KEY, context.serialize(sessionKeys.getLocalPair()));
            json.addProperty(PROP_LOCAL_KEY_ID, sessionKeys.getLocalKeyID());

            json.add(PROP_REMOTE_KEY, context.serialize(sessionKeys.getRemoteKey()));
            json.addProperty(PROP_REMOTE_KEY_ID, sessionKeys.getRemoteKeyID());

            json.addProperty(PROP_IS_USED_MAC_KEY, sessionKeys.getIsUsedReceivingMACKey());

            return json;
        }

        @Override
        public SessionKeys deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext context)
                throws JsonParseException {
            JsonObject json = jsonElement.getAsJsonObject();
            SessionKeys keys = new SessionKeysImpl(0, 0);

            KeyPair localKey = context.deserialize(json.get(PROP_LOCAL_KEY), KeyPair.class);
            int localKeyId = json.getAsJsonPrimitive(PROP_LOCAL_KEY_ID).getAsInt();
            keys.setLocalPair(localKey, localKeyId);

            DHPublicKey remoteKey = context.deserialize(json.get(PROP_REMOTE_KEY), DHPublicKey.class);
            int remoteKeyId = json.getAsJsonPrimitive(PROP_REMOTE_KEY_ID).getAsInt();
            keys.setRemoteDHPublicKey(remoteKey, remoteKeyId);

            boolean isUsedMacKey = json.getAsJsonPrimitive(PROP_IS_USED_MAC_KEY).getAsBoolean();
            keys.setIsUsedReceivingMACKey(isUsedMacKey);

            JsonElement receivingCtrElement = json.get(PROP_RECEIVING_CTR);
            if (receivingCtrElement != null) {
                byte[] receivingCtr = context.deserialize(receivingCtrElement, byte[].class);
                keys.setReceivingCtr(receivingCtr);
            }

            JsonElement sendingCtrElement = json.get(PROP_SENDING_CTR);
            if (sendingCtrElement != null) {
                byte[] sendingCtr = context.deserialize(sendingCtrElement, byte[].class);
                keys.setSendingCtr(sendingCtr);
            }

            return keys;
        }
    }

    private static class ByteArrayJsonSerializer
            implements JsonSerializer<byte[]>, JsonDeserializer<byte[]> {

        @Override
        public JsonElement serialize(byte[] bytes, Type type, JsonSerializationContext context) {
            String base64 = new String(Base64.encode(bytes));
            return new JsonPrimitive(base64);
        }

        @Override
        public byte[] deserialize(JsonElement json, Type type, JsonDeserializationContext context)
                throws JsonParseException {
            String base64 = json.getAsString();
            return Base64.decode(base64);
        }
    }

    private static class SessionStatusSerializer
            implements JsonSerializer<SessionStatus>, JsonDeserializer<SessionStatus> {
        private static final String STATUS_PLAINTEXT = "plaintext";
        private static final String STATUS_ENCRYPTED = "encrypted";
        private static final String STATUS_FINISHED = "finished";

        @Override
        public JsonElement serialize(SessionStatus status, Type type, JsonSerializationContext context) {
            String strStatus;
            switch (status) {
            case PLAINTEXT:
                strStatus = STATUS_PLAINTEXT;
                break;

            case ENCRYPTED:
                strStatus = STATUS_ENCRYPTED;
                break;

            case FINISHED:
                strStatus = STATUS_FINISHED;
                break;

            default:
                strStatus = null;
            }
            return new JsonPrimitive(strStatus);
        }

        @Override
        public SessionStatus deserialize(JsonElement json, Type type, JsonDeserializationContext context) throws JsonParseException {
            String strStatus = json.getAsString();
            if (STATUS_PLAINTEXT.equals(strStatus)) {
                return SessionStatus.PLAINTEXT;
            } else if (STATUS_ENCRYPTED.equals(strStatus)) {
                return SessionStatus.ENCRYPTED;
            } else if (STATUS_FINISHED.equals(strStatus)) {
                return SessionStatus.FINISHED;
            }
            return SessionStatus.PLAINTEXT;
        }
    }
}
