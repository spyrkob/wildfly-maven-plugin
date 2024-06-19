package org.wildfly.plugin.provision;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.encoders.Hex;
import org.jboss.logging.Logger;
import org.wildfly.channel.gpg.GpgKeystore;

public class GpgKeyring implements GpgKeystore {

    private final Logger log = Logger.getLogger(GpgKeyring.class.getName());

    private final PGPPublicKeyRingCollection publicKeyRingCollection;
    private Map<String, PGPPublicKey> keyCache = new HashMap<>();

    public PGPPublicKey get(String keyID) {
        if (publicKeyRingCollection != null) {
            final Iterator<PGPPublicKeyRing> keyRings = publicKeyRingCollection.getKeyRings();
            while (keyRings.hasNext()) {
                final PGPPublicKeyRing keyRing = keyRings.next();
                final PGPPublicKey publicKey = keyRing.getPublicKey(new BigInteger(keyID, 16).longValue());
                if (publicKey != null) {
                    System.out.println("!!!! Found the key in keyring");
                    return publicKey;
                }
            }
            return null;
        } else {
            System.out.println("!!!! Getting the key from cache");
            return keyCache.get(keyID);
        }
    }

    public GpgKeyring(Path keyringPath) {
        if (keyringPath != null) {
            try {
                publicKeyRingCollection = new PGPPublicKeyRingCollection(
                        new ArmoredInputStream(new FileInputStream(keyringPath.toFile())),
                        new JcaKeyFingerprintCalculator());
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (PGPException e) {
                throw new RuntimeException(e);
            }
        } else {
            publicKeyRingCollection = null;
        }
    }

    public boolean add(List<PGPPublicKey> publicKeys) {
        for (PGPPublicKey publicKey : publicKeys) {
            keyCache.put(Long.toHexString(publicKey.getKeyID()).toUpperCase(Locale.ROOT), publicKey);
        }
        return true;
    }

    static String describeImportedKeys(PGPPublicKey pgpPublicKey) {
        final StringBuilder sb = new StringBuilder();
        final Iterator<String> userIDs = pgpPublicKey.getUserIDs();
        while (userIDs.hasNext()) {
            sb.append(userIDs.next());
        }
        sb.append(": ").append(Hex.toHexString(pgpPublicKey.getFingerprint()));
        return sb.toString();
    }
}
