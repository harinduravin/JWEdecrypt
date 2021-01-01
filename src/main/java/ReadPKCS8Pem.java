import java.io.*;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import android.util.Base64;

public class ReadPKCS8Pem {

    private final static String PRIVATE_KEY =
            "-----BEGIN PRIVATE KEY-----\n" +
                    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3lU0vdr8EPFVB\n" +
                    "Zximw1xK5/O48iC+NPcrvQ/oigtnGsnxKqQIX+a9k3t8cxp73kAFVWecPE7w/nTp\n" +
                    "PQsdalET0ShE7dnyf9oqruiC3bJCabr+RdjjkSAKEt9ONUAiFoHW5Pnp16vktZiQ\n" +
                    "pBYmU8XO/tnt8Z05G0YZFWGmP90g1Q8WtK0vYkgQeu/rAYFKKiRo4RS98OMkijKK\n" +
                    "0MnICvB1rvuYCvi2WjGpCWu7yvkwzWjJKK6H5aWHb75TNrNYjDsny+PeP0PZj39j\n" +
                    "N5yrlUXjsis8BiKGRLrW2e857ZSK2Zr/cxil79RNND2F7ah5HRsFPbnLBydNo1GV\n" +
                    "e2gfWg/dAgMBAAECggEAKBDWkphI4gTE2oxEjgiu+M4cm+2EBd8LXqlZcnfGO09W\n" +
                    "aWLT/9vmQNOSLLv2OLhtonxcK3XiCKiQHWMsLNRKM5f/QOPkIA+VLqGTrxPxVps6\n" +
                    "q0nVJv1CT9CEmc33XDkrRxocDNP7+ONFE7Qr/VtlHWLzbwG/PXpdVxYahK0FdqeK\n" +
                    "i85/5uKN1fDttK6vrQ7aWSTd2zRBTmC6s8QPXpJEZ1eCqC8xxWvFAD7iyptdkSFt\n" +
                    "DSc1uYR7llyFKB9/xqSPNBS6aSH/4ac1nGwoecpMkUXXdLSdJtxsCjjNbj9cSHLz\n" +
                    "Q6KU2K/O4SFbeQZoIHRQwJ8d0NTufaEjfuISavbmBQKBgQDbwdffKps9AwC03wB+\n" +
                    "bkRPYrjAuMJKLcjnSMcv2CZG/oCh3tj8p3QNB6y1x4VZhkP0s2EJaqaSS32xHzBh\n" +
                    "WtFLUVWXAlMiCs6NnTpz3ypPNLg+C0oyYJnHn8GgdmYp4aEiQ+VppqRN5q0UMAYZ\n" +
                    "ZABJcM6LqDOAYgIojJRADBp4DwKBgQDV3DDqDviuJsEPiwDqTplKolWqKehNNO7q\n" +
                    "WPOepqRMy4Buq4F0PAv9k2vet8E+k6COlQhLxUW2qq4+TgTtD1F7im5hX4DwSgSY\n" +
                    "bnPGBLrkJgLF7fRER1wuZL0RcXNuvsivBpYIktrqmLXv222mjLgjBLaD409gpDjG\n" +
                    "YPPgey2tUwKBgQCweJV17K0E7ahflsS6wqmwZkKe4L+E+gdfU55A2X7DfBSn6GCv\n" +
                    "Y3laDVOwFi0LmzpvAq1l9nMU//JLjhQ32cpAhWwJ/B/uMmd0aVJLQmajfF6H1GEc\n" +
                    "214iZDQFO48HCt1uur87fEptFFTg5T/AnAFu+Fuk4smYyxuYnGtgk1eeGQKBgQCr\n" +
                    "J5g2GllH91gXemX3H4RrSNRKZVO3Rp/XCe2fkTp5A3z8FWJ7hfsKrEtuaZ3M2RVs\n" +
                    "RzXmfjE26g6dao9ishnCR53jbC2jIXngDLW3St3P7ePWSIRviLTrpE/0f9mkTigK\n" +
                    "e7jjj7SIgENLfU+aNZDA5eq0Tt2eOI//pGRJygtaZQKBgFS3x79KchZW6h8ksy7z\n" +
                    "ve3zNxaB0MDFYcZ9OlwtePHw9bX/prtLlSXuydU1UHZaq9fZi6bKiFKjUti9BI2G\n" +
                    "fzHx7T9xMqx4TR+Dbzbrc3GYX3hnXqq7HxdELBTrrU9O3MGL+Ui1X4/mOePR0IM0\n" +
                    "7sQmDfjsHEhFBGwmnRMIecrc\n" +
                    "-----END PRIVATE KEY-----";

    public static void main(String[] args) throws Exception {
        // Read in the key into a String
        StringBuilder pkcs8Lines = new StringBuilder();
        BufferedReader rdr = new BufferedReader(new StringReader(PRIVATE_KEY));
        String line;
        while ((line = rdr.readLine()) != null) {
            pkcs8Lines.append(line);
        }

        // Remove the "BEGIN" and "END" lines, as well as any whitespace

        String pkcs8Pem = pkcs8Lines.toString();
        pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replaceAll("\\s+","");

        // Base64 decode the result

        byte [] pkcs8EncodedBytes = Base64.decode(pkcs8Pem, Base64.DEFAULT);

        // extract the private key

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        System.out.println(privKey);
    }

}

