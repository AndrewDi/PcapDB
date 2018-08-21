package pcapdb.core.frame;

import java.util.HashMap;

public class SECCHKCDReson {
    private static HashMap<Integer,String> hashMap = new HashMap<>();

    static {
        hashMap.put(0x00,"The security information is correct and acceptable");
        hashMap.put(0x01,"SECMEC value not supported");
        hashMap.put(0x02,"DCE informational status issued");
        hashMap.put(0x03,"DCE retryable error");
        hashMap.put(0x04,"DCE non-retryable error");
        hashMap.put(0x05,"GSSAPI informational status issued");
        hashMap.put(0x06,"GSSAPI retryable error");
        hashMap.put(0x07,"GSSAPI non-retryable error");
        hashMap.put(0x08,"Local Security Service informational status issued");
        hashMap.put(0x09,"Local Security Service retryable error");
        hashMap.put(0x0A,"Local Security Service non-retryable error");
        hashMap.put(0x0B,"SECTKN missing on ACCSEC when it is required, or it is invalid.");
        hashMap.put(0x0E,"Password expired.");
        hashMap.put(0x0F,"Password invalid.");
        hashMap.put(0x10,"Password missing.");
        hashMap.put(0x12,"Userid missing.");
        hashMap.put(0x13,"Userid invalid.");
        hashMap.put(0x14,"Userid revoked.");
        hashMap.put(0x15,"New Password invalid.");
    }

    public static String ValueOf(int value){
        return hashMap.getOrDefault(value,"UNKNOWN");
    }
}
