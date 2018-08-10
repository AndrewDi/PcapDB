package pcapdb.core.frame;

import java.io.Serializable;

public class PcapHeaderFrame implements Serializable {

    public static int iMagicLength = 4;

    public static int iMaVersionLength=2;

    public static int iMiVersionLength=2;

    public static int iTimezoneLength=4;

    public static int iSigFlagsLength=4;

    public static int iSnapLenLength=4;

    public static int iLinkTypeLength=4;

    public static int iMagicPosition = 0;

    public static int iMaVersionPosition;

    public static int iMiVersionPosition;

    public static int iTimezonePosition;

    public static int iSigFlagsPosition;

    public static int iSnapLenPosition;

    public static int iLinkTypePosition;

    static {
        iMaVersionPosition=iMagicPosition+iMagicLength;
        iMiVersionPosition=iMaVersionPosition+iMaVersionLength;
        iTimezonePosition=iMiVersionPosition+iMiVersionLength;
        iSigFlagsPosition=iTimezonePosition+iTimezoneLength;
        iSnapLenPosition=iSigFlagsPosition+iSigFlagsLength;
        iLinkTypePosition=iSnapLenPosition+iSnapLenLength;
    }

    @Override
    public String toString() {
        return "PcapHeaderFrame{" +
                "iMagicLength=" + iMagicLength +
                ", iMaVersionLength=" + iMaVersionLength +
                ", iMiVersionLength=" + iMiVersionLength +
                ", iTimezoneLength=" + iTimezoneLength +
                ", iSigFlagsLength=" + iSigFlagsLength +
                ", iSnapLenLength=" + iSnapLenLength +
                ", iLinkTypeLength=" + iLinkTypeLength +
                ", iMagicPosition=" + iMagicPosition +
                ", iMaVersionPosition=" + iMaVersionPosition +
                ", iMiVersionPosition=" + iMiVersionPosition +
                ", iTimezonePosition=" + iTimezonePosition +
                ", iSigFlagsPosition=" + iSigFlagsPosition +
                ", iSnapLenPosition=" + iSnapLenPosition +
                ", iLinkTypePosition=" + iLinkTypePosition +
                '}';
    }
}
