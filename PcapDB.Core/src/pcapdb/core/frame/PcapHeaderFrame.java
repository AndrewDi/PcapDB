package pcapdb.core.frame;

import java.io.Serializable;

/**
 * This class contains Pcap File Header Structure
 *
 * @author PanDi(anonymous-oss@outlook.com)
 */
public class PcapHeaderFrame implements Serializable {

    /**
     * The length of iMagic field
     */
    public static final int iMagicLength = 4;

    /**
     * The length of iMaversion field
     */
    public static final int iMaVersionLength=2;

    /**
     * The length of iMiVersion field
     */
    public static final int iMiVersionLength=2;

    /**
     * The length of iTimezone field
     */
    public static final int iTimezoneLength=4;

    /**
     * The length of iSigFlags field
     */
    public static final int iSigFlagsLength=4;

    /**
     * The length of iSnapLen field
     */
    public static final int iSnapLenLength=4;

    /**
     * The length of iLinkType field
     */
    public static final int iLinkTypeLength=4;

    /**
     * The offset of iMagic field
     */
    public static final int iMagicPosition = 0;

    /**
     * The offset of iMaversion field
     */
    public static final int iMaVersionPosition;

    /**
     * The offset of iMiVersion field
     */
    public static final int iMiVersionPosition;

    /**
     * The offset of iTimezone field
     */
    public static final int iTimezonePosition;

    /**
     * The offset of iSigFlags field
     */
    public static final int iSigFlagsPosition;

    /**
     * The offset of iSnapLen field
     */
    public static final int iSnapLenPosition;

    /**
     * The offset of iLinkType field
     */
    public static final int iLinkTypePosition;

    /**
     * The totalLength of this header
     */
    public static final int totalLength;

    static {
        iMaVersionPosition=iMagicPosition+iMagicLength;
        iMiVersionPosition=iMaVersionPosition+iMaVersionLength;
        iTimezonePosition=iMiVersionPosition+iMiVersionLength;
        iSigFlagsPosition=iTimezonePosition+iTimezoneLength;
        iSnapLenPosition=iSigFlagsPosition+iSigFlagsLength;
        iLinkTypePosition=iSnapLenPosition+iSnapLenLength;
        totalLength=iLinkTypePosition+iLinkTypeLength;
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
                ", totalLength=" + totalLength +
                '}';
    }
}
