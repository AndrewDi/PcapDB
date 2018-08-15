package pcapdb.core.frame;

/**
 * This class contains Ethernet LinkType Frame Structure
 *
 * @author PanDi(anonymous-oss@outlook.com)
 */
public class EthernetFrame {

    /**
     * The length of DestinationAddress field
     */
    public static final int DestinationAddressLength=6;

    /**
     * The length of SourceAddress field
     */
    public static final int SourceAddressLength=6;

    /**
     * The length of Type field
     */
    public static final int TypeLength=2;

    /**
     * The offset of DestinationAddress field
     */
    public static final int DestinationAddressPosition=0;

    /**
     * The offset of SourceAddress field
     */
    public static final int SourceAddressPosition;

    /**
     * The offset of Type field
     */
    public static final int TypePosition;

    /**
     * The totalLength of this header
     */
    public static final int totalLength;

    /**
     * Calculater position offset
     */
    static {
        SourceAddressPosition=DestinationAddressPosition+DestinationAddressLength;
        TypePosition = SourceAddressPosition+SourceAddressLength;
        totalLength=TypePosition+TypeLength;
    }

    @Override
    public String toString() {
        return "EthernetFrame{" +
                "DestinationAddressLength=" + DestinationAddressLength +
                ", SourceAddressLength=" + SourceAddressLength +
                ", TypeLength=" + TypeLength +
                ", DestinationAddressPosition=" + DestinationAddressPosition +
                ", SourceAddressPosition=" + SourceAddressPosition +
                ", TypePosition=" + TypePosition +
                ", totalLength=" + totalLength +
                '}';
    }
}
