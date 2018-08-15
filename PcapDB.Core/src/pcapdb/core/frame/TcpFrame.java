package pcapdb.core.frame;

/**
 * This class contains TCP Header Structure
 *
 * @author PanDi(anonymous-oss@outlook.com)
 */
public class TcpFrame {

    public static final int TCP_NS_MASK = 0x0100;
    public static final int TCP_CWR_MASK = 0x0080;
    public static final int TCP_ECN_MASK = 0x0040;
    public static final int TCP_URG_MASK = 0x0020;
    public static final int TCP_ACK_MASK = 0x0010;
    public static final int TCP_PSH_MASK = 0x0008;
    public static final int TCP_RST_MASK = 0x0004;
    public static final int TCP_SYN_MASK = 0x0002;
    public static final int TCP_FIN_MASK = 0x0001;

    public static final int PortLength = 2;

    /**
     * The length of Sequence Number field
     */
    public static final int SequenceNumberLength = 4;

    /**
     * The length of Ack Number field
     */
    public static final int AckNumberLength = 4;

    /**
     * The length of data offset and flags field
     */
    public static final int DataOffsetAndFlagsLength = 2;

    /**
     * The length of Window Size field
     */
    public static final int WindowSizeLength = 2;

    /**
     * The length of Checksum field
     */
    public static final int ChecksumLength = 2;

    /**
     * The length of UrgentPointer field
     */
    public static final int UrgentPointerLength = 2;

    /**
     * The offset of Source Port field
     */
    public static final int SourcePortPosition = 0;

    /**
     * The offset of Destination Port field
     */
    public static final int DestinationPortPosition;

    /**
     * The offset of Sequence Number field
     */
    public static final int SequenceNumberPosition;

    /**
     * The offset of Ack Number field
     */
    public static final int AckNumberPosition;

    /**
     * The offset of Data offset and flags field
     */
    public static final int DataOffsetAndFlagsPosition;

    /**
     * The offset of Window Size field
     */
    public static final int WindowSizePosition;

    /**
     * The offset of Checksum field
     */
    public static final int ChecksumPosition;

    /**
     * The offset of UrgentPointer field
     */
    public static final int UrgentPointerPosition;

    /**
     * The totalLength of this header
     */
    public static final int totalLength;

    static {
        DestinationPortPosition = SourcePortPosition + PortLength;
        SequenceNumberPosition = DestinationPortPosition + PortLength;
        AckNumberPosition = SequenceNumberPosition + SequenceNumberLength;
        DataOffsetAndFlagsPosition = AckNumberPosition + AckNumberLength;
        WindowSizePosition = DataOffsetAndFlagsPosition + DataOffsetAndFlagsLength;
        ChecksumPosition = WindowSizePosition + WindowSizeLength;
        UrgentPointerPosition = ChecksumPosition + ChecksumLength;
        totalLength = UrgentPointerPosition + UrgentPointerLength;
    }

    @Override
    public String toString() {
        return "TcpFrame{" +
                "PortLength=" + PortLength +
                ", SequenceNumberLength=" + SequenceNumberLength +
                ", AckNumberLength=" + AckNumberLength +
                ", DataOffsetAndFlagsLength=" + DataOffsetAndFlagsLength +
                ", WindowSizeLength=" + WindowSizeLength +
                ", ChecksumLength=" + ChecksumLength +
                ", UrgentPointerLength=" + UrgentPointerLength +
                ", SourcePortPosition=" + SourcePortPosition +
                ", DestinationPortPosition=" + DestinationPortPosition +
                ", SequenceNumberPosition=" + SequenceNumberPosition +
                ", AckNumberPosition=" + AckNumberPosition +
                ", DataOffsetAndFlagsPosition=" + DataOffsetAndFlagsPosition +
                ", WindowSizePosition=" + WindowSizePosition +
                ", ChecksumPosition=" + ChecksumPosition +
                ", UrgentPointerPosition=" + UrgentPointerPosition +
                ", totalLength=" + totalLength +
                '}';
    }
}
