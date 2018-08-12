package pcapdb.core.frame;

public class TcpFrame {

    public static int TCP_NS_MASK = 0x0100;
    public static int TCP_CWR_MASK = 0x0080;
    public static int TCP_ECN_MASK = 0x0040;
    public static int TCP_URG_MASK = 0x0020;
    public static int TCP_ACK_MASK = 0x0010;
    public static int TCP_PSH_MASK = 0x0008;
    public static int TCP_RST_MASK = 0x0004;
    public static int TCP_SYN_MASK = 0x0002;
    public static int TCP_FIN_MASK = 0x0001;

    public static int PortLength = 2;

    /// <summary> Length of the sequence number in bytes.</summary>
    public static int SequenceNumberLength = 4;
    /// <summary> Length of the acknowledgment number in bytes.</summary>
    public static int AckNumberLength = 4;
    /// <summary> Length of the data offset and flags field in bytes.</summary>
    public static int DataOffsetAndFlagsLength = 2;
    /// <summary> Length of the window size field in bytes.</summary>
    public static int WindowSizeLength = 2;
    /// <summary> Length of the checksum field in bytes.</summary>
    public static int ChecksumLength = 2;
    /// <summary> Length of the urgent field in bytes.</summary>
    public static int UrgentPointerLength = 2;

    /// <summary> Position of the source port field.</summary>
    public static int SourcePortPosition = 0;
    /// <summary> Position of the destination port field.</summary>
    public static int DestinationPortPosition;
    /// <summary> Position of the sequence number field.</summary>
    public static int SequenceNumberPosition;
    /// <summary> Position of the acknowledgment number field.</summary>
    public static int AckNumberPosition;
    /// <summary> Position of the data offset </summary>
    public static int DataOffsetAndFlagsPosition;
    /// <summary> Position of the window size field.</summary>
    public static int WindowSizePosition;
    /// <summary> Position of the checksum field.</summary>
    public static int ChecksumPosition;
    /// <summary> Position of the urgent pointer field.</summary>
    public static int UrgentPointerPosition;

    public static int totalLength;

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
