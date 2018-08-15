package pcapdb.core.frame;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class contains IPv4 Packet Structure
 * @{link http://www.ietf.org/rfc/rfc793.txt}
 *
 * @author PanDi(anonymous-oss@outlook.com)
 */
public class IPv4Frame {
    protected final Logger logger = LoggerFactory.getLogger(this.toString());

    /**
     * The length of VersionAndHeaderLength field
     */
    public static final int VersionAndHeaderLengthLength = 1;

    /**
     * The length of DifferentiatedServices field
     */
    public static final int DifferentiatedServicesLength = 1;

    /**
     * The length of TotalLength field
     */
    public static final int TotalLengthLength = 2;

    /**
     * The length of Id field
     */
    public static final int IdLength = 2;

    /**
     * The length of FragmentOffsetAndFlags field
     */
    public static final int FragmentOffsetAndFlagsLength=2;

    /**
     * The length of Time to live field
     */
    public static final int TtlLength = 1;

    /**
     * The length of Protocol field
     */
    public static final int ProtocolLength = 1;

    /**
     * The length of Checksum field
     */
    public static final int ChecksumLength = 2;

    /**
     * The offset of VersionAndHeaderLength field
     */
    public static final int VersionAndHeaderLengthPosition = 0;

    /**
     * The length of IPv4 Address field
     */
    public static final int AddressLength = 4;

    /**
     * The offset of DifferentiatedServices field
     */
    public static final int DifferentiatedServicesPosition;

    /**
     * The offset of TotalLength field
     */
    public static final int TotalLengthPosition;

    /**
     * The offset of Id field
     */
    public static final int IdPosition;

    /**
     * The offset of FragmentOffsetAndFlags field
     */
    public static final int FragmentOffsetAndFlagsPosition;

    /**
     * The offset of Time to live field
     */
    public static final int TtlPosition;

    /**
     * The offset of Protocol field
     */
    public static final int ProtocolPosition;

    /**
     * The offset of Checksum field
     */
    public static final int ChecksumPosition;

    /**
     * The offset of Source field
     */
    public static final int SourcePosition;

    /**
     * The offset of Destination field
     */
    public static final int DestinationPosition;

    /**
     * The totalLength of this header
     */
    public static final int totalLength;

    /**
     * Calculater position offset
     */
    static {
        DifferentiatedServicesPosition = VersionAndHeaderLengthPosition + VersionAndHeaderLengthLength;
        TotalLengthPosition = DifferentiatedServicesPosition + DifferentiatedServicesLength;
        IdPosition = TotalLengthPosition + TotalLengthLength;
        FragmentOffsetAndFlagsPosition = IdPosition + IdLength;
        TtlPosition = FragmentOffsetAndFlagsPosition + FragmentOffsetAndFlagsLength;
        ProtocolPosition = TtlPosition + TtlLength;
        ChecksumPosition = ProtocolPosition + ProtocolLength;
        SourcePosition = ChecksumPosition + ChecksumLength;
        DestinationPosition = SourcePosition + AddressLength;
        totalLength = DestinationPosition + AddressLength;
    }

    @Override
    public String toString() {
        return "IPv4Frame{" +
                "VersionAndHeaderLengthLength=" + VersionAndHeaderLengthLength +
                ", DifferentiatedServicesLength=" + DifferentiatedServicesLength +
                ", TotalLengthLength=" + TotalLengthLength +
                ", IdLength=" + IdLength +
                ", FragmentOffsetAndFlagsLength=" + FragmentOffsetAndFlagsLength +
                ", TtlLength=" + TtlLength +
                ", ProtocolLength=" + ProtocolLength +
                ", ChecksumLength=" + ChecksumLength +
                ", VersionAndHeaderLengthPosition=" + VersionAndHeaderLengthPosition +
                ", AddressLength=" + AddressLength +
                ", DifferentiatedServicesPosition=" + DifferentiatedServicesPosition +
                ", TotalLengthPosition=" + TotalLengthPosition +
                ", IdPosition=" + IdPosition +
                ", FragmentOffsetAndFlagsPosition=" + FragmentOffsetAndFlagsPosition +
                ", TtlPosition=" + TtlPosition +
                ", ProtocolPosition=" + ProtocolPosition +
                ", ChecksumPosition=" + ChecksumPosition +
                ", SourcePosition=" + SourcePosition +
                ", DestinationPosition=" + DestinationPosition +
                ", totalLength=" + totalLength +
                '}';
    }
}
