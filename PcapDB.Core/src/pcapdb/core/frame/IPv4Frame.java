package pcapdb.core.frame;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IPv4Frame {
    protected final Logger logger = LoggerFactory.getLogger(this.toString());

    public static int VersionAndHeaderLengthLength = 1;

    public static int DifferentiatedServicesLength = 1;

    public static int TotalLengthLength = 2;

    public static int IdLength = 2;

    public static int FragmentOffsetAndFlagsLength=2;

    public static int TtlLength = 1;

    public static int ProtocolLength = 1;

    public static int ChecksumLength = 2;

    public static int VersionAndHeaderLengthPosition = 0;

    public static int AddressLength = 4;

    public static int DifferentiatedServicesPosition;

    public static int TotalLengthPosition;

    public static int IdPosition;

    public static int FragmentOffsetAndFlagsPosition;

    public static int TtlPosition;

    public static int ProtocolPosition;

    public static int ChecksumPosition;

    public static int SourcePosition;

    public static int DestinationPosition;

    public static int totalLength;

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
