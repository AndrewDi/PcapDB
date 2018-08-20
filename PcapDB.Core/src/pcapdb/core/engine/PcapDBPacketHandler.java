package pcapdb.core.engine;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;

public class PcapDBPacketHandler implements PcapPacketHandler<PacketBus> {
    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    @Override
    public void nextPacket(PcapPacket pcapPacket, PacketBus packetBus) {
        packetBus.Dispatch(pcapPacket);
    }
}
