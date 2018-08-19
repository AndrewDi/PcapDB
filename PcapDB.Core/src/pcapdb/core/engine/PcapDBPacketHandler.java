package pcapdb.core.engine;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PcapDBPacketHandler<PacketBus> implements PcapPacketHandler<Object> {
    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    @Override
    public void nextPacket(PcapPacket pcapPacket, Object o) {
        logger.debug(pcapPacket.toHexdump());
        logger.debug(o.toString());
    }
}
