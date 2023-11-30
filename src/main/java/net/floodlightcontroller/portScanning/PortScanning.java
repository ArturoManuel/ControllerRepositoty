package net.floodlightcontroller.portScanning;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.mactracker.MACTracker;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;

import java.util.*;


import net.floodlightcontroller.core.IFloodlightProviderService;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;

import net.floodlightcontroller.packet.Ethernet;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PortScanning implements IOFMessageListener, IFloodlightModule {


    protected IFloodlightProviderService floodlightProvider;

    protected Map<IPv4Address, Set<TransportPort>> portAccessMap;
    protected Map<IPv4Address, Long> lastAccessTimeMap;
    protected final int PORT_SCAN_THRESHOLD = 10; // Ejemplo: umbral de puertos
    protected final long TIME_WINDOW = 10 * 1000;

    protected Set<Long> macAddresses;
    protected static Logger logger;


    @Override
    public String getName() {
        return  PortScanning.class.getSimpleName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }


    @Override
    public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        if (eth.getEtherType() == EthType.IPv4) {
            IPv4 ipv4 = (IPv4) eth.getPayload();
            if (ipv4.getProtocol() == IpProtocol.TCP || ipv4.getProtocol() == IpProtocol.UDP) {
                IPv4Address srcIp = ipv4.getSourceAddress();
                TransportPort dstPort = (ipv4.getPayload() instanceof TCP) ?
                        ((TCP) ipv4.getPayload()).getDestinationPort() :
                        ((UDP) ipv4.getPayload()).getDestinationPort();

                Set<TransportPort> ports = portAccessMap.get(srcIp);
                if (ports == null) {
                    ports = new ConcurrentSkipListSet<>();
                    portAccessMap.put(srcIp, ports);
                }
                ports.add(dstPort);

                lastAccessTimeMap.put(srcIp, System.currentTimeMillis());

                if (isPortScan(srcIp)) {
//                    blockSourceIp(sw, srcIp);
                    logger.info("Detección de escaneo de puertos desde la IP: {}, en el switch con MAC: {}",
                            srcIp.toString(), sw.getId().toString());
                    return Command.STOP;
                }
            }
        }
        return Command.CONTINUE;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        macAddresses = new ConcurrentSkipListSet<Long>();
        logger = LoggerFactory.getLogger(PortScanning.class);

        portAccessMap = new ConcurrentHashMap<>();

        lastAccessTimeMap = new ConcurrentHashMap<>();
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }
    protected boolean isPortScan(IPv4Address srcIp) {
        Set<TransportPort> accessedPorts = portAccessMap.get(srcIp);
        long currentTime = System.currentTimeMillis();
        Long lastAccessTime = lastAccessTimeMap.get(srcIp);
        if (lastAccessTime == null) {
            lastAccessTime = currentTime; // o podrías usar un valor predeterminado
        }

        // Verificar si el número de accesos en el tiempo establecido excede el umbral
        if (accessedPorts != null && (currentTime - lastAccessTime <= TIME_WINDOW) && accessedPorts.size() > PORT_SCAN_THRESHOLD) {
            return true;
        }

        return false;
    }


    protected void blockSourceIp(IOFSwitch sw, IPv4Address srcIp) {
        // Implementar bloqueo de IP aquí. Esto podría ser mediante la inserción de una regla de flujo en el switch para
        // bloquear tráfico desde la IP de origen.
        Match.Builder mb = sw.getOFFactory().buildMatch();
        mb.setExact(MatchField.ETH_TYPE, EthType.IPv4)
                .setExact(MatchField.IPV4_SRC, srcIp);

        OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
        fmb.setMatch(mb.build())
                .setIdleTimeout(0)
                .setHardTimeout(3600) // Ejemplo: tiempo en segundos antes de que la regla expire
                .setPriority(32768)
                .setBufferId(OFBufferId.NO_BUFFER)
                .setActions(Collections.<OFAction>emptyList()); // No se especifican acciones para efectivamente 'dropear' el paquete

        try {
            sw.write(fmb.build());
        } catch (Exception e) {
            logger.error("Error al bloquear la IP de origen: {}", srcIp, e);
        }
    }
}
