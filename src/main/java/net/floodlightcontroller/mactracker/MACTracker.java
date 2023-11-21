package net.floodlightcontroller.mactracker;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.*;

import java.util.*;


import java.util.Collection;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.MacAddress;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;

import java.util.concurrent.ConcurrentSkipListSet;

import net.floodlightcontroller.packet.Ethernet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.IPv4Address;

public class MACTracker implements IOFMessageListener, IFloodlightModule {


    protected IFloodlightProviderService floodlightProvider;
    protected Set<Long> macAddresses;
    protected static Logger logger;
    private Map<IPv4Address, MacAddress> allowedIPMacPairs;

    @Override
    public String getName() {
        return MACTracker.class.getSimpleName();
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
        MacAddress sourceMac = eth.getSourceMACAddress();
        IPv4Address srcIp = null;

        // Procesa solo paquetes IPv4
        if (eth.getEtherType() == EthType.IPv4) {
            IPv4 ipv4 = (IPv4) eth.getPayload();
            srcIp = ipv4.getSourceAddress();

            // Registra todos los paquetes IPv4
            logger.info("Paquete IPv4 recibido: IP Origen: {}, MAC Origen: {}", srcIp.toString(), sourceMac.toString());

            // Procesa solo paquetes ICMP
            if (ipv4.getProtocol() == IpProtocol.ICMP) {
                // Revisa si la dirección IP de origen está en la lista de pares permitidos
                if (allowedIPMacPairs.containsKey(srcIp)) {
                    if (!allowedIPMacPairs.get(srcIp).equals(sourceMac)) {
                        logger.info("Bloqueo de paquete ICMP desde IP: {}, con MAC: {}. La dirección MAC no coincide con la permitida.", srcIp.toString(), sourceMac.toString());
                        return Command.STOP;
                    }
                } else {
                    logger.info("Bloqueo de paquete ICMP desde IP no permitida: {}, con MAC: {}.", srcIp.toString(), sourceMac.toString());
                    return Command.STOP;
                }
            }
        } else {
            // Si deseas registrar otros tipos de paquetes, puedes hacerlo aquí
            logger.info("Paquete no IPv4 recibido, tipo EtherType: {}", eth.getEtherType());
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
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        macAddresses = new ConcurrentSkipListSet<Long>();
        logger = LoggerFactory.getLogger(MACTracker.class);

        // Inicializa el HashMap para almacenar los pares permitidos de IP y MAC
        allowedIPMacPairs = new HashMap<>();

        // Agrega los pares permitidos de IP y MAC
        allowedIPMacPairs.put(IPv4Address.of("10.0.0.1"), MacAddress.of("fa:16:3e:3f:84:9c"));
        allowedIPMacPairs.put(IPv4Address.of("10.0.0.2"), MacAddress.of("fa:16:3e:03:d1:8b"));
        allowedIPMacPairs.put(IPv4Address.of("10.0.0.21"), MacAddress.of("fa:16:3e:01:a4:c0"));
        // ... Agrega tantas combinaciones como necesites
    }


    @Override
    public void startUp(FloodlightModuleContext context) {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }
}
