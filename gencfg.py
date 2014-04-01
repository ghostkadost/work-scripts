#/usr/bin/python3

import sys
import ipaddress

#######################################################################
#############  Globals. Modify as needed  #############################
initiator="snart"
responder="defcon"

numRules=4000
termsInRules=2
useDPD = False

scardOnInitiator="ms-3/0/0"
scardOnResponder="ms-2/2/0"

egressInitiator="ge-4/0/2"
ingressInitiator="ge-4/0/9"

egressResponder="ge-2/0/0"
ingressResponder="ge-2/0/9"

ingressInitiatorIP="192.168.0.1/24"
ingressResponderIP="192.168.1.1/24"

localSubnet="30.0.0.0/16"
remoteSubnet="80.0.0.0/16"

gatewayStartAddress="10.0.0.1/24"

############### End of global section ################################
######################################################################

######################################################################
##### Do not modify anything below this ##############################
######################################################################


######################################################################
################  Start of Invariates Section  #######################
prefixIPsec = "set services ipsec-vpn "
prefixService = "set services service-set "
prefixInterface = "set interfaces "
prefixRoute = "set routing-options " 

################  End of Invariates Section  #########################
######################################################################

######################################################################
############ Helper functions  #######################################
def getNextSubnet(substr):
    try:
        subnet = ipaddress.ip_network(substr, strict = False)
        base = int(subnet[1])
        nextBase = base + subnet.num_addresses
        nextBaseAddr = ipaddress.ip_address(nextBase)
        nextBaseAddrStr = str(nextBaseAddr) + '/' + str(subnet.prefixlen)
        nextBaseSubStr = ipaddress.ip_network(nextBaseAddrStr, strict = False)
        return str(nextBaseSubStr)
    except ValueError:
        print('subnet is invalid:', substr)
        return Null

def getNextGatewayInterface(addr):
    try:
        interface = ipaddress.ip_interface(addr)
        ip = interface.ip
        network = interface.network
        nextIP = int(ip) + network.num_addresses
        return str(ipaddress.ip_address(nextIP)) + '/' + str(network.prefixlen)
    except ValueError:
        print('interface address is invalid:', addr)
        return Null

def getNextIPInSameSubnet(addr):
    try:
        interface = ipaddress.ip_interface(addr)
        ip = interface.ip
        return str(ipaddress.ip_address(int(ip) + 1))
    except ValueError:
        print('interface address is invalid:', addr)
        return Null

def constructIKEProposal(name="ikeProp"):
    ikeProposal=[]
    proposalPrefix = prefixIPsec + "ike proposal " + name + " "
    ikeProposal.append(proposalPrefix + " authentication-method pre-shared-keys")
    ikeProposal.append(proposalPrefix + " dh-group group2")
    return ikeProposal

def constructIKEPolicy(proposals, name="ikePolicy", version=2, mode="main"):
    ikePolicy=[]
    policyPrefix = prefixIPsec + "ike policy " + name + " "
    ikePolicy.append(policyPrefix + " version " + str(version))
    ikePolicy.append(policyPrefix + " pre-shared-key ascii-text Juniper1234") 
    for proposal in proposals:
        ikePolicy.append(policyPrefix + " proposals " + proposal)

    return ikePolicy

def constructIPsecProposal(name="ipsecProp"):
    ipsecProposal=[]
    proposalPrefix = prefixIPsec + "ipsec proposal " + name + " "
    ipsecProposal.append(proposalPrefix + "protocol esp")
    ipsecProposal.append(proposalPrefix + "authentication-algorithm hmac-sha1-96")
    ipsecProposal.append(proposalPrefix + "encryption-algorithm aes-128-cbc")
    return ipsecProposal

def constructIPsecPolicy(proposals, name="ipsecPolicy"):
    ipsecPolicy=[]
    policyPrefix = prefixIPsec + "ipsec policy " + name + " "
    ipsecPolicy.append(policyPrefix + "perfect-forward-secrecy keys group2")
    for proposal in proposals:
        ipsecPolicy.append(policyPrefix + " proposals " + proposal)

    return ipsecPolicy

def constructTerm(fromAddress, toAddress, remote, ikePolicy, ipsecPolicy, 
                  rulePrefix, termName, dpd):
    term = []
    termPrefix = rulePrefix + " term " + termName + " "
    term.append(termPrefix + "from source-address " + fromAddress)
    term.append(termPrefix + "from destination-address " + toAddress)
    term.append(termPrefix + "then remote-gateway " + remote)
    term.append(termPrefix + "then dynamic ike-policy " + ikePolicy)
    term.append(termPrefix + "then dynamic ipsec-policy " + ipsecPolicy)
    if dpd == True:
        term.append(termPrefix + "then initiate-dead-peer-detection")

    return term

def constructRoute(destinationAddress, nextHop, isV6 = False):
    route = prefixRoute
    if isV6 == True:
        route += " rib inet6.0 static route "
    else:
        route += "static route "

    route += destinationAddress + " next-hop " + nextHop
    return route

def constructDefaultServiceInterface(interfaceName):
    interface = []
    interface.append(prefixInterface + interfaceName + " unit 0 family inet")
    return interface


def constructServiceInterface(logicalInterface, nextHopStyle = True):
    interface = []
    prefixUnit = prefixInterface + logicalInterface.interfaceName + " unit " + str(logicalInterface.unit)
    interface.append(prefixUnit + " family inet")
    interface.append(prefixUnit + " family inet6")
    if nextHopStyle == True:
        interface.append(prefixUnit + " service-domain inside")
        prefixUnit = prefixInterface + logicalInterface.interfaceName + " unit " + str(logicalInterface.getPairedUnit())
        interface.append(prefixUnit + " family inet")
        interface.append(prefixUnit + " family inet6")
        interface.append(prefixUnit + " service-domain outside")

    return interface

def getVLANStrint(interfaceName):
    return [prefixInterface + interfaceName + " vlan-tagging"]


def constructPhysicalInterface(logicalInterface, 
                              interfaceAddress, serviceSet = None):
    interface = []
    prefix = prefixInterface + logicalInterface.interfaceName + " unit " + str(logicalInterface.unit)
    if logicalInterface.vlanTag != 0:
        interface.append(prefix + " vlan-id " + str(logicalInterface.vlanTag))

    if interfaceAddress.version == 4:
        prefix += " family inet address "
    else:
        prefix += " family inet6 address "

    interface.append(prefix + str(interfaceAddress))
    if serviceSet is not None:
        interface.append(prefix + " service input service-set " + serviceSet)
        interface.append(prefix + " service output service-set " + serviceSet)

    return interface
######################################################################

######################################################################
######### Helper classes  ############################################

class Interface:

    def __init__(self, interfaceName, serviceInt = True, unit = 0 , vlanTag = 0, address =
            ipaddress.ip_interface('0.0.0.0/0')):
        self.interfaceName = interfaceName
        self.serviceInt = serviceInt
        self.unit = unit
        self.pairedUnit = unit + 1
        self.vlanTag = vlanTag
        self.address = address

    def getPairedUnit(self):
        return self.pairedUnit

    def getNameWithUnit(self):
        return self.interfaceName + '.' + str(self.unit)

    def getNameWithPairedUnit(self):
        return self.interfaceName + '.' + str(self.pairedUnit)

# XXX Add more functions to this class and make it self rendering

class Term:

    def __init__(self, localSubnet, remoteSubnet):
        self.localSubnet = localSubnet
        self.remoteSubnet = remoteSubnet


class Rule:

    def __init__(self, name, startLocalSubnet, startRemoteSubnet, remoteGW, 
                 numTerms):
        self.terms = []
        self.name = name
        self.startLocalSubnet = startLocalSubnet
        self.startRemoteSubnet = startRemoteSubnet
        self.remoteGW = remoteGW 
        self.termsInRules = numTerms
        self.dpdPolicy = True
        self.direction='input'
        self.ikePolicy = None
        self.ipsecPolicy = None

       
    def setIKEAndIPsecPolicy(self, ikePolicy, ipsecPolicy):
        self.ikePolicy = ikePolicy
        self.ipsecPolicy = ipsecPolicy

    def setDirection(self, direction = "input"):
        self.direction = direction

    def setDPDPolicy(self, dpdPolicy=True):
        self.dpdPolicy = dpdPolicy

    def getLastTerm(self):
        return self.terms[-1]

    def getRuleName(self):
        return self.name

    def _generateTermAddresses(self):
        localSubnet = self.startLocalSubnet
        remoteSubnet = self.startRemoteSubnet

        for i in range(0, self.termsInRules):
            term = Term(localSubnet, remoteSubnet)
            self.terms.append(term)
            localSubnet = getNextSubnet(localSubnet)
            remoteSubnet = getNextSubnet(remoteSubnet)

    def constructRule(self):
        rule = []
        rulePrefix = "set services ipsec-vpn rule " + self.name + " "
        self._generateTermAddresses()
        for i in range(0,self.termsInRules):
            term = constructTerm(self.terms[i].localSubnet, 
                                 self.terms[i].remoteSubnet, 
                                 self.remoteGW, self.ikePolicy, 
                                 self.ipsecPolicy,
                                 rulePrefix, "term" + str(i), self.dpdPolicy)
            for j in term:
                rule.append(str(j).strip('[]'))

        rule.append(rulePrefix + 'match-direction ' + self.direction)
        return rule

    def generateRoutesForRule(self, nextHopForLocal, nextHopForRemote,
                              remoteNeeded = True):
        routes = []
        for i in range(self.termsInRules):
            routes.append(constructRoute(self.terms[i].localSubnet, 
                                         nextHopForLocal))
            if remoteNeeded == True:
                routes.append(constructRoute(self.terms[i].remoteSubnet, 
                                             nextHopForRemote))

        return routes
    
class ServiceSet:

    def __init__(self, name, nextHop = True):
        self.name = name
        self.nextHop = nextHop
        self.localGateway = None
        self.ruleName = None
        self.insideInterface = None
        self.outsideInterface = None
        self.serviceInterface = None

    def setLocalGateWay(self, localGateway):
        self.localGateway = localGateway

    def setRuleName(self, ipsecRuleName):
        self.ruleName = ipsecRuleName

    def setNextHopInterfaces(self, insideInterface, outsideInterface):
        self.insideInterface = insideInterface
        self.outsideInterface = outsideInterface

    def setServiceInterface(self, serviceInterface):
        self.serviceInterface = serviceInterface

    def constructServiceSet(self):
        serviceSet = []
        serviceSetPrefix = prefixService + self.name + " "
        if self.nextHop == True:
            serviceSet.append(serviceSetPrefix + "next-hop-service " +
                              "inside-service-interface " + self.insideInterface)
            serviceSet.append(serviceSetPrefix + "next-hop-service " +
                              "outside-service-interface " + self.outsideInterface)
        else:
            serviceSet.append(serviceSetPrefix + "interface-service " + 
                              "service-interface " + self.serviceInterface)

        serviceSet.append(serviceSetPrefix + "ipsec-vpn-options " + 
                          "local-gateway " + self.localGateway)
        serviceSet.append(serviceSetPrefix + "ipsec-vpn-rules " + 
                          self.ruleName) 
        return serviceSet






def writeToFile(policy, f):
    for line in policy:
        f.write(str(line).strip('[]'))
        f.write('\n')

    return

def main():
    ikeProp = 'ikeProp'
    ikePolicy = 'ikePolicy'
    ipsecProp = 'ipsecProp'
    ipsecPolicy = 'ipsecPolicy'
    startLocalSubnet = localSubnet
    startRemoteSubnet = remoteSubnet
    nextLocalGateway = str(ipaddress.ip_interface(gatewayStartAddress).ip)
    gatewayPrefix = str(ipaddress.ip_interface(gatewayStartAddress).network.prefixlen)
    nextRemoteGateway = getNextIPInSameSubnet(gatewayStartAddress)
    nextLocalGatewayInterface = gatewayStartAddress
    nextRemoteGatewayInterface = nextRemoteGateway + '/' + gatewayPrefix
    f1 = open(initiator + '.junos', 'w')
    f2 = open(responder + '.junos', 'w')
    policy = constructIKEProposal(ikeProp)
    writeToFile(policy, f1)
    writeToFile(policy, f2)

    policy = constructIKEPolicy([ikeProp], ikePolicy)
    writeToFile(policy, f1)
    writeToFile(policy, f2)

    policy = constructIPsecProposal(ipsecProp)
    writeToFile(policy, f1)
    writeToFile(policy, f2)

    policy = constructIPsecPolicy([ipsecProp], ipsecPolicy)
    writeToFile(policy, f1)
    writeToFile(policy, f2)

    for i in range(0, numRules):
        #Create Rule
        ruleI = Rule('ipsec-rule-' + str(i), startLocalSubnet, startRemoteSubnet,
                    nextRemoteGateway, termsInRules)
        #Create Service Set
        serviceSetI = ServiceSet('ipsec-sset-' + str(i))
        #Create Service Interface
        serviceIntI = Interface(scardOnInitiator, unit = 2 * i + 1)
        #Create egress Interface
        egressIntI = Interface(egressInitiator, serviceInt = False, 
                               unit = i, vlanTag = i + 1)

        #Write Rule
        ruleI.setIKEAndIPsecPolicy(ikePolicy, ipsecPolicy)
        ruleI.setDPDPolicy(useDPD)
        policy = ruleI.constructRule()
        writeToFile(policy, f1)

        #Write service Set 
        serviceSetI.setLocalGateWay(nextLocalGateway)
        serviceSetI.setRuleName('ipsec-rule-' + str(i))
        serviceSetI.setNextHopInterfaces(serviceIntI.getNameWithUnit(),
                                         serviceIntI.getNameWithPairedUnit())
        policy = serviceSetI.constructServiceSet()
        writeToFile(policy, f1)

        #Write default service interface
        policy = constructDefaultServiceInterface(scardOnInitiator)
        writeToFile(policy, f1)

        #Write Service Interface
        policy = constructServiceInterface(serviceIntI)
        writeToFile(policy, f1)

        #Write physical interface Vlan thingy
        policy = getVLANStrint(egressInitiator)
        writeToFile(policy, f1)

        #Write egress interface IP address information
        policy = constructPhysicalInterface(egressIntI, 
                                            ipaddress.ip_interface(nextLocalGatewayInterface))
        writeToFile(policy, f1)

        #Write Route information
        policy = ruleI.generateRoutesForRule(str(ipaddress.ip_interface(ingressInitiatorIP).ip),
                                             serviceIntI.getNameWithUnit())
        writeToFile(policy, f1)
                                             

        ruleR = Rule('ipsec-rule-' + str(i), startRemoteSubnet, startLocalSubnet,
                     nextLocalGateway, termsInRules)

        serviceSetR = ServiceSet('ipsec-sset-' + str(i))
        serviceIntR = Interface(scardOnResponder, unit = 2 * i + 1)
        egressIntR = Interface(egressResponder, serviceInt = False, 
                               unit = i, vlanTag = i + 1)


        ruleR.setIKEAndIPsecPolicy(ikePolicy, ipsecPolicy)
        ruleR.setDPDPolicy(useDPD)
        policy = ruleR.constructRule()
        writeToFile(policy, f2)
        
        serviceSetR.setLocalGateWay(nextRemoteGateway)
        serviceSetR.setRuleName('ipsec-rule-' + str(i))
        serviceSetR.setNextHopInterfaces(serviceIntR.getNameWithUnit(),
                                         serviceIntR.getNameWithPairedUnit())
        policy = serviceSetR.constructServiceSet()
        writeToFile(policy, f2)


        policy = constructDefaultServiceInterface(scardOnResponder)
        writeToFile(policy, f2)

        policy = constructServiceInterface(serviceIntR)
        writeToFile(policy, f2)

        policy = getVLANStrint(egressResponder)
        writeToFile(policy, f2)

        policy = constructPhysicalInterface(egressIntR,
                                            ipaddress.ip_interface(nextRemoteGatewayInterface))
        writeToFile(policy, f2)

        policy = ruleR.generateRoutesForRule(str(ipaddress.ip_interface(ingressResponderIP).ip),
                                                 serviceIntR.getNameWithUnit())
        writeToFile(policy, f2)

        startLocalSubnet  = getNextSubnet(ruleI.getLastTerm().localSubnet)
        startRemoteSubnet = getNextSubnet(ruleI.getLastTerm().remoteSubnet)

        nextLocalGatewayInterface = getNextGatewayInterface(nextLocalGatewayInterface) 
        nextLocalGateway = str(ipaddress.ip_interface(nextLocalGatewayInterface).ip)
        nextRemoteGateway = getNextIPInSameSubnet(nextLocalGatewayInterface)
        nextRemoteGatewayInterface = nextRemoteGateway + '/' + str(ipaddress.ip_interface(gatewayStartAddress).network.prefixlen)

    ingressIntI = Interface(ingressInitiator, serviceInt = False)
    ingressIntR = Interface(ingressResponder, serviceInt = False)

    policy = constructPhysicalInterface(ingressIntI, 
                                        ipaddress.ip_interface(ingressInitiatorIP)) 
    writeToFile(policy, f1)
    
    policy = constructPhysicalInterface(ingressIntR,
                                        ipaddress.ip_interface(ingressResponderIP))
    writeToFile(policy, f2)

    f1.close()
    f2.close()

    print ("Hello world\n")




if __name__ == "__main__":
    main()
