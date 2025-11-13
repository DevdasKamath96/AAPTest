import os
import re
import sys
import configparser
from collections import OrderedDict
from pwd import getpwuid, getpwnam
from grp import getgrgid, getgrnam
import logging
import time
from typing import List
from xmlrpc import server
import yaml
import ipaddress as newipaddress
import json

from create_inventory import CreateInventory

class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
            return True

class MyDumper(yaml.Dumper):  # your force-indent dumper

    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)
    def ignore_aliases(self, data):
            return True

class QuotedString(str):  # just subclass the built-in str
    pass

def quoted_scalar(dumper, data):  # a representer to force quotations on scalars
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='"')

# add the QuotedString custom type with a forced quotation representer to your dumper
MyDumper.add_representer(QuotedString, quoted_scalar)

class Constants:
    AAP_API_URL = "https://controller.example.org/api/v2"
    AAP_USERNAME = "admin"
    AAP_PASSWORD = "redhat"
    ORG_NAME = "Default"
    EMSInvNAME = "EMSLaunchTest"
    FreshLaunchMainInvName = "FreshLaunchMain"
    FreshLaunchInvName = "FreshLaunch"
    POCGROUPNAME = "poc"
    NNIGROUPNAME = "nni"
    SSH_USER = "autoinstall"
    SSH_PASS = "kodiak"
    CONFIG_SCRIPT_PATH = "ipaserverclientconfig.sh"
    CONFIG_PATH = "/usr/local/bin/ipaconfig"
    Relative_path = "./files/"
    Psswdhosts = f'{Relative_path}psswdhosts'
    MasterConfFile = f'{Relative_path}MasterinputConf.ini'
    Usertemplatefile = f'{Relative_path}INItemplate.ini'
    waveliteanswertemplate = f'{Relative_path}answertemplate.ans'
    Inventoryfile = f'{Relative_path}inventory'
    RInventoryfile = f'{Relative_path}rhelidminventory'
    EInventoryfile = f'{Relative_path}emsinventory'
    pocdatfile = f'{Relative_path}images.dat'
    nnidatfile = f'{Relative_path}nniimages.dat'
    ALLVMiptxt = f'{Relative_path}ALLEMSVM.txt'
    SITE1 = 'SITE1'
    SITE2 = 'SITE2'
    # CLUSTERIDDICT = {'PRIMARY' : 1, 'GEO' : 2, 'SECONDARY' : 1}
    hostext={'POC':'poc','NNI':'gw'}
    # IDAP_LIGHT_CARDS = {0: ['IDAPElasticsrch', 'IDAPHadoop','IDAPWebService', 'IDAPDshboard', 'IDAPLanding'],
    #                 1: ['IDAPElasticsrch', 'IDAPLanding','IDAPWebService', 'IDAPDshboard']}
    exclude_cards = {"FieldUtils", "FieldUtilCouchDB", "F5", "EMS", "EMSNNI"}
    clustevar={SITE1 : 1, SITE2 : 2}
    POC_RHELIDM_FILE = f'{Relative_path}RHELIDMMCVSParms.txt'
    NNIGW_RHELIDM_FILE = f'{Relative_path}NNIGWRHELIDMMCVSParms.txt'

    LICENSE_FILE_USER = "autoinstall"
    LICENSE_FILE_GROUP = "kodiakgroup"
    logfile = 'CreateEMSInventory.log'
    required_files = [Usertemplatefile, waveliteanswertemplate]


def check_required_files(systemtype, logger):
    logger.info("Checking for required user input files and templates.")
    for file in Constants.required_files:
        if not os.path.isfile(file):
            logger.error(f"User Input File ::{file} doesn't exist. Please check and retry")
            sys.exit(1)
            
    logger.info("All required user input files and templates are present.")

def setup_logging():
    logging.basicConfig(
        filename=Constants.logfile,
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)


############# Creating a Dict with the List of Cards per Site with NNIGW RHELIDM #############
# def CreateContainerHash():
#     if SETUPTYPE.lower() == 'wavelite':
#         if SYSTEMTYPE.lower() == 'poc_nnigw':
#             if DEPLOYMENTTYPE == '2':
#                 ipmap = {'PRIMARY': {'EMS': '', 'EMSNNI': ''},'GEO' : {'EMS': '', 'EMSNNI': ''}}
#         #Tocheck why poc and nnigw separately if wavelite
#         if SYSTEMTYPE.lower() == 'poc':
#             if DEPLOYMENTTYPE == '2':
#                 ipmap = {'PRIMARY': {'EMS': ''},'GEO' : {'EMS': ''}}
#         if SYSTEMTYPE.lower() == 'nnigw':
#             if DEPLOYMENTTYPE == '2':
#                 ipmap = {'PRIMARY': {'EMSNNI': ''},'GEO' : {'EMSNNI': ''}}
                
#     else:
#         if SYSTEMTYPE.lower() == 'poc':
#             if DEPLOYMENTTYPE == '2':
#                 ipmap = {'PRIMARY': {'EMS': ''},'GEO' : {'EMS': ''}}
#             elif DEPLOYMENTTYPE == '1':
#                 ipmap = {'PRIMARY': {'EMS': ''},'SECONDARY': {'EMS': ''},'GEO' : {'EMS': ''}}
#             elif DEPLOYMENTTYPE == '4':
#                 ipmap = {'PRIMARY': {'EMS': ''},'SECONDARY': {'EMS': ''}}
#         if SYSTEMTYPE.lower() == 'nnigw':
#             if DEPLOYMENTTYPE == '2':
#                 ipmap = {'PRIMARY': {'EMSNNI': ''},'GEO' : {'EMSNNI': ''}}
#             elif DEPLOYMENTTYPE == '1':
#                 ipmap = {'PRIMARY': {'EMSNNI': ''},'SECONDARY': {},'GEO' : {'EMSNNI': ''}}
#             elif DEPLOYMENTTYPE == '4':
#                 ipmap = {'PRIMARY': {'EMSNNI': ''},'SECONDARY': {}}
#         if SYSTEMTYPE.lower() == 'poc_nnigw':
#             if DEPLOYMENTTYPE == '2':
#                 ipmap = {'PRIMARY': {'EMS': '', 'EMSNNI': ''},'GEO' : {'EMS': '', 'EMSNNI': ''}}
#             elif DEPLOYMENTTYPE == '3':
#                ipmap = {'PRIMARY': {'EMS': '', 'EMSNNI': ''}}
#             elif DEPLOYMENTTYPE == '1':
#                 ipmap = {'PRIMARY': {'EMS': '', 'EMSNNI': ''},'SECONDARY': {'EMS': ''},'GEO' : {'EMS': '', 'EMSNNI': ''}}
#             elif DEPLOYMENTTYPE == '4':
#                 ipmap = {'PRIMARY': {'EMS': '', 'EMSNNI': ''},'SECONDARY': {'EMS': ''}}

#     return ipmap


def CreateEMSIPHash():
    if SETUPTYPE.lower() == 'wavelite':
        if SYSTEMTYPE.lower() == 'poc_nnigw':
            if DEPLOYMENTTYPE == '2':
                ipmap = {'SITE1': {'EMSPRI': '', 'EMSNNIPRI': ''},'SITE2' : {'EMSGEO': '', 'EMSGEONNI': ''}}
            # elif DEPLOYMENTTYPE == '3':
            #     ipmap = {'SITE1': {'EMS': '', 'EMSNNI': ''}}

    else:
        if SYSTEMTYPE.lower() == 'poc':
            if DEPLOYMENTTYPE == '2':
                ipmap = {'SITE1': {'EMSPRI': ''},'SITE2' : {'EMSGEO': ''}}
            # elif DEPLOYMENTTYPE == '3':
            #    ipmap = {'SITE1': {'EMS': ''}}
            elif DEPLOYMENTTYPE == '1':
                ipmap = {'SITE1': {'EMSPRI': '', 'EMSSEC': ''}, 'SITE2' : {'EMSGEO': ''}}
            # elif DEPLOYMENTTYPE == '4':
            #     ipmap = {'SITE1': {'EMS': '','EMSSEC': ''}}
        if SYSTEMTYPE.lower() == 'nnigw':
            if DEPLOYMENTTYPE == '2':
                ipmap = {'SITE1': {'EMSNNIPRI': ''},'SITE2' : {'EMSNNIGEO': ''}}
            # elif DEPLOYMENTTYPE == '3':
            #    ipmap = {'SITE1': {'EMSNNI': ''}}
            # elif DEPLOYMENTTYPE == '1':
            #     ipmap = {'SITE1': {'EMSNNI': '',},'SECONDARY': {},'GEO' : {'EMSNNI': ''}}
            # elif DEPLOYMENTTYPE == '4':
            #     ipmap = {'PRIMARY': {'EMSNNI': ''},'SECONDARY': {}}
        if SYSTEMTYPE.lower() == 'poc_nnigw':
            if DEPLOYMENTTYPE == '2':
                ipmap = {'SITE1': {'EMSPRI': '', 'EMSNNIPRI': ''},'SITE2' : {'EMSGEO': '', 'EMSNNIGEO': ''}}
            # elif DEPLOYMENTTYPE == '3':
            #    ipmap = {'SITE1': {'EMS': '', 'EMSNNI': ''}}
            elif DEPLOYMENTTYPE == '1':
                ipmap = {'SITE1': {'EMSPRI': '', 'EMSNNIPRI': '', 'EMSSEC': ''}, 'SITE2' : {'EMSGEO': '', 'EMSNNIGEO': ''}}
            # elif DEPLOYMENTTYPE == '4':
            #     ipmap = {'PRIMARY': {'EMS': '', 'EMSNNI': ''},'SECONDARY': {'EMS': ''}}

    return ipmap


def ReadImageDatfile(datfile):
    logger.info("Reading Image dat file::{} to fetch Image name.format(datfile)")
    MyImagelist = {}
    with open(datfile) as f:
        datafile = f.readlines()
        for line in datafile:
            if not line.isspace():
                newline = line.strip().split("-")
                servicetype = newline[0].split(":")
                if servicetype[0] == "EMS" or servicetype[0] == "RHELIDM":
                    MyImagelist[servicetype[0]] = newline[1]

    return MyImagelist


def CreateInventoryGroups(ems_inventory: CreateInventory, system_type, logger):
    logger.info("----------------- Calling CreateInventoryGroups() ------------------")
    # mydict = {}
    # i = 1
    # replica_list,poc_list,master_list,nni_list = [],[],[],[]
    # if 'ipaserver1' in myinventoryhash['PRIMARY'].keys() and 'NNI' not in myinventoryhash['PRIMARY'].keys():
    #     master_list.append('ipaserver1')

    # if 'NNIipaserver1' in myinventoryhash['PRIMARY'].keys() and COMMONPLATFLAG == 'no':
    #     master_list.append('NNIipaserver1')

    # mydict[i] =  { 'master' : master_list}
    # i+=1

    # for eachvalue in myinventoryhash:
    #     for servertype in myinventoryhash[eachvalue]:
    #         if 'ipaserver' in servertype and 'NNI' not in servertype:
    #             if servertype != 'ipaserver1':
    #                 replica_list.append(servertype)

    #         if 'NNIipaserver' in servertype and COMMONPLATFLAG == 'no':
    #             if servertype != 'NNIipaserver1':
    #                 replica_list.append(servertype)

    #         if servertype == 'EMSNNI':
    #             nni_list.append(servertype.lower()+eachvalue.lower())
    #         if servertype == 'EMS':
    #             poc_list.append(servertype.lower()+eachvalue.lower())

    # if len(replica_list) != 0:
    #     mydict[i] = {'replica' : replica_list}
    #     i+=1
    # if len(poc_list) != 0:
    #     mydict[i] = {'poc' : poc_list}
    #     i+=1
    # if len(nni_list) != 0:
    #     mydict[i] = { 'nni' : nni_list}

    # try:
    #     with open(Constants.Inventoryfile, "w") as file1, open(Constants.RInventoryfile, "w") as file2, open(Constants.EInventoryfile, "w") as file3:
    #         sorted_dict = OrderedDict(mydict)
    #         for i in sorted_dict:
    #             for k in sorted_dict[i]:
    #                 if k in ['master','replica']: file2.writelines("["+k+"]"+'\n')
    #                 if k in  ['poc','nni']: file3.writelines("["+k+"]"+'\n')
    #                 file1.writelines("["+k+"]"+'\n')
    #                 for j in sorted_dict[i][k]:
    #                     if k in ['master','replica']: file2.writelines(j+'\n')
    #                     if k in  ['poc','nni']: file3.writelines(j+'\n')
    #                     file1.writelines(j+'\n')
    #                 file1.write('\n')
    #                 file2.write('\n')
    #                 file3.write('\n')
    #         file1.write("[all:vars]\nansible_ssh_extra_args='-o StrictHostKeyChecking=no'\n")
    #         file2.write("[all:vars]\nansible_ssh_extra_args='-o StrictHostKeyChecking=no'\n")
    #         file3.write("[all:vars]\nansible_ssh_extra_args='-o StrictHostKeyChecking=no'\n")

    #     logger.info("Successfuly created Inventory file :;{}".format(Constants.Inventoryfile))\
    try:
        if 'poc' in system_type.lower():
            ems_inventory.create_group(Constants.EMSInvNAME, Constants.POCGROUPNAME)

        if 'nnigw' in system_type.lower():
            ems_inventory.create_group(Constants.EMSInvNAME, Constants.NNIGROUPNAME)
        
    except Exception as e:
        logger.error("Failed to Create Inventory Groups")
        logger.error(str(e))
        print(str(e))
        sys.exit(1)
    logger.info("------------------ END of  CreateInventoryGroups() ------------------")
    

def AssignOAMPlaneIP(ipmap):
    # Assign OAM IP for all the cards in ipmap which are not allocated IP
    logger.info("------------------ Calling AssignIp() ------------------")
    for site in ipmap:
        newsgip = ''
        oamip = FreshLaunchInvVars.get(site).get('OAMPLANE_MGMT_NW').strip()
        myip1 = oamip
        mylist = []
        # for card in ipmap[site]:
        #     if 'ipaserver' in card:
        #         ipalist.append(card)

        #Interchange NNIipaserver2 and NNIipaserver1 index position in ipalist if NNIipaserver2 comes first
        # if  SETUPTYPE.lower() == 'wavelite' and 'NNIipaserver2' in ipalist and 'NNIipaserver1' in ipalist:
        #     k, j = ipalist.index('NNIipaserver1'), ipalist.index('NNIipaserver2')
        #     if j < k:
        #         ipalist[k], ipalist[j] = ipalist[j], ipalist[k]

        if FreshLaunchInvVars.get(site).get('FIXEDIP_SERVICETYPE_MAP') != '':
            logger.info("FIXEDIP_SERVICETYPE_MAP value from Input file is ::{}".format(FreshLaunchInvVars.get(site).get('FIXEDIP_SERVICETYPE_MAP')))
            ipaddress = FreshLaunchInvVars.get(site).get('FIXEDIP_SERVICETYPE_MAP').split(';')
            mylist = []
            for val in ipaddress:
                myfinalval = val.split(':')

                if myfinalval[0] == 'RHELIDM' or myfinalval[0] == 'NNIRHELIDM':
                    mylist.extend(myfinalval[1].split(','))
                    newsgip = mylist[-1]
                else:
                    ipmap[site][myfinalval[0]] = str(myfinalval[1])
                    newsgip = myfinalval[1]

        # if len(ipalist) != 0:
        #     for ip in range(0,len(mylist)):
        #         ipmap[site].update({ ipalist[ip] : str(mylist[ip]) })

        for card in ipmap[site]:
            if ipmap[site][card] == '':
                logger.info("Fixed IP is not allocated for {}. Hence assinging IP from OAMPLane Ip".format(card))
                ipmap[site][card] = str(myip1)
                myip1 = newipaddress.ip_address(myip1) + 1
                newsgip = myip1

        mylistmap[site].update({ 'oamplaneip' : str(newsgip) })

    logger.info("------------------ End Of AssignIp() ------------------")
    return ipmap


def ReadTemplate(filename):
    logger.info("------------------ Calling ReadTemplate() ------------------")
    logger.info ("Reading Template File ::{}".format(filename))
    list_array = []
    try:
        f = open(filename, 'r')
        Lines = f.readlines()
        for line in Lines:
            if not line.isspace():
                list_array.append(line.strip())
        f.close()
        return list_array
    except Exception as e:
        logger.error("Failed to read Template file ::{}".format(filename))
        logger.error(str(e))
        print(str(e))
        sys.exit(1)
        
        
###################### Create Interface Value and List  ###########################
def Createinterface(site):
    logger.info("------------------ Calling Createinterface() ------------------")
    logger.info("Creating InterfaceList based on User Input File")
    if SETUPTYPE.lower() == 'wavelite':
        if FreshLaunchInvVars.get(site).get('OAMPLANE_MGMT_BRIDGE') != '':
            interfacevalue = 'eth1#'+FreshLaunchInvVars.get(site).get('OAMPLANE_MGMT_BRIDGE')
            interfacelist = 'eth1'
    else:
        if FreshLaunchInvVars.get(site).get('OAMPLANE_MGMT_BRIDGE') != '':
            interfacevalue = 'eth1#'+FreshLaunchInvVars.get(site).get('OAMPLANE_MGMT_BRIDGE')
            interfacelist = 'eth1'
        if FreshLaunchInvVars.get(site).get('SERVICEPLANE_MGMT_BRIDGE') != '':
            logger.info("SERVICEPLANE_MGMT_BRIDGE Value is configured in User file. Adding to Interfacelist")
            interfacelist = interfacelist+',eth2'
            interfacevalue = interfacevalue+'\n'+'interface'+'='+'eth2#'+FreshLaunchInvVars.get(site).get('SERVICEPLANE_MGMT_BRIDGE')
        if FreshLaunchInvVars.get(site).get('REMOTELOGPLANE_MGMT_BRIDGE') != '':
            logger.info("REMOTELOGPLANE_MGMT_BRIDGE Value is configured in User file. Adding to Interfacelist")
            interfacelist = interfacelist+',eth3'
            interfacevalue = interfacevalue+'\n'+'interface'+'='+'eth3#'+FreshLaunchInvVars.get(site).get('REMOTELOGPLANE_MGMT_BRIDGE')
        if FreshLaunchInvVars.get(site).get('RXPLANE_MGMT_BRIDGE') != '':
            logger.info("RXPLANE_MGMT_BRIDGE Value is configured in User file. Adding to Interfacelist")
            interfacelist = interfacelist+',eth4'
            interfacevalue = interfacevalue+'\n'+'interface'+'='+'eth4#'+FreshLaunchInvVars.get(site).get('RXPLANE_MGMT_BRIDGE')
    interfacevlaues = { 'interfacevalue' : interfacevalue , 'interfacelist' : interfacelist}

    logger.info("Interface values Created are:: interfacelist :: {}".format(interfacevlaues))
    logger.info("------------------ End of Createinterface() ------------------")
    return interfacevlaues


def Createroute(site,card):

    logger.info("--------------------- Calling Createroute() ---------------------------")
    logger.info("Creating route based on User Input File")

    if 'NNI' in card:
        routevar='NNIGW_ROUTE'
    else:
        routevar='POC_ROUTE'
    newarr = FreshLaunchInvVars.get(site).get(routevar).split(' ')
    newvalue=''
    for i in newarr:
        if i == '':
            continue
        routearr = i.split('#')
        if newvalue == '':
            newvalue = routearr[2]+'#'+routearr[0]+'@'+routearr[1]
        else:
            newvalue = newvalue+'\n'+'route'+'='+routearr[2]+'#'+routearr[0]+'@'+routearr[1]

    routevalue=newvalue
    logger.info("Route values Created are :: {}".format(routevalue))
    logger.info("--------------------------- End of Createroute() ----------------------")
    return routevalue

def CreatePlaneIp(serviceplane):
    logger.info("------------------ Calling CreateplaneIp() ------------------")
    logger.info("Creating IP Map for Plane :: {} ".format(serviceplane))
    # if COMMONPLATFLAG == 'yes':
    #     myhash = CreateContainerHash()
    # else:
    ems_map = CreateEMSIPHash()

    for site in ems_map:
        serviceip = FreshLaunchInvVars.get(site).get(serviceplane).strip()
        serviceip1 = serviceip
        newserviceip = ''
        if serviceip1 != '':
            for card in ems_map[site]:
                ems_map[site][card] = str(serviceip1)
                serviceip1 = newipaddress.ip_address(serviceip1) + 1
                newserviceip = newipaddress.ip_address(serviceip1) + 1
        mylistmap[site].update({ serviceplane : str(serviceip1) })
    logger.info("Created IP Map for Plane :: {} and the values are :: {}".format(serviceplane,ems_map))
    return ems_map


def CreateIpaddress(site,sgid,card):
    logger.info("------------------ Calling CreateIpaddress() ------------------")
    mysubnet = FreshLaunchInvVars.get(site).get('OAMPLANE_SUBNET').split('/')
    ipaddrvalue = 'eth1#'+sgid+'/'+mysubnet[1]

    if SETUPTYPE.lower() != 'wavelite':
        if serviceplane[site][card] != '':
            mysubnet = FreshLaunchInvVars.get(site).get('SERVICEPLANE_SUBNET').split('/')
            ipaddrvalue = ipaddrvalue+'\n'+'ipaddr'+'='+'eth2#'+serviceplane[site][card]+'/'+mysubnet[1]+'@'+FreshLaunchInvVars.get(site).get('SERVICEPLANE_GATEWAY')
        if remoteplane[site][card] != '':
            mysubnet = FreshLaunchInvVars.get(site).get('REMOTELOGPLANE_SUBNET').split('/')
            ipaddrvalue = ipaddrvalue+'\n'+'ipaddr'+'='+'eth3#'+remoteplane[site][card]+'/'+mysubnet[1]
        if rxplane[site][card] != '':
            mysubnet = FreshLaunchInvVars.get(site).get('RXPLANE_SUBNET').split('/')
            ipaddrvalue = ipaddrvalue+'\n'+'ipaddr'+'='+'eth4#'+rxplane[site][card]+'/'+mysubnet[1]
    return ipaddrvalue



################ Create Details For RHELIDM Yaml ##############################
# def CreateRhelidmYml(site,pttid,image,host,sgip,filename):
#     if DEPLOYMENT_PLATFORM_TYPE != 5 and 'NNI' in filename:
#         host = 'NNI' + host
#     ymlint = []
#     rhelidmlist1 = {'name' : QuotedString('RHELIDM'),'sigcardid':'127','dgid':pttid[2:5],'version': '1.0','image':QuotedString(image),'host': QuotedString(host),'pttid':pttid, 'interface' : []}

#     ymlinterface = {"interface":"eth1", "ip": sgip,"gateway": config.get(site,'OAMPLANE_GATEWAY'), "broadcast": config.get(site,'OAMPLANE_BROADCASTIP'), 'netmask': config.get('GLOBAL','NETMASKIP'), "subnet_type": "oam","ip_type":"phy"}
#     ymlint.append(ymlinterface)

#     if serviceplane[site][filename] != '':
#         ymlinterface = {"interface":"eth2", "ip": serviceplane[site][filename],"gateway": config.get(site,'SERVICEPLANE_GATEWAY'), "broadcast": config.get(site,'SERVICEPLANE_BROADCASTIP'), 'netmask': config.get('GLOBAL','NETMASKIP'), "subnet_type": "service","ip_type":"phy"}
#         ymlint.append(ymlinterface)
#     else:
#         ymlinterface = {"interface":"eth1", "ip": sgip,"gateway": config.get(site,'OAMPLANE_GATEWAY'),"broadcast":config.get(site,'OAMPLANE_BROADCASTIP'), 'netmask': config.get('GLOBAL','NETMASKIP'), "subnet_type": "service","ip_type":"phy"}
#         ymlint.append(ymlinterface)

#     if remoteplane[site][filename] != '':
#         ymlinterface = {"interface":"eth3", "ip": remoteplane[site][filename],"gateway": config.get(site,'REMOTELOGPLANE_GATEWAY'),"broadcast":config.get(site,'REMOTELOGPLANE_BROADCASTIP'), 'netmask': config.get('GLOBAL','NETMASKIP'), "subnet_type": "log","ip_type":"phy"}
#         ymlint.append(ymlinterface)
#     else:
#         ymlinterface = {"interface":"eth1", "ip": sgip,"gateway": config.get(site,'OAMPLANE_GATEWAY'),"broadcast":config.get(site,'OAMPLANE_BROADCASTIP'), 'netmask': config.get('GLOBAL','NETMASKIP'), "subnet_type": "log","ip_type":"phy"}
#         ymlint.append(ymlinterface)

#     if rxplane[site][filename] != '':
#         ymlinterface = {"interface":"eth3", "ip": rxplane[site][filename],"gateway": config.get(site,'RXPLANE_GATEWAY'),"broadcast":config.get(site,'RXPLANE_BROADCASTIP'), 'netmask': config.get('GLOBAL','NETMASKIP'), "subnet_type": "rx","ip_type":"phy"}
#         ymlint.append(ymlinterface)

#     if site == 'PRIMARY':
#         rhelidmlist1['interface'] = ymlint
#         prirhelidmlist.append(rhelidmlist1)
#         rhelidmjson1.update({site : prirhelidmlist})
#     if site == 'SECONDARY':
#         rhelidmlist1['interface'] = ymlint
#         secrhelidmlist.append(rhelidmlist1)
#         rhelidmjson1.update({site : secrhelidmlist})
#     if site == 'GEO':
#         rhelidmlist1['interface'] = ymlint
#         georhelidmlist.append(rhelidmlist1)
#         rhelidmjson1.update({site : georhelidmlist})
        
        
        
################ Creating Host Var File ####################################
def CreateHostVarFile(servertype, image, host, containerip, pttid):
    logger.info("------------------ Calling CreateHostVarFile() ------------------")
    
    tag = image.split(":")[1]
    docker_registry = FreshLaunchInvVars.get('GLOBAL').get('DOCKER_REGISTRY')

    # if "ipaserver" in servertype:
    #     if "ipaserver1" in servertype:
    #         IS_MASTER = '1'
    #     else:
    #         IS_MASTER = '0'

    #     if DEPLOYMENT_PLATFORM_TYPE == 5:
    #         if 'NNIipa' in servertype:
    #             newservertype = Constants.hostext['NNI']+servertype[3:]
    #         else:
    #             newservertype = Constants.hostext['POC']+servertype
    #     else:
    #         newservertype = servertype

    #     newhost=newservertype.lstrip('NNI')
    #     servertypelist = { 'INIFILE' : '/Software/ProdApplicationInfra/conf/'+servertype+'.ini' ,'CONTAINERNAME' : 'PROJ-'+newhost+'.'+INTERNAL_HOST_DOMAIN+'-'+pttid+'-'+tag,'ansible_ssh_host' : host ,'CONTAINERIP' : containerip,'IS_MASTER' : IS_MASTER, 'DOCKERREGISTRY': docker_registry, 'IMAGE': image }
        
    #     logger.info("Content of Host_var file for {} is {}".format(servertype,servertypelist))
    # else:
    servertypelist = { 'INIFILE' : servertype+'.ini', 'ANS' : Ansfile, 'CONTAINERNAME' : 'PROJ-'+servertype+'-'+pttid+'-'+tag,'ansible_ssh_host' : host,'CONTAINERIP':containerip,'INSTALLATIONTYPE': int(InstallationType), 'DOCKERREGISTRY': docker_registry, 'IMAGE': image }
    logger.info("Content of Host_var file for {} is {}".format(servertype,servertypelist))
    
        
    return servertypelist
    # try:
    #     with open('/Software/ProdApplicationInfra/playbooks/host_vars/'+servertype, "w") as file1:
    #         for i in servertypelist:
    #             file1.writelines(i+' : '+servertypelist[i]+'\n')
    # except Exception as e:
    #     logger.error("Failed to create host_var file {}".format(servertype))
    #     logger.error(str(e))
    #     print(str(e))
    #     sys.exit(1)
        

def WriteOutFile(filename,list_array):
    logger.info("------------------ Calling WriteOutFile() ------------------")
    try:
        logger.info ("Writing Output to File ::{}".format(filename))
        with open(filename, "w") as myfile:
            for line in list_array:
                myfile.write(line+'\n')
        logger.info("Successfuly created file :{}".format(filename))
    except Exception as e:
        logger.error("Failed to write to file ::{}".format(filename))
        logger.error(str(e))
        #logger.closelog()
        sys.exit(1)
        

def convert_listarray_to_json(list_array, logger):
    """
    Convert a list array configuration to JSON format.

    Args:
        list_array: List containing configuration key-value pairs
        logger: Logger instance for logging

    Returns:
        dict: JSON representation of the configuration
    """
    logger.info("Converting list array to JSON format")

    special_keys = ['interface', 'ipaddr', 'route']

    json_data = {}

    try:
        for item in list_array:
            if '=' in item:
                # Split only on the first '=' to handle values that contain '='
                key, value = item.split('=', 1)
                if key in special_keys:
                    value_list = []
                    for each_value in item.split('\n'):
                        if each_value.startswith(f"{key}="):
                            value_list.append(each_value.split('=', 1)[1])

                    json_data[key] = value_list
                else:
                    # Try to parse JSON strings
                    if value.startswith('[') and value.endswith(']'):
                        try:
                            json_data[key] = json.loads(value)
                        except json.JSONDecodeError:
                            json_data[key] = value
                    else:
                        json_data[key] = value

        container_ini_vars = {'INI_FILE_DATA': json_data}
        print(f"json data --> {container_ini_vars}")

        logger.info(f"Successfully converted list array to JSON: {json_data}")
        return container_ini_vars

    except Exception as e:
        logger.error(f"Failed to convert list array to JSON: {str(e)}")
        return {}


################ Creating Container INI File ##############
def CreateContainerINI(site,Servertype,filename,host,sgip,pttid,image,ptttype):
    logger.info("------------------ Calling CreateContainerINI() ------------------")

    if 'EMS'in Servertype:
        servertype = 'ConfigMgmt Server'
        host = filename
    else:
        servertype = Servertype

    interfaceval = Createinterface(site)

    if SETUPTYPE.lower() != 'wavelite':
        route = Createroute(site,Servertype)

    if 'RHELIDM' in Servertype:
        host = host
        ipaddrval = CreateIpaddress(site,sgip,filename)
    else:
        ipaddrval = CreateIpaddress(site,sgip,Servertype)


    CHASSISID=''
    CHASSIS_HOSTNAME=''

    if ptttype == '1':
        for chid in VM_CHASSIS[site].keys():
            if 'EMSPRI' in VM_CHASSIS[site][chid]['CARDS'] or 'EMSSEC' in VM_CHASSIS[site][chid]['CARDS'] or 'EMSGEO' in VM_CHASSIS[site][chid]['CARDS']:
                logger.info("Servertype :: {}, SITE :: {} is present in CHASSISID :: {}".format(Servertype,site,chid))
                CHASSISID=chid
                CHASSIS_HOSTNAME = 'VM_CHASSIS_'+str(CHASSISID)+'_OAMVMIP'
                break
            
    if ptttype == '2':
        for chid in NNIGW_VM_CHASSIS[site].keys():
            if 'EMSNNIPRI' in NNIGW_VM_CHASSIS[site][chid]['CARDS'] or 'EMSNNIGEO' in NNIGW_VM_CHASSIS[site][chid]['CARDS']:
                logger.info("Servertype :: {}, SITE :: {} is present in CHASSISID :: {}".format(Servertype,site,chid))
                CHASSISID=chid
                CHASSIS_HOSTNAME = 'NNIGW_VM_CHASSIS_'+str(CHASSISID)+'_OAMVMIP'
                break


    # ipachassisid = []
    # if Servertype == 'RHELIDM':
    #     for chid in VM_CHASSIS[site].keys():
    #         if Servertype in VM_CHASSIS[site][chid]['CARDS']:
    #             ipachassisid.append(chid)

    #     if filename in ['ipaserver1','ipaserver3']:
    #         CHASSISID=min(ipachassisid)
    #     else:
    #         CHASSISID=max(ipachassisid)


    #     CHASSIS_HOSTNAME = 'VM_CHASSIS_'+str(CHASSISID)+'_OAMVMIP'

    #     if DEPLOYMENT_PLATFORM_TYPE == 5:
    #         IPASERVERCHASSIS[Constants.hostext['POC']+filename]=CHASSISID
    #     else:
    #         IPASERVERCHASSIS[filename]=CHASSISID

    # ipachassisid = []
    # if Servertype == 'NNIRHELIDM':
    #     for chid in NNIGW_VM_CHASSIS[site].keys():
    #         if Servertype in NNIGW_VM_CHASSIS[site][chid]['CARDS']:
    #             ipachassisid.append(chid)

    #     if filename in ['NNIipaserver1','NNIipaserver3']:
    #         CHASSISID=min(ipachassisid)
    #     else:
    #         CHASSISID=max(ipachassisid)

    #     CHASSIS_HOSTNAME = 'NNIGW_VM_CHASSIS_'+str(CHASSISID)+'_OAMVMIP'

    #     if DEPLOYMENT_PLATFORM_TYPE == 5:
    #         NNIIPASERVERCHASSIS[Constants.hostext['NNI']+filename.lstrip('NNI')]=CHASSISID
    #     else:
    #         NNIIPASERVERCHASSIS[filename] = CHASSISID

    #TODO: need to fetch this from RhelIDM Inventory
    rhelidminstance = [{"IP": "10.2.13.14", "Host": "ipaserver1.msidm.com", "IS_SERVER_NODE": 1}, {"IP": "10.2.13.15", "Host": "ipaserver2.msidm.com", "IS_SERVER_NODE": 0}, {"IP": "10.2.13.67", "Host": "ipaserver3.msidm.com", "IS_SERVER_NODE": 0}, {"IP": "10.2.13.68", "Host": "ipaserver4.msidm.com", "IS_SERVER_NODE": 0}]

    if COMMONPLATFLAG == 'no' and ptttype == '2':
        rhelidminstance = NNIrhelidminstance

    if DEPLOYMENT_PLATFORM_TYPE == 5:
        if 'NNIipa' in host:
            newhost = Constants.hostext['NNI'] + host[3:]
        elif 'ipa' in host:
            newhost = Constants.hostext['POC'] + host
        else:
            newhost=host
        newhost=newhost.lstrip('NNI')
    else:
        newhost=host.lstrip('NNI')
        
    inilist = {'DEPLOYMENT_REDUNDANCY_TYPE':FreshLaunchInvVars['GLOBAL']['DEPLOYMENT_REDUNDANCY_TYPE'],'INTERNAL_HOST_DOMAIN':FreshLaunchInvVars['GLOBAL']['INTERNAL_HOST_DOMAIN'],'image': image,'SERVERTYPE': servertype,'host':newhost,'pttsvrid':pttid,'ipaddr': ipaddrval,'interface' :interfaceval['interfacevalue'],'SIGNALINGCARDIP':sgip,'HOSTIP': FreshLaunchInvVars[site][CHASSIS_HOSTNAME], 'RHELIDM_INSTANCE_INFO': json.dumps(rhelidminstance,separators=(',', ':'))}
    if SETUPTYPE.lower() != 'wavelite':
        inilist['route'] = route

    logger.info("List Formed with Replaced Values in template are ::{}".format(inilist))
    list_array = ReadTemplate(Constants.Usertemplatefile)
    # if "ipaserver" in filename:
    #     CreateRhelidmYml(site,pttid,image,inilist['host'],sgip,filename)
    #     if "ipaserver1" in filename:
    #         list_array.append('IS_SERVER_NODE=1')
    #     else:
    #         list_array.append('IS_SERVER_NODE=0')

    if ptttype == '1':
        POCVMEMSLIST.append(FreshLaunchInvVars[site][CHASSIS_HOSTNAME])
        POCPRIEMSVM.append(FreshLaunchInvVars[Constants.SITE1][CHASSIS_HOSTNAME])
        # if inilist['HOSTIP'] not in emshosts and AUTOMATE_DOCKER_PULL == 'yes':
        #     imagefile = f"{Constants.Relative_path}"+filename+".dat"
        #     with open(imagefile, "w") as f:
        #         f.write(f"EMS:0-{image}\n")
        #     emshosts.append(inilist['HOSTIP'])
        # else:
        #     imagefile = "empty"
            
    if ptttype == '2':
        NNIVMEMSLIST.append(FreshLaunchInvVars[site][CHASSIS_HOSTNAME])
        GWPRIEMSVM.append(FreshLaunchInvVars[Constants.SITE1][CHASSIS_HOSTNAME])
        # if AUTOMATE_DOCKER_PULL == 'yes':
        #     imagefile = f"{Constants.Relative_path}"+filename+".dat"
        #     with open(imagefile, "w") as f:
        #         f.write(f"EMS:0-{image}\n")
        # else:
        #     imagefile = "empty"
            
    # if 'RHELIDM' in Servertype:
    #     if inilist['HOSTIP'] not in ipahosts and AUTOMATE_DOCKER_PULL == 'yes':
    #         imagefile = f"{Constants.Relative_path}"+filename+".dat"
    #         with open(imagefile, "w") as f:
    #             f.write(f"RHELIDM:127-{image}\n")
    #         ipahosts.append(inilist['HOSTIP'])
    #     else:
    #         imagefile = "empty"

    for param in inilist.keys():
        index = list_array.index(param+'=##'+param+'##')
        list_array[index] = param+'='+str(inilist[param])

    if SETUPTYPE.lower() == 'wavelite':
        list_array.remove('route=##route##')
    WriteOutFile(f'{Constants.Relative_path}'+filename+'.ini',list_array)
    

    # Convert the list array to JSON format
    ini_vars = convert_listarray_to_json(list_array, logger)

    logger.info("Creating HostVar file For ::{}".format(filename))
    hostvars = CreateHostVarFile(filename, inilist['image'], inilist['HOSTIP'], inilist['SIGNALINGCARDIP'], pttid)

    # Combine ini_vars and hostvars into a single dictionary
    combined_vars = {**hostvars, **ini_vars}
    logger.info("Combined variables for {}: {}".format(filename, combined_vars))
    
    return combined_vars
    
    
def update_redundant_ems_ipaddress(site, myvalues, ipmapjson, mycard, emscardname, DEPLOYMENTTYPE):

    if DEPLOYMENTTYPE == '1':
        # Deployement type 1 is supported only for POC deployements
        if site == Constants.SITE1 and emscardname == 'EMSPRI':
            myvalues.append('GEOEMSIPADDRESS:' + ipmapjson[Constants.SITE2]['EMSGEO'])
            myvalues.append('SECONDARYEMSIPADDRESS:' + ipmapjson[Constants.SITE1]['EMSSEC'])
        elif site == Constants.SITE1 and emscardname == 'EMSSEC':
            myvalues.append('GEOEMSIPADDRESS:' + ipmapjson[Constants.SITE2]['EMSGEO'])
            myvalues.append('SECONDARYEMSIPADDRESS:' + ipmapjson[Constants.SITE1]['EMSPRI'])
        else:
            myvalues.append('GEOEMSIPADDRESS:' + ipmapjson[Constants.SITE1]['EMSPRI'])
            myvalues.append('SECONDARYEMSIPADDRESS:' + ipmapjson[Constants.SITE1]['EMSSEC'])

    elif DEPLOYMENTTYPE == '2':
        if site == Constants.SITE1 and emscardname == f'{mycard}PRI':
            myvalues.append('GEOEMSIPADDRESS:' + ipmapjson[Constants.SITE2][f'{mycard}GEO'])
        else:
            myvalues.append('GEOEMSIPADDRESS:' + ipmapjson[Constants.SITE1][f'{mycard}PRI'])



################ Creating EMS Answer Files #############################
def CreateAnswerFile(site,filename,pttsystemtype,installationtype,emscardname,signalingip):
    logger.info("------------------ Calling CreateAnswerFile() ------------------")
    logger.info("Creating Answer File {}".format(filename))
    myvalues = ReadTemplate(Constants.waveliteanswertemplate)
    myinterfacelist = Createinterface(site)
    aliasinterface,aliasipaddress,aliasbroadcast,aliasnetmask = '','','',''
    if pttsystemtype == '2':
        path = FreshLaunchInvVars['GLOBAL']['NNI_LICENSE_PATH']
        custname = FreshLaunchInvVars['GLOBAL']['NNI_LICENSECUSTOMERNAME']
        custpasswd = FreshLaunchInvVars['GLOBAL']['NNI_LICENSEKEYPASSWORD']
    if pttsystemtype == '1':
        path = FreshLaunchInvVars['GLOBAL']['POC_LICENSE_PATH']
        custname = FreshLaunchInvVars['GLOBAL']['POC_LICENSECUSTOMERNAME']
        custpasswd = FreshLaunchInvVars['GLOBAL']['POC_LICENSEKEYPASSWORD']
        
    if pttsystemtype == '2' and serviceplane[site][emscardname] != '':
        serviceplaneip = serviceplane[site][emscardname]
    elif pttsystemtype == '1' and serviceplane[site][emscardname] != '':
        serviceplaneip = serviceplane[site][emscardname]
    else:
        serviceplaneip = signalingip
        
    if DEPLOYMENTTYPE == '1' or DEPLOYMENTTYPE == '4':
        #aliasinterface = myinterfacelist['interfacelist']
        aliasinterface = 'eth1~1'
        #aliasipaddress = signalingip
        aliasipaddress = mylistmap[site]['oamplaneip']

        if site == Constants.SITE1 and emscardname == 'EMSPRI':
            newaliasip = newipaddress.ip_address(aliasipaddress) + 1
            mylistmap[site].update({ 'oamplaneip' : str(newaliasip) })

        aliasbroadcast = FreshLaunchInvVars[site]['OAMPLANE_BROADCASTIP']
        aliasnetmask = FreshLaunchInvVars['GLOBAL']['NETMASKIP']

        if site == Constants.SITE1 and (emscardname in ['EMSPRI','EMSNNIPRI']):
            ALIASIP['EMS'] = aliasipaddress

        if site == Constants.SITE1 and emscardname == 'EMSSEC':
            aliasipaddress = ALIASIP['EMS']
        elif (site == Constants.SITE2 and emscardname == 'EMSGEO') or pttsystemtype == '2':
            aliasipaddress = ''
            aliasinterface = ''
            aliasbroadcast = ''
            aliasnetmask = ''

    newdeployment = FreshLaunchInvVars['GLOBAL']['DEPLOYMENT_REDUNDANCY_TYPE']

    if pttsystemtype == '2' and newdeployment == '1':
        newdeployment = '2'

    anspttsystemtype = pttsystemtype
    if COMMONPLATFLAG == 'yes':
        if pttsystemtype == '1':
            anspttsystemtype = '3'
        elif pttsystemtype == '2':
            anspttsystemtype = '4'

    waveliteanslist = {'INSTALLATIONTYPE':installationtype ,'PTTSYSTEMTYPE':anspttsystemtype,'DEPLOYMENT_REDUNDANCY_TYPE':newdeployment,'EMSCHASSISNAME':filename+'_mgmt','CHASSISLOCATION':FreshLaunchInvVars['GLOBAL']['CHASSISLOCATION'],'CHASSISZIPCODE':FreshLaunchInvVars['GLOBAL']['CHASSISZIPCODE'],'CHASSISCITY':FreshLaunchInvVars['GLOBAL']['CHASSISCITY'],'CARRIERID':FreshLaunchInvVars['GLOBAL']['CARRIERID'],'COUNTRYCODE':FreshLaunchInvVars['GLOBAL']['COUNTRYCODE'],'EMSCARDNAME':emscardname,'LOCALEMSIPADDRESS': signalingip ,'CMMIPADDRESS': signalingip ,'POCINTERFACEIPADDRESS': signalingip ,'COMMUNICATIONINTERFACEIP': signalingip ,'SERVICEPLANEIPADDRESSES': serviceplaneip , 'DEPLOYMENTTYPE' : FreshLaunchInvVars['GLOBAL']['DEPLOYMENT_TYPE'], 'INTERFACELIST' : myinterfacelist['interfacelist'],'ALIASINTERFACE':aliasinterface, 'ALIASIPADDRESS': aliasipaddress,'ALIASBROADCASTIPADDRESS' : aliasbroadcast, 'ALIASNETMASK' : aliasnetmask,'LICENSEKEYLOCATION': path ,'LICENSECUSTOMERNAME': custname, 'LICENSEKEYPASSWORD': custpasswd, 'DEPLOYMENT_PLATFORM_TYPE': FreshLaunchInvVars['GLOBAL']['DEPLOYMENT_PLATFORM_TYPE'], 'INTERNAL_HOST_DOMAIN': FreshLaunchInvVars['GLOBAL']['INTERNAL_HOST_DOMAIN'],'PKI_ORGANISATION': FreshLaunchInvVars['GLOBAL']['INTERNAL_HOST_DOMAIN']}
    logger.info("Answer File Content after Replacing actual values in template is{}".format(waveliteanslist))
    if pttsystemtype == '2':
        mycard = 'EMSNNI'
        Nniiplist.append(signalingip)
        myvalues.append('DOCKERREGISTRYIPADDRESS:'+FreshLaunchInvVars['GLOBAL']['DOCKERREGISTRYIPADDRESS'])
        myvalues.append('DOCKERREGISTRYDOMAIN:'+FreshLaunchInvVars['GLOBAL']['DOCKERREGISTRYDOMAIN'])
        if COMMONPLATFLAG == 'yes':
            myvalues.append('CONSUL_AGENT_TOKEN:'+FreshLaunchInvVars['GLOBAL']['CONSUL_AGENT_TOKEN'])
            myvalues.append('CONSUL_LOCAL_SERVERS:'+FreshLaunchInvVars[site]['CONSUL_LOCAL_SERVERS'])
    else:
        mycard = 'EMS'
        Emsiplist.append(signalingip)

    update_redundant_ems_ipaddress(site, myvalues, ipmapjson, mycard, emscardname, DEPLOYMENTTYPE)
    
    for param in waveliteanslist.keys():
        index = myvalues.index(param+':'+'##'+param+'##')
        myvalues[index] = param+':'+str(waveliteanslist[param])
        
    # Convert myvalues list to key-value pairs
    logger.info("Converting myvalues list to key-value pairs for answer file: {}".format(filename))
    
    answer_vars = {}
    for item in myvalues:
        if ':' in item:
            # Split only on the first ':' to handle values that contain ':'
            key, value = item.split(':', 1)
            answer_vars.update({key: value})
    answer_vars = {'ANSWER_FILE_DATA': answer_vars}
    return answer_vars
    
    # WriteOutFile('/Software/ProdApplicationInfra/ans/'+filename+'.ans',myvalues)
    

def validate_license_file_checks(license_file_path):
    """
    checks the following things:
        the provided path is a valid file.
        the provided file path is not empty.
        the provided file path is given with correct user and group ownership. if not correct,
        log warning and update the correct one
    """
    if not os.path.isfile(license_file_path):
        logger.error("License file Path {} mentioned in Global section of master input file is not a file. Please check and update.".format(license_file_path))
        return False
    if not os.stat(license_file_path).st_size > 0:
        logger.error(
            "License file path {} mentioned in Global section of master input file is an empty file. Please check and update.".format(
                license_file_path))
        return False
    if not (getpwuid(os.stat(license_file_path).st_uid).pw_name == Constants.LICENSE_FILE_USER and getgrgid(os.stat(license_file_path).st_uid).gr_name == Constants.LICENSE_FILE_GROUP):
        logger.warning(
            "License file path {} mentioned in Global section of master input file does not have correct user and group assigned. updating user: {} and group: {}.".format(
                license_file_path, Constants.LICENSE_FILE_USER, Constants.LICENSE_FILE_GROUP))
        #updating the required ownership
        uid = getpwnam(Constants.LICENSE_FILE_USER).pw_uid
        gid = getgrnam(Constants.LICENSE_FILE_GROUP).gr_gid
        os.chown(license_file_path, uid, gid)
        return True
    return True

def validate_license_file():
    """
    This function checks if the user has specified a valid license file in valid license path
    """
    if SYSTEMTYPE.lower() == 'poc':
        return validate_license_file_checks(FreshLaunchInvVars['GLOBAL']['POC_LICENSE_PATH'])
    elif SYSTEMTYPE.lower() == 'nnigw':
        return validate_license_file_checks(FreshLaunchInvVars['GLOBAL']['NNI_LICENSE_PATH'])
    else:
        # if not the other two, then SYSTEMTYPE.lower() == 'poc_nnigw'
        return validate_license_file_checks(FreshLaunchInvVars['GLOBAL']['POC_LICENSE_PATH']) and validate_license_file_checks(FreshLaunchInvVars['GLOBAL']['NNI_LICENSE_PATH'])


# def validate_required_idap_cards(allcards: List[str], cluster: str, idap_light_flag: int):
#     try:
#         for idapcard in Constants.IDAP_LIGHT_CARDS[idap_light_flag]:
#             if idapcard not in allcards:
#               raise Exception(f'Card {idapcard} is not available in {cluster}. Required for INSTALL_IDAP_LIGHT = {idap_light_flag}.')

#         if idap_light_flag == 0:
#             if allcards.count('IDAPHadoop') != 2:
#                 raise Exception(f'Two IDAPHadoop Cards should be present. One for NameNode and One for DataNode')

#         elif idap_light_flag == 1:
#             if 'IDAPHadoop' in allcards:
#                 raise Exception(f'IDAPHadoop card should not be present when INSTALL_IDAP_LIGHT=1')

#     except Exception as e:
#         logger.error(e)
#         sys.exit(1)
        

def evaluate_idap_cards(system_type: str, cards: List[str], cluster, idap_light_flag):
    """
    checks if the required idap cards are available.
    throws exception if required idap cards are not available.
    """
    try:
        if system_type == 'poc':
            if IDAP_INSTALLED_FLAG_POC == 0:
                if 'idap' in " ".join(cards).lower():
                    raise Exception("idap cards should not be added when IDAP_INSTALLED_FLAG=0")
            else:
                if idap_light_flag == 1:
                    validate_required_idap_cards(cards, cluster,1)
                else:
                    validate_required_idap_cards(cards, cluster,0)
        elif system_type == 'nnigw':
            if IDAP_INSTALLED_FLAG_NNIGW == 0:
                if 'idap' in " ".join(cards).lower():
                    raise Exception("idap cards should not be added when IDAP_INSTALLED_FLAG=0")
            else:
                #for NNIGW INTALL_IDAP_LIGHT flag is always 1
                validate_required_idap_cards(cards, cluster, 1)

    except Exception as err:
        logger.error(err)
        sys.exit(1)
        
        
def VerifyMasterInputFile():
    '''
    This function to validate mandatory paramters are updated in MasterinputConf.ini file
    '''

    dictionary = {}
    # CardList = {}
    # NNIGWCardList ={}

    for section in config.sections():
        dictionary[section] = {}
        for option in config.options(section):
            option=option.upper()
            dictionary[section][option] = config.get(section, option)

    if 'nnigw' not in SYSTEMTYPE.lower():
        del dictionary['GLOBAL']['NNI_LICENSE_PATH']
        del dictionary['GLOBAL']['NNI_LICENSECUSTOMERNAME']
        del dictionary['GLOBAL']['NNI_LICENSEKEYPASSWORD']

    if 'poc' not in SYSTEMTYPE.lower():
        del dictionary['GLOBAL']['POC_LICENSE_PATH']
        del dictionary['GLOBAL']['POC_LICENSECUSTOMERNAME']
        del dictionary['GLOBAL']['POC_LICENSEKEYPASSWORD']
        del dictionary['GLOBAL']['NO_OF_POCINSTANCES']
        del dictionary['GLOBAL']['NO_OF_MEDIA_PER_POC']
        del dictionary['GLOBAL']['NO_OF_ALIAS_PER_MEDIA']

    if not validate_license_file():
        logger.error("License file Path mentioned in Global section of master input file is invalid. Please check and update.")
        # sys.exit(1)

    logger.info("License file Path is validated Successfully")
    if 'COMMON_PLATFORM_FLAG' not in dictionary['GLOBAL'].keys() or dictionary['GLOBAL']['COMMON_PLATFORM_FLAG'] == '':
        logger.error("GLOBAL Section in master input COMMON_PLATFORM_FLAG is not exists or empty. Please check and update  master input file")
        sys.exit(1)

    COMMONPLATFLAG = config.get('GLOBAL','COMMON_PLATFORM_FLAG').lower()
    if COMMONPLATFLAG == 'no' or 'poc' == SYSTEMTYPE.lower():
        if 'CONSUL_AGENT_TOKEN' in dictionary['GLOBAL'].keys(): del dictionary['GLOBAL']['CONSUL_AGENT_TOKEN']


    MandParams=['OAMPLANE_SUBNET','OAMPLANE_GATEWAY','OAMPLANE_BROADCASTIP','OAMPLANE_MGMT_BRIDGE','OAMPLANE_MGMT_NW']

    if COMMONPLATFLAG == 'yes' and 'nnigw' in SYSTEMTYPE.lower():
        MandParams.append('CONSUL_LOCAL_SERVERS')

    if SETUPTYPE.lower() == 'wavelite':
        MandParams.append('FIXEDIP_SERVICETYPE_MAP')
    else:
         MandParams.extend(['SERVICEPLANE_BROADCASTIP','SERVICEPLANE_MGMT_BRIDGE','SERVICEPLANE_MGMT_NW'])

    if 'nnigw' in SYSTEMTYPE.lower():
        MandParams.append('NNIGW_TOTAL_NO_CHASSIS')
        MandParams.append('NNIGW_ROUTE')

    if 'poc' in SYSTEMTYPE.lower():
        MandParams.append('POC_ROUTE')
        MandParams.append('TOTAL_NO_CHASSIS')


    if SETUPTYPE.lower() == 'wavelite' and DEPLOYMENTTYPE == '1':
        logger.error("DEPLOYMENTTYPE 1 is not supported for SETUPTYPE wavelite. Please check and update master input file with proper values.")
        sys.exit(1)

    # sites=['PRIMARY','GEO']
    # if DEPLOYMENTTYPE == '1':
    #     sites=['PRIMARY','SECONDARY','GEO']
    # elif DEPLOYMENTTYPE == '3':
    #     sites=['PRIMARY']
    # elif DEPLOYMENTTYPE == '4':
    #     sites=['PRIMARY','SECONDARY']

    sites = [section for section in config.sections() if section not in ['GLOBAL']]

    # Validating Mandatory parameters in all Sites Sheet in Master Input File
    for site in sites:
        for mankey in MandParams:
            if site not in [Constants.SITE1, Constants.SITE2] and mankey in ['NNIGW_TOTAL_NO_CHASSIS','NNIGW_ROUTE','CONSUL_LOCAL_SERVERS']:
                continue
            if mankey not in dictionary[site]:
                logger.error("{} Section in master input Mandatory key {} not exists. Please check and update master input file".format(site,mankey))
                sys.exit(1)

            if dictionary[site][mankey] == '' or not dictionary[site][mankey]:
                logger.error("{} Section in master input {} :: {} is empty. Please check and update master input file".format(site,mankey,dictionary[site][mankey]))
                sys.exit(1)
        if 'poc' in SYSTEMTYPE.lower():
            for chasssis_num in range(0,int(dictionary[site]['TOTAL_NO_CHASSIS'])):
                chasssis_num = chasssis_num + 1
                for param in ['HOSTIP','SERVICEVMIP','OAMVMIP','CARDLIST']:
                    paramname='VM_CHASSIS_'+str(chasssis_num)+'_'+param
                    if paramname not in dictionary[site]:
                        logger.error("{} Section in master input Mandatory key {} not exists. Please check and update master input file".format(site,paramname))
                        sys.exit(1)

                    if dictionary[site][paramname] == '' or not dictionary[site][paramname]:
                        logger.error("{} Section in master input {} :: {} is empty. Please check and update master input file".format(site,paramname,dictionary[site][paramname]))
                        sys.exit(1)

                # newkey=site
                # if site == 'SECONDARY':
                #     newkey = 'PRIMARY'
                # if newkey not in CardList.keys():
                #     CardList[newkey] = []
                # CardList[newkey].extend(dictionary[site]['VM_CHASSIS_'+str(chasssis_num)+'_CARDLIST'].split(','))

                # for poc_cards in CardList.values():
                #     if 'SYNCGW' in poc_cards:
                #         logger.error("SYNCGW and SYNCGWREP Containers are not supported from 12.3.1.2.Please remove the cards from masterinput file.\n")
                #         print("SYNCGW and SYNCGWREP Containers are not supported from 12.3.1.2.Please remove the cards from masterinput file.\n")
                #         sys.exit(1)


        if 'nnigw' in SYSTEMTYPE.lower():
            # if site == 'SECONDARY':
            #     continue
            for chass_num in range(0,int(dictionary[site]['NNIGW_TOTAL_NO_CHASSIS'])):
                chass_num = chass_num + 1
                for param in ['HOSTIP','SERVICEVMIP','OAMVMIP','CARDLIST']:
                    paramname='NNIGW_VM_CHASSIS_'+str(chass_num)+'_'+param
                    if paramname not in dictionary[site]:
                        logger.error("{} Section in master input Mandatory key {} not exists. Please check and update master input file".format(site,paramname))
                        sys.exit(1)

                    if dictionary[site][paramname] == '' or not dictionary[site][paramname]:
                        logger.error("{} Section in master input {} :: {} is empty. Please check and update master input file".format(site,paramname,dictionary[site][paramname]))
                        sys.exit(1)

                # newkey=site
                # if site == 'SECONDARY':
                #     newkey = 'PRIMARY'
                # if newkey not in NNIGWCardList.keys():
                #     NNIGWCardList[newkey] = []
                # NNIGWCardList[newkey].extend(dictionary[site]['NNIGW_VM_CHASSIS_'+str(chass_num)+'_CARDLIST'].split(','))


    # if 'poc' in SYSTEMTYPE.lower():
    #     for site in CardList.keys():
    #         consulcount=CardList[site].count('ConsulServer')
    #         rmqcount=CardList[site].count('RMQ')
    #         vaultcount=CardList[site].count('VAULT')

    #         if consulcount != 3 :
    #             logger.error("{} Section in master input Consul Container Count is :: {}. Required Consul card in each site is 3. Please check and update master input file CARDS value".format(key,consulcount))
    #             sys.exit(1)
    #         if rmqcount != 3 :
    #             logger.error("{} Section in master input RMQ Container Count is :: {}. Required RMQ card in each site is 3. Please check and update master input file CARDS value".format(key,rmqcount))
    #             sys.exit(1)
    #         if vaultcount != 2 :
    #             logger.error("{} Section in master input VAULT Container Count is :: {}. Required VAULT card in each site is 2. Please check and update master input file CARDS value".format(key,vaultcount))
    #             sys.exit(1)

    #         evaluate_idap_cards('poc', CardList[site], site, IDAP_INSTALL_LIGHT_POC)

    # if 'nnigw' in SYSTEMTYPE.lower():
    #     for site in NNIGWCardList.keys():
    #         consulcount=NNIGWCardList[site].count('ConsulServer')
    #         rmqcount=NNIGWCardList[site].count('RMQ')
    #         vaultcount=NNIGWCardList[site].count('VAULT')

    #         if consulcount != 3 :
    #             logger.error("{} Section in master input Consul Container Count is :: {} for NNIGW. Required Consul card in each site is 3. Please check and update master input file CARDS value".format(site,consulcount))
    #             sys.exit(1)
    #         if rmqcount != 3 :
    #             logger.error("{} Section in master input RMQ Container Count is :: {} for NNIGW. Required RMQ card in each site is 3. Please check and update master input file CARDS value".format(site,rmqcount))
    #             sys.exit(1)
    #         if vaultcount != 2 :
    #             logger.error("{} Section in master input VAULT Container Count is :: {} for NNIGW. Required VAULT card in each site is 2. Please check and update master input file CARDS value".format(site,vaultcount))
    #             sys.exit(1)

    #         evaluate_idap_cards('nnigw', NNIGWCardList[site], site, IDAP_INSTALL_LIGHT_NNIGW)

def Updaterhelidminstance(Type):
    '''
    This Function creates RHELIDM_INSTANCE_INFO value based on input POC/NNI
    '''

    rhelidminstance = []
    if Type == 'POC':
        ipacheck='ipaserver'
    else:
        ipacheck='NNIipaserver'

    for server in ipmapjson:
        for card in ipmapjson[server]:
            if re.search('^'+ipacheck,card):
                if card == ipacheck+"1":
                    isserver = '1'
                else:
                    isserver = '0'

                cardname=card
                if 'NNI' in card:
                    cardname=card.lstrip('NNI')

                if DEPLOYMENT_PLATFORM_TYPE == 5:
                    host = Constants.hostext[Type]+cardname+"."+INTERNAL_HOST_DOMAIN
                else:
                    host = cardname+"."+INTERNAL_HOST_DOMAIN
                rhelidmjson={"IP":ipmapjson[server][card],"Host":host, "IS_SERVER_NODE":isserver}
                rhelidminstance.append(rhelidmjson)
        logger.info("RHELIDM_INSTANCE_INFO is {}".format(rhelidminstance))

    return rhelidminstance


def validate_oam_configuration(ip_map_hash, config, logger):
        """
        Validates OAM configuration for all sites in the IP map hash.
        
        Args:
            ip_map_hash: Dictionary containing site information
            config: Configuration parser object
            logger: Logger instance for error logging
        """
        for mysite in ip_map_hash:
            if FreshLaunchInvVars[mysite]['OAMPLANE_SUBNET'] == '' or FreshLaunchInvVars[mysite]['OAMPLANE_GATEWAY'] == '' or FreshLaunchInvVars[mysite]['OAMPLANE_BROADCASTIP'] == '' or FreshLaunchInvVars[mysite]['OAMPLANE_MGMT_BRIDGE']  == '':
                print("Please configure all OAM inputs in the Conf file and retry")
                logger.error("Please configure all OAM inputs in the Conf file and retry")
                #sys.exit(1)
            if FreshLaunchInvVars[mysite]['OAMPLANE_MGMT_NW'] == '' and FreshLaunchInvVars[mysite]['FIXEDIP_SERVICETYPE_MAP'] == '':
                print ("Please configure OAMPLANE_MGMT_NW or FIXEDIP_SERVICETYPE_MAP and retry")
                logger.error("Please configure OAMPLANE_MGMT_NW or FIXEDIP_SERVICETYPE_MAP and retry")
                
                
def populate_chassis_data(ip_map_hash, SYSTEMTYPE, VM_CHASSIS, NNIGW_VM_CHASSIS, 
                             ALLPOCVM, ALLPOCBM, ALLNNIVM, ALLNNIBM, XDMVMIP, SIGVMIP, 
                             exclude_cards):
        """
        Populate VM chassis data for POC and NNIGW systems.
        
        Args:
            ip_map_hash: Dictionary containing site information
            SYSTEMTYPE: System type (poc, nnigw, or poc_nnigw)
            VM_CHASSIS: Dictionary to store POC chassis data
            NNIGW_VM_CHASSIS: Dictionary to store NNIGW chassis data
            ALLPOCVM: List to store POC VM IPs
            ALLPOCBM: List to store POC bare metal IPs
            ALLNNIVM: List to store NNI VM IPs
            ALLNNIBM: List to store NNI bare metal IPs
            XDMVMIP: List to store XDM VM IPs
            SIGVMIP: List to store SIG VM IPs
            exclude_cards: Set of cards to exclude from counting
        
        Returns:
            tuple: (POCCardCount, GWCardCount)
        """
        POCCardCount = 0
        GWCardCount = 0
        
        for site in ip_map_hash.keys():
            if 'poc' in SYSTEMTYPE.lower():
                Chassis_Count = FreshLaunchInvVars[site]['TOTAL_NO_CHASSIS']
                for count in range(0, int(Chassis_Count)):
                    count += 1
                    if site not in VM_CHASSIS:
                        VM_CHASSIS[site] = {}

                    VM_CHASSIS[site][count] = ({
                        'CARDS': FreshLaunchInvVars[site][f'VM_CHASSIS_{count}_CARDLIST'].split(',')
                    })
                    VM_CHASSIS[site][count].update({
                        'VMIP': FreshLaunchInvVars[site][f'VM_CHASSIS_{count}_SERVICEVMIP']
                    })
                    VM_CHASSIS[site][count].update({
                        'SERVICEVMIP': FreshLaunchInvVars[site][f'VM_CHASSIS_{count}_SERVICEVMIP']
                    })
                    VM_CHASSIS[site][count].update({
                        'OAMVMIP': FreshLaunchInvVars[site][f'VM_CHASSIS_{count}_OAMVMIP']
                    })
                    
                    ALLPOCVM.append(FreshLaunchInvVars[site][f'VM_CHASSIS_{count}_OAMVMIP'])
                    ALLPOCBM.append(FreshLaunchInvVars[site][f'VM_CHASSIS_{count}_HOSTIP'])
                    
                    POCCardCount += len(VM_CHASSIS[site][count]['CARDS'])
                    POCCardCount -= sum(1 for card in VM_CHASSIS[site][count]['CARDS'] 
                                      if card in exclude_cards)
                    
                    if 'XDM' in VM_CHASSIS[site][count]['CARDS']:
                        XDMVMIP.append(FreshLaunchInvVars[Constants.SITE1][f'VM_CHASSIS_{count}_OAMVMIP'])

            if 'nnigw' in SYSTEMTYPE.lower():
                # if site == 'SECONDARY':
                #     continue
                    
                Chassis_Count = FreshLaunchInvVars[site]['NNIGW_TOTAL_NO_CHASSIS']
                for count in range(0, int(Chassis_Count)):
                    count += 1
                    if site not in NNIGW_VM_CHASSIS:
                        NNIGW_VM_CHASSIS[site] = {}

                    NNIGW_VM_CHASSIS[site][count] = ({
                        'CARDS': FreshLaunchInvVars[site][f'NNIGW_VM_CHASSIS_{count}_CARDLIST'].split(',')
                    })
                    NNIGW_VM_CHASSIS[site][count].update({
                        'VMIP': FreshLaunchInvVars[site][f'NNIGW_VM_CHASSIS_{count}_SERVICEVMIP']
                    })
                    
                    ALLNNIVM.append(FreshLaunchInvVars[site][f'NNIGW_VM_CHASSIS_{count}_OAMVMIP'])
                    ALLNNIBM.append(FreshLaunchInvVars[site][f'NNIGW_VM_CHASSIS_{count}_HOSTIP'])
                    
                    GWCardCount += len(NNIGW_VM_CHASSIS[site][count]['CARDS'])
                    GWCardCount -= sum(1 for card in NNIGW_VM_CHASSIS[site][count]['CARDS'] 
                                     if card in exclude_cards)
                    
                    if 'SIG' in NNIGW_VM_CHASSIS[site][count]['CARDS']:
                        SIGVMIP.append(FreshLaunchInvVars[Constants.SITE1][f'NNIGW_VM_CHASSIS_{count}_OAMVMIP'])
        
        return POCCardCount, GWCardCount
    

# def populate_emsvm_chassid(ip_map_hash, SYSTEMTYPE, VM_CHASSIS, NNIGW_VM_CHASSIS, VM_HOSTIPS, NNIGW_VM_HOSTIPS):
#         """
#         Populate VM host IP to chassis id mapping for EMS VMs for POC and NNIGW systems.
        
#         Args:
#             ip_map_hash: Dictionary containing site information
#             SYSTEMTYPE: System type (poc, nnigw, or poc_nnigw)
#             VM_CHASSIS: Dictionary containing POC chassis data
#             NNIGW_VM_CHASSIS: Dictionary containing NNIGW chassis data
#             VM_HOSTIPS: Dictionary to store POC VM host IP mappings
#             NNIGW_VM_HOSTIPS: Dictionary to store NNIGW VM host IP mappings
#         """
#         for site in ip_map_hash.keys():
#             if 'poc' in SYSTEMTYPE.lower():
#                 count = 0
#                 for chid in VM_CHASSIS[site].keys():
#                     if 'EMS' in VM_CHASSIS[site][chid]['CARDS']:
#                         count = Constants.clustevar[site]

#                         # if "SECONDARY" not in ip_map_hash.keys() and site == "GEO":
#                         #     count = 2

#                         VM_HOSTIPS[VM_CHASSIS[site][chid]['VMIP']] = count

#             if 'nnigw' in SYSTEMTYPE.lower():
#                 # if site in 'SECONDARY':
#                 #     continue
#                 count = 0
#                 for chid in NNIGW_VM_CHASSIS[site].keys():
#                     if 'EMSNNI' in NNIGW_VM_CHASSIS[site][chid]['CARDS']:
#                         count = Constants.clustevar[site]

#                         # if site == "GEO":
#                         #     count = 2

#                         NNIGW_VM_HOSTIPS[NNIGW_VM_CHASSIS[site][chid]['VMIP']] = count
                        

# def assign_othervm_chassid(ip_map_hash, SYSTEMTYPE, VM_CHASSIS, NNIGW_VM_CHASSIS, VM_HOSTIPS, NNIGW_VM_HOSTIPS):
#         """
#         Assign Chassis id for VM other than EMS VMs  counts for POC and NNIGW systems.
        
#         Args:
#             ip_map_hash: Dictionary containing site information
#             SYSTEMTYPE: System type (poc, nnigw, or poc_nnigw)
#             VM_CHASSIS: Dictionary containing POC chassis data
#             NNIGW_VM_CHASSIS: Dictionary containing NNIGW chassis data
#             VM_HOSTIPS: Dictionary to store POC VM host IP mappings
#             NNIGW_VM_HOSTIPS: Dictionary to store NNIGW VM host IP mappings
#         """
#         if 'poc' in SYSTEMTYPE.lower():
#             count = max(VM_HOSTIPS.values(), key=int)
            
#         nnigw_count = ''
#         if 'nnigw' in SYSTEMTYPE.lower():
#             nnigw_count = max(NNIGW_VM_HOSTIPS.values(), key=int)

#         for site in ['PRIMARY','SECONDARY','GEO']:
#             if not site in ip_map_hash.keys():
#                 continue

#             if 'poc' in SYSTEMTYPE.lower():
#                 for chid in VM_CHASSIS[site].keys():
#                     if VM_CHASSIS[site][chid]['VMIP'] not in VM_HOSTIPS.keys():
#                         count +=1
#                         VM_HOSTIPS[VM_CHASSIS[site][chid]['VMIP']] = count

#             if 'nnigw' in SYSTEMTYPE.lower():
#                 if site in 'SECONDARY':
#                     continue

#                 for chid in NNIGW_VM_CHASSIS[site].keys():
#                     if NNIGW_VM_CHASSIS[site][chid]['VMIP'] not in NNIGW_VM_HOSTIPS.keys():
#                         nnigw_count +=1
#                         NNIGW_VM_HOSTIPS[NNIGW_VM_CHASSIS[site][chid]['VMIP']] = nnigw_count
                        

def write_ip_mapping_to_file(ipmapjson, logger):
        """
        Write IP mapping to alliplist.txt file.
        
        Args:
            ipmapjson: Dictionary containing IP mappings
            logger: Logger instance for logging
        """
        try:
            logger.info("Populating Signalling Cards Ip's into text file :: alliplist.txt")
            with open(f'{Constants.Relative_path}alliplist.txt', "w") as myfile:
                for line in ipmapjson:
                    myfile.write('['+line+']'+'\n')
                    for mylist in ipmapjson[line]:
                        myfile.write(mylist+':'+ipmapjson[line][mylist]+'\n')
                    myfile.write('\n')
        except Exception as e:
            logger.error(str(e))
            sys.exit(1)


def update_host_vars(ems_inv: CreateInventory, host_vars: dict, hostname: str, logger: logging.Logger):
    """
    Update host and host variables in the EMS inventory.
    
    Args:
        ems_inv: CreateInventory instance
        host_vars: Dictionary containing host variables to update
        hostname: Host name to identify the host in the inventory
        logger: Logger instance for logging
    """
    try:
        if 'nni' in hostname:
            group_name = Constants.NNIGROUPNAME
        else:
            group_name = Constants.POCGROUPNAME
            
        ems_inv.create_host(Constants.EMSInvNAME, hostname)
        ems_inv.update_host_vars(Constants.EMSInvNAME, hostname, host_vars)
        ems_inv.add_host_to_group(Constants.EMSInvNAME, hostname, group_name)
        logger.info("Successfully updated host variables for host {}".format(hostname))
        
    except Exception as e:
        logger.error("Error updating host variables for host {}: {}".format(hostname, str(e)))
        sys.exit(1)
     
            
            
def update_input_data(ems_inv, ipmapjson, sites_to_launch, logger):
        """
        Update input data by creating container INI files and answer files for each server and card.
        
        Args:
            ipmapjson: Dictionary containing IP mappings for servers and cards
            Imagelist: Dictionary containing POC image mappings
            NNIImagelist: Dictionary containing NNI image mappings
            systemtype: System type (poc, nnigw, or poc_nnigw)
            logger: Logger instance for logging
        """
        global Dgid, InstallationType, Ansfile
        
        for site in ipmapjson:
            
            if site.lower() not in sites_to_launch:
                continue
            for card in ipmapjson[site]:
                # logger.info("Creating Container ini file for Card:: {}".format(card))
                # if 'ipaserver' in card:
                #     rhelpttsystemtype = '1'
                #     ServerType='RHELIDM'

                #     if 'NNI' in card:
                #         rhelpttsystemtype = '2'
                #         ServerType='NNIRHELIDM'

                #     ipaimage=Imagelist['RHELIDM']
                #     if 'NNI' in card:
                #         ipaimage=NNIImagelist['RHELIDM']

                #     CreateContainerINI(site, ServerType,card,card+'.'+INTERNAL_HOST_DOMAIN,ipmapjson[site][card],config.get('GLOBAL','CARRIERID')+str(Dgid)+'1',ipaimage,rhelpttsystemtype);
                #     Dgid+=1
                # else:
                if card in ['EMSPRI','EMSSEC','EMSGEO']:
                    pttsystemtype = '1'
                    #TODO: get ems image from AAP Inventory
                    image = "rhel810_platform/rhel810_ems:R14_000_00_D14_000_00_111120250428"
                elif card in ['EMSNNIPRI', 'EMSGEONNI']:
                    pttsystemtype = '2'
                    image = "rhel810_platform/rhel810_ems:R14_000_00_D14_000_00_111120250428"
                else:
                    logger.error("Invalid ems card type: {}".format(card))
                    sys.exit(1)

                if site == Constants.SITE1:
                    if card == 'EMSPRI':
                        InstallationType = '1'
                        Ansfile = card.lower()+site.lower()+'.ans'
                        ini_host_vars = CreateContainerINI(site,card,card.lower()+site.lower(),'emspri',ipmapjson[site][card],'emsdsn',image,pttsystemtype)
                        answer_vars = CreateAnswerFile(site,card.lower()+'pri',pttsystemtype,InstallationType,'EMSPRI',ipmapjson[site][card])
                    if card == 'EMSPRINNI':
                        InstallationType = '1'
                        Ansfile = card.lower()+site.lower()+'.ans'
                        ini_host_vars = CreateContainerINI(site,card,card.lower()+site.lower(),'emsnnipri',ipmapjson[site][card],'emsdsn',image,pttsystemtype)
                        answer_vars = CreateAnswerFile(site,card.lower()+'pri',pttsystemtype,InstallationType,'EMSNNIPRI',ipmapjson[site][card])
                    if card == 'EMSSEC':
                        InstallationType = '2'
                        Ansfile = card.lower()+site.lower()+'.ans'
                        ini_host_vars = CreateContainerINI(site,card,card.lower()+site.lower(),'emssec',ipmapjson[site][card],'emsdsn',image,pttsystemtype)
                        answer_vars = CreateAnswerFile(site,card.lower()+'sec',pttsystemtype,InstallationType,'EMSSEC',ipmapjson[site][card])
                # if server == 'SECONDARY':
                #     InstallationType = '2'
                #     Ansfile = card.lower()+'sec.ans'
                #     ini_host_vars = CreateContainerINI(server,card,card.lower()+server.lower(),'emssec',ipmapjson[server][card],'emsdsn',image,pttsystemtype)
                #     answer_vars = CreateAnswerFile(server,card.lower()+'sec',pttsystemtype,InstallationType,'EMSSEC',ipmapjson[server][card])
                if site == Constants.SITE2:
                    if card == 'EMSGEO':  
                        InstallationType = '3'
                        Ansfile = card.lower()+site.lower()+'.ans'
                        ini_host_vars = CreateContainerINI(site,card,card.lower()+site.lower(),'emsgeo',ipmapjson[site][card],'emsdsn',image,pttsystemtype)
                        answer_vars = CreateAnswerFile(site,card.lower()+'geo',pttsystemtype,InstallationType,'EMSGEO',ipmapjson[site][card])
                    if card == 'EMSNNIGEO':  
                        InstallationType = '3'
                        Ansfile = card.lower()+site.lower()+'.ans'
                        ini_host_vars = CreateContainerINI(site,card,card.lower()+site.lower(),'emsnnigeo',ipmapjson[site][card],'emsdsn',image,pttsystemtype)
                        answer_vars = CreateAnswerFile(site,card.lower()+'geo',pttsystemtype,InstallationType,'EMSNNIGEO',ipmapjson[site][card])

                
                all_host_vars = {**ini_host_vars, **answer_vars}
                update_host_vars(ems_inv, all_host_vars, card.lower(), logger)

                    


def write_allemsvm_file(POCVMEMSLIST, ALLPOCVM, NNIVMEMSLIST, ALLNNIVM, logger):
        """
        Generate /home/autoinstall/ALLEMSVM.txt file with VM IP information.
        
        Args:
            POCVMEMSLIST: List of POC EMS VM IPs
            ALLPOCVM: List of all POC VM IPs
            NNIVMEMSLIST: List of NNI EMS VM IPs
            ALLNNIVM: List of all NNI VM IPs
            logger: Logger instance for error logging
        """
        try:
            with open(Constants.ALLVMiptxt, "w") as myfile:
                if len(POCVMEMSLIST) != 0:
                    myfile.write('[POCEMSVMS]'+'\n')
                    for line in POCVMEMSLIST:
                        myfile.write(line+'\n')
                    myfile.write('\n')

                if len(ALLPOCVM) != 0:
                    myfile.write('[ALLPOCVMS]'+'\n')
                    for line in ALLPOCVM:
                        myfile.write(line+'\n')
                    myfile.write('\n')

                if len(NNIVMEMSLIST) != 0:
                    myfile.write('[NNIGWEMSVMS]'+'\n')
                    for line in NNIVMEMSLIST:
                        myfile.write(line+'\n')
                    myfile.write('\n')

                if len(ALLNNIVM) != 0:
                    myfile.write('[ALLNNIGWVMS]'+'\n')
                    for line in ALLNNIVM:
                        myfile.write(line+'\n')

        except Exception as e:
            logger.error(str(e))
            sys.exit(1)
            
            
def createFreshLaunchInventory(freshlaunchinv, logger):
    
    '''
    This function creates EMS inventory in AAP
    '''
    logger.info(f"Creating EMS Inventory with name: {Constants.EMSInvNAME}")
    
    try:
        
        if freshlaunchinv.check_inventory_exists(Constants.FreshLaunchInvName):
            logger.info(f"EMS Inventory '{Constants.FreshLaunchInvName}' already exists. Deleting existing inventory.")
            freshlaunchinv.delete_inventory(Constants.FreshLaunchInvName)
            time.sleep(2)  # Wait for 2 seconds to ensure deletion is processed
            logger.info(f"Existing Fresh Launch Inventory '{Constants.FreshLaunchInvName}' deleted successfully.")

        inventory_vars = {}

        freshlaunchinv.create_inventory(Constants.FreshLaunchInvName, inventory_vars)
        logger.info("Fresh Launch Inventory created successfully.")
        
        # Update_inventory_variables(ems_inventory, Constants.EMSInvNAME, logger)
    except Exception as e:
        logger.error(f"Failed to create Fresh Launch Inventory: {str(e)}")
        sys.exit(1)

def createFreshLaunchInv(freshlaunchinv, POCVMEMSLIST, ALLPOCVM, NNIVMEMSLIST, ALLNNIVM, ALLPOCBM, ALLNNIBM, 
                                Emsiplist, Nniiplist, SYSTEMTYPE, POCPriems, GWPriems, POCPRIEMSVM, 
                                GWPRIEMSVM, XDMVMIP, SIGVMIP, POCCardCount, GWCardCount, DEPLOYMENTTYPE, F5_CORES, SETUPTYPE, AUTOMATE_DOCKER_PULL, logger):
    """
    Write password hosts file with VM and configuration information.
    
    Args:
        freshlaunchinv: Fresh launch inventory object
        POCVMEMSLIST: List of POC EMS VM IPs
        ALLPOCVM: List of all POC VM IPs
        NNIVMEMSLIST: List of NNI EMS VM IPs
        ALLNNIVM: List of all NNI VM IPs
        ALLPOCBM: List of all POC bare metal IPs
        ALLNNIBM: List of all NNI bare metal IPs
        Emsiplist: List of EMS IPs
        Nniiplist: List of NNI IPs
        SYSTEMTYPE: System type (poc, nnigw, or poc_nnigw)
        POCPriems: Primary POC EMS IP
        GWPriems: Primary gateway EMS IP
        POCPRIEMSVM: List of POC primary EMS VM IPs
        GWPRIEMSVM: List of gateway primary EMS VM IPs
        XDMVMIP: List of XDM VM IPs
        SIGVMIP: List of SIG VM IPs
        POCCardCount: Count of POC cards
        GWCardCount: Count of gateway cards
        DEPLOYMENTTYPE: Deployment type
        F5_CORES: F5 cores configuration
        SETUPTYPE: Setup type
        AUTOMATE_DOCKER_PULL: Docker pull automation flag
        logger: Logger instance for error logging
    """
    try:
        
        createFreshLaunchInventory(freshlaunchinv, logger)
        
        iplist = []
        
        if len(POCVMEMSLIST) != 0:
            for host in POCVMEMSLIST:
                if host not in iplist:
                    freshlaunchinv.create_host(Constants.FreshLaunchInvName, host)
                    iplist.append(host)
            freshlaunchinv.create_group(Constants.FreshLaunchInvName, 'POCEMSVMS')
            freshlaunchinv.add_hosts_to_group(Constants.FreshLaunchInvName, POCVMEMSLIST, 'POCEMSVMS', )

        if len(ALLPOCVM) != 0:
            for host in ALLPOCVM:
                if host not in iplist:
                    freshlaunchinv.create_host(Constants.FreshLaunchInvName, host)
                    iplist.append(host)
            freshlaunchinv.create_group(Constants.FreshLaunchInvName, 'ALLPOCVMS')
            freshlaunchinv.add_hosts_to_group(Constants.FreshLaunchInvName, ALLPOCVM, 'ALLPOCVMS')

        if len(NNIVMEMSLIST) != 0:
            for host in NNIVMEMSLIST:
                if host not in iplist:
                    freshlaunchinv.create_host(Constants.FreshLaunchInvName, host)
                    iplist.append(host)
            freshlaunchinv.create_group(Constants.FreshLaunchInvName, 'NNIGWEMSVMS')
            freshlaunchinv.add_hosts_to_group(Constants.FreshLaunchInvName, NNIVMEMSLIST, 'NNIGWEMSVMS')

        if len(ALLNNIVM) != 0:
            for host in ALLNNIVM:
                if host not in iplist:
                    freshlaunchinv.create_host(Constants.FreshLaunchInvName, host)
                    iplist.append(host)
            freshlaunchinv.create_group(Constants.FreshLaunchInvName, 'ALLNNIGWVMS')
            freshlaunchinv.add_hosts_to_group(Constants.FreshLaunchInvName, ALLNNIVM, 'ALLNNIGWVMS')
            
        freshLaunchVars = {}

        if 'poc' in SYSTEMTYPE.lower():
            freshLaunchVars['POCVMIPS'] = ALLPOCVM
            freshLaunchVars['POCBMIPS'] = ALLPOCBM
            freshLaunchVars['POCEMSIPS'] = Emsiplist
            freshLaunchVars['POCPRIEMSIP'] = POCPriems
            freshLaunchVars['POCPRIEMSVM'] = POCPRIEMSVM[0]
            freshLaunchVars['XDMVMIP'] = XDMVMIP[0]
            freshLaunchVars['POCCardCount'] = POCCardCount
            freshLaunchVars['POC_LICENSE_PATH'] = FreshLaunchInvVars['GLOBAL']['POC_LICENSE_PATH']
        if 'nnigw' in SYSTEMTYPE.lower():
            NNIVM_ips = ', '.join(['"{}"'.format(ip) for ip in ALLNNIVM])
            NNIBM_ips = ', '.join(['"{}"'.format(ip) for ip in ALLNNIBM])
            NNIEMS_ips = ', '.join(['"{}"'.format(ip) for ip in Nniiplist])
            freshLaunchVars['GWVMIPS'] = ALLNNIVM
            freshLaunchVars['GWBMIPS'] = ALLNNIBM
            freshLaunchVars['GWEMSIPS'] = Nniiplist
            freshLaunchVars['GWPRIEMSIP'] = GWPriems
            freshLaunchVars['GWPRIEMSVM'] = GWPRIEMSVM[0]
            freshLaunchVars['SIGVMIP'] = SIGVMIP[0]
            freshLaunchVars['GWCardCount'] = GWCardCount
            freshLaunchVars['NNI_LICENSE_PATH'] = FreshLaunchInvVars['GLOBAL']['NNI_LICENSE_PATH']
            
        freshLaunchVars['SYSTEM_TYPE'] = SYSTEMTYPE
        freshLaunchVars['DEPLOYMENTTYPE'] = DEPLOYMENTTYPE
        freshLaunchVars['F5_CORES'] = F5_CORES
        freshLaunchVars['SETUP_TYPE'] = SETUPTYPE.lower()
        if SETUPTYPE.lower() == 'wavelite':
            for site in ['PRIMARY','GEO']:
                WAVELITE_ROUTE=FreshLaunchInvVars[site]['WAVELITE_ROUTE']
                freshLaunchVars['WAVELITE_ROUTE_'+site] = WAVELITE_ROUTE
        freshLaunchVars['AUTOMATE_DOCKER_PULL'] = AUTOMATE_DOCKER_PULL
        if AUTOMATE_DOCKER_PULL.lower()=='yes':
            freshLaunchVars['DOCKER_USERNAME'] = FreshLaunchInvVars['GLOBAL']['DOCKER_USERNAME']
            freshLaunchVars['DOCKER_PASSWORD'] = FreshLaunchInvVars['GLOBAL']['DOCKER_PASSWORD'].strip('"')
            freshLaunchVars['DOCKER_REGISTRY'] = FreshLaunchInvVars['GLOBAL']['DOCKER_REGISTRY']
            freshLaunchVars['COSIGN_PUB_KEY_PATH'] = '/Software/'+FreshLaunchInvVars['GLOBAL']['COSIGN_PUB_KEY']
        freshLaunchVars['WILDCARDFQDN'] = FreshLaunchInvVars['GLOBAL']['WILDCARDFQDN']
        freshLaunchVars['ansible_ssh_user'] = 'autoinstall'
        freshLaunchVars['ansible_ssh_pass'] = 'kodiak'
        freshLaunchVars['ansible_connection'] = 'ssh'
        
        freshlaunchinv.update_inventory_vars(Constants.FreshLaunchInvName, freshLaunchVars)

    except Exception as e:
        logger.error(str(e))
        sys.exit(1)
            

# def create_rhelidm_yaml_files(SYSTEMTYPE, rhelidmjson1, IPASERVERCHASSIS, NNIIPASERVERCHASSIS, 
#                                   VM_HOSTIPS, NNIGW_VM_HOSTIPS, config, COMMONPLATFLAG, 
#                                   DEPLOYMENT_PLATFORM_TYPE):
#         """
#         Create RHELIDM YAML files for POC and NNIGW systems.
        
#         Args:
#             SYSTEMTYPE: System type (poc, nnigw, or poc_nnigw)
#             rhelidmjson1: Dictionary containing RHELIDM server configurations
#             IPASERVERCHASSIS: Dictionary mapping IPA servers to chassis IDs
#             NNIIPASERVERCHASSIS: Dictionary mapping NNI IPA servers to chassis IDs
#             VM_HOSTIPS: Dictionary mapping VM IPs to host IPs
#             NNIGW_VM_HOSTIPS: Dictionary mapping NNIGW VM IPs to host IPs
#             config: Configuration parser object
#             COMMONPLATFLAG: Common platform flag
#             DEPLOYMENT_PLATFORM_TYPE: Deployment platform type
#         """
        
#         if 'poc' in SYSTEMTYPE.lower():
#             myrhelidmdata = {"rhelidm_servers" : []}

#             for site in ['PRIMARY','SECONDARY','GEO']:
#                 if not site in rhelidmjson1:
#                     continue

#                 mydata = {}
#                 newclusterid = Constants.CLUSTERIDDICT[site]
#                 rhelidmymlroute = config.get(site,'POC_ROUTE')
                
#                 for val in rhelidmjson1[site]:
#                     if 'NNI' in val['host'].split('.')[0] or 'gw' in val['host'].split('.')[0]:
#                         continue

#                     ipachassisid = IPASERVERCHASSIS[val['host'].split('.')[0]]
#                     rhelhostip = config.get(site,'VM_CHASSIS_'+str(ipachassisid)+'_SERVICEVMIP')
#                     newchassisid = VM_HOSTIPS[rhelhostip]

#                     if DEPLOYMENT_PLATFORM_TYPE == 5:
#                         val['host'] = QuotedString(val['host'].lstrip('poc'))

#                     mydata = {}
#                     mydata["clusterid"] = newclusterid
#                     mydata["chassisid"] = newchassisid
#                     mydata["route"] = rhelidmymlroute
                    
#                     if not "containers" in mydata:
#                         mydata["containers"] = []
                        
#                     mydata["containers"].append(val)
#                     myrhelidmdata["rhelidm_servers"].append(mydata)

#             with open(f'{Constants.Relative_path}rhelidm.yml', 'w') as f:
#                 yaml.preserve_quotes = True
#                 yaml.dump(myrhelidmdata, f, Dumper=MyDumper)

#         if 'nnigw' in SYSTEMTYPE.lower() and COMMONPLATFLAG == 'no':
#             myrhelidmdata = {"rhelidm_servers" : []}

#             for site in ['PRIMARY','SECONDARY','GEO']:
#                 if not site in rhelidmjson1:
#                     continue

#                 mydata = {}
#                 newclusterid = Constants.CLUSTERIDDICT[site]
#                 rhelidmymlroute = config.get(site,'NNIGW_ROUTE')
                
#                 for val in rhelidmjson1[site]:
#                     if 'NNI' in val['host'].split('.')[0] or 'gw' in val['host'].split('.')[0]:
#                         ipachassisid = NNIIPASERVERCHASSIS[val['host'].split('.')[0]]
#                         rhelhostip = config.get(site,'NNIGW_VM_CHASSIS_'+str(ipachassisid)+'_SERVICEVMIP')
#                         newchassisid = NNIGW_VM_HOSTIPS[rhelhostip]
                        
#                         mydata = {}
#                         mydata["clusterid"] = newclusterid
#                         mydata["chassisid"] = newchassisid
#                         mydata["route"] = rhelidmymlroute

#                         if not "containers" in mydata:
#                             mydata["containers"] = []

#                         val['host'] = QuotedString(val['host'].lstrip('NNI'))
#                         if DEPLOYMENT_PLATFORM_TYPE == 5:
#                             val['host'] = QuotedString(val['host'].lstrip('gw'))

#                         mydata["containers"].append(val)
#                         myrhelidmdata["rhelidm_servers"].append(mydata)
                        
#                 with open('/DG/activeRelease/NNIplaybook/roles/cms/vars/rhelidm.yml', 'w') as f:
#                     yaml.preserve_quotes = True
#                     yaml.dump(myrhelidmdata, f, Dumper=MyDumper)
                    
                    
def write_ip_configuration_files(mylistmap, logger):
        """
        Write IP configuration files for OAM and service plane mappings.
        
        Args:
            mylistmap: Dictionary containing IP mappings for different sites and planes
            logger: Logger instance for error logging
        """
        try:
            logger.info("Writing IP configuration to ip.ini file")
            with open(f'{Constants.Relative_path}ip.ini', 'w') as myfile:
                for mycard in mylistmap:
                    myfile.write('['+mycard+']'+'\n')
                    for card in mylistmap[mycard]:
                        if card == 'oamplaneip':
                            myfile.write('OAMPLANEIP='+mylistmap[mycard][card])
                        else:
                            myplane = card.split('_')
                            myfile.write(myplane[0]+'IP='+mylistmap[mycard][card])
                        myfile.write('\n')

            logger.info("Writing IP configuration to nninewip.ini file")
            with open(f'{Constants.Relative_path}nninewip.ini', 'w') as myfile:
                for mycard in mylistmap:
                    myfile.write('['+mycard+']'+'\n')
                    for card in mylistmap[mycard]:
                        if card == 'oamplaneip':
                            myfile.write('oamplaneip='+mylistmap[mycard][card])
                        else:
                            myplane = card.split('_')
                            myfile.write(myplane[0].lower()+'ip='+mylistmap[mycard][card])
                        myfile.write('\n')
                        
            logger.info("Successfully created IP configuration files")
            
        except Exception as e:
            logger.error(f"Failed to create IP configuration files: {str(e)}")
            sys.exit(1)
            

def update_rhelidm_instance_info(rhel_idm_file, rhelidminstance):
    '''
    This function updates RHELIDM_INSTANCE_INFO in POC/NNIGW RHELIDMMCVSParms.txt file
    '''
    with open(rhel_idm_file, "a+") as file_object:
        file_object.seek(0)
        readfile = file_object.read()
        if 'RHELIDM_INSTANCE_INFO###' not in readfile:
            logger.info(f"RHELIDM_INSTANCE_INFO### not in {rhel_idm_file} file, hence adding")
            file_object.write('RHELIDM_INSTANCE_INFO###'+json.dumps(rhelidminstance,separators=(',', ':')))
            file_object.write('\n')


def CreateEMSInventory(ems_inventory: CreateInventory, logger: logging.Logger):
    
    '''
    This function creates EMS inventory in AAP
    '''
    logger.info(f"Creating EMS Inventory with name: {Constants.EMSInvNAME}")
    
    try:
        
        if ems_inventory.check_inventory_exists(Constants.EMSInvNAME):
            logger.info(f"EMS Inventory '{Constants.EMSInvNAME}' already exists. Deleting existing inventory.")
            ems_inventory.delete_inventory(Constants.EMSInvNAME)
            time.sleep(2)  # Wait for 2 seconds to ensure deletion is processed
            logger.info(f"Existing EMS Inventory '{Constants.EMSInvNAME}' deleted successfully.")
            
        
            
        inventory_vars = {
            'group_poc': Constants.POCGROUPNAME,
            'group_nni': Constants.NNIGROUPNAME,
            'ansible_ssh_user': Constants.SSH_USER,
            'ansible_ssh_pass': Constants.SSH_PASS,
            'CONFIG_SCRIPT': Constants.CONFIG_SCRIPT_PATH,
            'CONFIG_PATH': Constants.CONFIG_PATH
        }
        
        ems_inventory.create_inventory(Constants.EMSInvNAME, inventory_vars)
        logger.info("EMS Inventory created successfully.")
        
        # Update_inventory_variables(ems_inventory, Constants.EMSInvNAME, logger)
    except Exception as e:
        logger.error(f"Failed to create EMS Inventory: {str(e)}")
        sys.exit(1)
    
    
def get_fresh_launch_inventory_vars(inventory, logger):
    '''
    This function returns the inventory variables for Fresh Launch Inventory
    '''
    try:
        inv_vars = inventory.get_inventory_vars(Constants.FreshLaunchMainInvName)
        logger.info("Successfully retrieved inventory variables for Fresh Launch Inventory.")
        return inv_vars
    except Exception as e:
        logger.error(f"Failed to retrieve inventory variables: {str(e)}")
        sys.exit(1)
    

if __name__ == "__main__":
    
    logger = setup_logging()
    logger.info("Starting Script Execution")
    
    #TODO: Need to read from AAP FreshLaunch Main Inventory
    sites_to_launch = ['site1']
    
    inventory = CreateInventory(Constants.AAP_API_URL, Constants.AAP_USERNAME, Constants.AAP_PASSWORD, Constants.ORG_NAME, logger)
    
    CreateEMSInventory(inventory, logger)
    # Check if the master configuration file exists before reading it
    # if not os.path.exists(Constants.MasterConfFile):
    #     logger.error(f"Master configuration file {Constants.MasterConfFile} does not exist. Please check the file path and retry.")
    #     sys.exit(1)
    
    # logger.info(f"Reading master configuration file: {Constants.MasterConfFile}")
    
    
    FreshLaunchInvVars = get_fresh_launch_inventory_vars(inventory, logger)
    
    print(f"Fresh Launch Inventory Variables: {FreshLaunchInvVars}")
    
    
    # config = configparser.ConfigParser()
    # config.read(Constants.MasterConfFile)
    
    DEPLOYMENTTYPE = FreshLaunchInvVars['GLOBAL']['DEPLOYMENT_REDUNDANCY_TYPE']
    DEPLOYMENT_PLATFORM_TYPE = int(FreshLaunchInvVars['GLOBAL']['DEPLOYMENT_PLATFORM_TYPE'])
    SETUPTYPE = FreshLaunchInvVars['GLOBAL']['SETUP_TYPE']
    SYSTEMTYPE = FreshLaunchInvVars['GLOBAL']['SYSTEM_TYPE']
    INTERNAL_HOST_DOMAIN = FreshLaunchInvVars['GLOBAL']['INTERNAL_HOST_DOMAIN']
    COMMONPLATFLAG = FreshLaunchInvVars['GLOBAL']['COMMON_PLATFORM_FLAG'].lower()
    F5_CORES = FreshLaunchInvVars['GLOBAL']['F5_CORES']
    AUTOMATE_DOCKER_PULL = FreshLaunchInvVars['GLOBAL']['AUTOMATE_DOCKER_PULL']
    POCPriems = ''
    GWPriems = ''
    InstallationType = ''
    Ansfile = ''
    Dgid = 200
    POCCardCount=0
    GWCardCount=0
    
    if 'poc' in SYSTEMTYPE.lower():
        IDAP_INSTALLED_FLAG_POC = int(FreshLaunchInvVars['GLOBAL']['IDAP_INSTALLED_FLAG_POC'])
        IDAP_INSTALL_LIGHT_POC = int(FreshLaunchInvVars['GLOBAL']['IDAP_INSTALL_LIGHT_POC'])

    if 'nnigw' in SYSTEMTYPE.lower():
        IDAP_INSTALLED_FLAG_NNIGW = int(FreshLaunchInvVars['GLOBAL']['IDAP_INSTALLED_FLAG_NNIGW'])
        IDAP_INSTALL_LIGHT_NNIGW = 1 # for NNIGW, IDAP_INSTALL_LIGHT flag is always 1

    logger.info(f"Configuration - Deployment Type: {DEPLOYMENTTYPE}, Platform Type: {DEPLOYMENT_PLATFORM_TYPE}, Setup Type: {SETUPTYPE}, System Type: {SYSTEMTYPE}")

    ############# Initializing Data Structures ##########################
    Imagelist, NNIImagelist = {}, {}
    ipahosts, emshosts, Emsiplist, Nniiplist, ALIASIP = [], [], [], [], {}
    IPASERVERCHASSIS, NNIIPASERVERCHASSIS = {}, {}
    POCVMEMSLIST,NNIVMEMSLIST,ALLPOCVM,ALLNNIVM,ALLPOCBM,ALLNNIBM = [],[],[],[],[],[]
    POCPRIEMSVM,GWPRIEMSVM,SIGVMIP,XDMVMIP=[],[],[],[]
    prirhelidmlist,secrhelidmlist,georhelidmlist,rhelidmjson1 = [],[],[],{}
    mylistmap = {Constants.SITE1 :{}, Constants.SITE2:{}}
    VM_CHASSIS={}
    NNIGW_VM_CHASSIS={}
    VM_HOSTIPS={}
    NNIGW_VM_HOSTIPS={}
    
    check_required_files(SYSTEMTYPE, logger)
    
    # VerifyMasterInputFile()
    
    # if 'poc' in SYSTEMTYPE.lower():
    #     Imagelist = ReadImageDatfile(Constants.pocdatfile)
        
    # if 'nnigw' in SYSTEMTYPE.lower():
    #     NNIImagelist = ReadImageDatfile(Constants.nnidatfile)

    ip_map_hash = CreateEMSIPHash()

    #TODO: validate OAM configuration can be handled from Radha script
    # validate_oam_configuration(ip_map_hash, config, logger)

    logger.info("Dictionary Formed for the Selected Deployment:: {} and Setup Type:: {} and Systemtype:: {} is ::{}".format(DEPLOYMENTTYPE,SETUPTYPE,SYSTEMTYPE,ip_map_hash))


    CreateInventoryGroups(inventory, SYSTEMTYPE, logger)

    #deprecate below check
    # Replace the selected code with this function call:
    POCCardCount, GWCardCount = populate_chassis_data(
        ip_map_hash, SYSTEMTYPE, VM_CHASSIS, NNIGW_VM_CHASSIS,
        ALLPOCVM, ALLPOCBM, ALLNNIVM, ALLNNIBM, XDMVMIP, SIGVMIP,
        Constants.exclude_cards
    )
    

    # Call the function
    # populate_emsvm_chassid(ip_map_hash, SYSTEMTYPE, VM_CHASSIS, NNIGW_VM_CHASSIS, VM_HOSTIPS, NNIGW_VM_HOSTIPS)
    

    # Call the function
    # assign_othervm_chassid(ip_map_hash, SYSTEMTYPE, VM_CHASSIS, NNIGW_VM_CHASSIS, VM_HOSTIPS, NNIGW_VM_HOSTIPS)
    
    
    ipmapjson = AssignOAMPlaneIP(ip_map_hash)
    
    logger.info("Signalling IP map of the cards are ::{} ".format(ipmapjson))
    if 'poc' in SYSTEMTYPE.lower():
        POCPriems=ipmapjson[Constants.SITE1]['EMSPRI']
    if 'nnigw' in SYSTEMTYPE.lower():
        GWPriems=ipmapjson[Constants.SITE1]['EMSNNIPRI']

    #TODO: check if this is needed or used anywhere
    write_ip_mapping_to_file(ipmapjson, logger)
    
    serviceplane = CreatePlaneIp('SERVICEPLANE_MGMT_NW')
    remoteplane = CreatePlaneIp('REMOTELOGPLANE_MGMT_NW')
    rxplane = CreatePlaneIp('RXPLANE_MGMT_NW')

    # POCrhelidminstance = Updaterhelidminstance('POC')
    # if COMMONPLATFLAG == 'no':
    #     NNIrhelidminstance = Updaterhelidminstance('NNI')


    # Call the function
    update_input_data(inventory, ipmapjson, sites_to_launch, logger)

    #TODO: check if this is needed or used anywhere
    write_allemsvm_file(POCVMEMSLIST, ALLPOCVM, NNIVMEMSLIST, ALLNNIVM, logger)

    # Replace the selected code with this function call:
    # create_rhelidm_yaml_files(SYSTEMTYPE, rhelidmjson1, IPASERVERCHASSIS, NNIIPASERVERCHASSIS,
    #                          VM_HOSTIPS, NNIGW_VM_HOSTIPS, config, COMMONPLATFLAG,
    #                          DEPLOYMENT_PLATFORM_TYPE)
    

    # Call the function
    write_ip_configuration_files(mylistmap, logger)
    
    # if "poc" in SYSTEMTYPE.lower():
    #     update_rhelidm_instance_info(Constants.POC_RHELIDM_FILE, POCrhelidminstance)

    # if "nnigw" in SYSTEMTYPE.lower():
    #     update_rhelidm_instance_info(Constants.NNIGW_RHELIDM_FILE, NNIrhelidminstance)
        

    # Replace the original code with a function call:
    createFreshLaunchInv(inventory, POCVMEMSLIST, ALLPOCVM, NNIVMEMSLIST, ALLNNIVM, ALLPOCBM, ALLNNIBM,
                             Emsiplist, Nniiplist, SYSTEMTYPE, POCPriems, GWPriems, POCPRIEMSVM,
                             GWPRIEMSVM, XDMVMIP, SIGVMIP, POCCardCount, GWCardCount,
                             DEPLOYMENTTYPE, F5_CORES, SETUPTYPE, AUTOMATE_DOCKER_PULL, logger)
 
 
 
