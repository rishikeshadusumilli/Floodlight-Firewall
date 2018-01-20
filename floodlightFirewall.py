#!/usr/bin/bash/env python

#Name: Rishikesh Adusumilli

from flask import Flask, render_template, Markup, request
from flask.helpers import send_file
import os,httplib,json,subprocess

count=1

############################ Module for cURL #######################

def post(cIP,userInput,configType):
    output=apiInt(cIP,userInput,configType,"POST")
    return output

def delete(cIP,userInput,configType):
    output=apiInt(cIP,userInput,configType,"DELETE")
    return output

def apiInt(cIP,userInput,configType,method):
    if(configType.lower()=="static"):
        path="/wm/staticflowpusher/json"
    elif(configType.lower()=="firewall"):
        path="/wm/firewall/rules/json"

    headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
    }
    userInput = json.dumps(userInput)
    conn = httplib.HTTPConnection(cIP, 8080)
    conn.request(method,path,userInput,headers)
    response = conn.getresponse()
    output = (response.status, response.reason, response.read())
    #print output
    conn.close()
    return output


############################ Module for Flask #######################

app = Flask(__name__)

#Function for index page
@app.route('/')
def startPage():
    bodyText=Markup("<b>SDN Topology Configuration -  User Input</b>")
    return render_template('index.html', bodyText=bodyText)

#page after action performed
@app.route('/actionStatus')
def actionStatus():
    return render_template("actionStatus.html")

#Function for static flow entries
@app.route('/form1')
def form1():
    return render_template("form1.html")

#Function for firewall flow entries
@app.route('/form2')
def form2():
    response=subprocess.check_output(["curl","http://192.168.56.101:8080/wm/staticflowentrypusher/clear/all/json"], stderr=subprocess.STDOUT, universal_newlines=True)
    print(response)
    return render_template("form2.html")

###############Function to record user input of static flow entries
@app.route('/recordUserInput1', methods=['POST'])
def recordUserInput1():
    DPID1=request.form['DPID1']
    priority1=request.form['priority1']
    inPort1=request.form['inPort1']
    ethType1=request.form['ethType1']
    destIP1=request.form['destIP1']
    action1=request.form['action1']

    DPID2=request.form['DPID2']
    priority2=request.form['priority2']
    inPort2=request.form['inPort2']
    ethType2=request.form['ethType2']
    destIP2=request.form['destIP2']
    action2=request.form['action2']

    DPIDZero1=DPID1.zfill(16)
    DPID1=":".join(DPIDZero1[i:i+2] for i in range(0,len(DPIDZero1),2))

    DPIDZero2=DPID2.zfill(16)
    DPID2=":".join(DPIDZero2[i:i+2] for i in range(0,len(DPIDZero2),2))

    global count
    if(DPID1==DPID2):
       flowARP1 = {
            "switch":DPID1,
            "name":"flow_mod-"+str(count),
            "priority":priority1,
            "eth_type": "0x0806",
            "actions":"output=flood"
            }
       print("flow-mod-"+str(count)+": ")
       print(post("192.168.56.101",flowARP1,"static"))
       count=count+1

    else:
        flowARP1 = {
            "switch":DPID1,
            "name":"flow_mod-"+str(count),
            "priority":priority1,
            "eth_type": 0x0806,
            "actions":"output=flood"
            }

        print("flow-mod-"+str(count)+": ")
        print(post("192.168.56.101",flowARP1,"static"))
        count=count+1

        flowARP2 = {
            "switch":DPID2,
            "name":"flow_mod-"+str(count),
            "priority":priority2,
            "eth_type": 0x0806,
            "actions":"output=flood"
            }

        print("flow-mod-"+str(count)+": ")
        print(post("192.168.56.101",flowARP2,"static"))
        count=count+1

    if(DPID1==DPID2):
        flowStatic1 = {
            "switch":DPID1,
            "name":"flow_mod-"+str(count),
            "priority":priority1,
            "in_port":inPort1,
            "eth_type":ethType1,
            "ipv4_dst":destIP1,
            "actions":"output="+action1
            }

        print("flow-mod-"+str(count)+": ")
        print(post("192.168.56.101",flowStatic1,"static"))
        count=count+1

    else:
        flowStatic1 = {
            "switch":DPID1,
            "name":"flow_mod-"+str(count),
            "priority":priority1,
            "in_port":inPort1,
            "eth_type":ethType1,
            "ipv4_dst":destIP1,
            "actions":"output="+action1
            }

        print("flow-mod-"+str(count)+": ")
        print(post("192.168.56.101",flowStatic1,"static"))
        count=count+1

        flowStaticReverse1 = {
            "switch":DPID1,
            "name":"flow_mod-"+str(count),
            "priority":priority1,
            "in_port":action1,
            "eth_type":ethType1,
            "ipv4_dst":destIP2,
            "actions":"output="+inPort1
            }

        print("flow-mod-"+str(count)+": ")
        print(post("192.168.56.101",flowStaticReverse1,"static"))
        count=count+1
        
    if(DPID1==DPID2):
        flowStatic2 = {
            "switch":DPID2,
            "name":"flow_mod-"+str(count),
            "priority":priority2,
            "in_port":inPort2,
            "eth_type":ethType2,
            "ipv4_dst":destIP2,
            "actions":"output="+action2
            } 

        print("flow-mod-"+str(count)+": ")
        print(post("192.168.56.101",flowStatic2,"static"))
        count=count+1

    else:
        flowStatic2 = {
            "switch":DPID2,
            "name":"flow_mod-"+str(count),
            "priority":priority2,
            "in_port":inPort2,
            "eth_type":ethType2,
            "ipv4_dst":destIP2,
            "actions":"output="+action2
            } 

        print("flow-mod-"+str(count)+": ")
        print(post("192.168.56.101",flowStatic2,"static"))
        count=count+1

        flowStaticReverse2 = {
            "switch":DPID2,
            "name":"flow_mod-"+str(count),
            "priority":priority2,
            "in_port":action2,
            "eth_type":ethType2,
            "ipv4_dst":destIP1,
            "actions":"output="+inPort2
            } 

        count=count+1
        print("flow-mod-"+str(count)+": ")
        print(post("192.168.56.101",flowStaticReverse2,"static"))

    return actionStatus()

##############Function to record user input of firewall flow entries
@app.route('/recordUserInput2', methods=['POST'])
def recordUserInput2():
    DPID1=request.form['DPID1']
    priority1=request.form['priority1']
    inPort1=request.form['inPort1']
    ethType1=request.form['ethType1']
    srcIP1=request.form['srcIP1']
    destIP1=request.form['destIP1']
    l4Protocol1=request.form['l4Protocol1'].upper()

    DPID2=request.form['DPID2']
    priority2=request.form['priority2']
    inPort2=request.form['inPort2']
    ethType2=request.form['ethType2']
    srcIP2=request.form['srcIP2']
    destIP2=request.form['destIP2']
    l4Protocol2=request.form['l4Protocol2'].upper()

    DPIDZero1=DPID1.zfill(16)
    DPID1=":".join(DPIDZero1[i:i+2] for i in range(0,len(DPIDZero1),2))

    DPIDZero2=DPID2.zfill(16)
    DPID2=":".join(DPIDZero2[i:i+2] for i in range(0,len(DPIDZero2),2))

    global count

    if((ethType1=="")and((l4Protocol2=="ICMP")or(l4Protocol2=="TCP")or(l4Protocol2=="UDP"))):
        flowFirewall = {
            "switch":DPID1,
            "priority":priority1,
            "src-ip":srcIP1,
            "dst-ip":destIP1,
            "dl-type":"ARP"
            }
        print(post("192.168.56.101",flowFirewall,"firewall"))
        flowStaticARP = {
            "switch":DPID1,
            "name":"flow_mod-"+str(count),
            "priority":priority1,
            "eth_type":"0x0806",
            "actions":"output=flood"
            }

        count=count+1
        print("flow-mod-"+str(count)+": ")
        print(post("192.168.56.101",flowStaticARP,"static"))

        flowFirewall = {
            "switch":DPID1,
            "priority":priority1,
            "src-ip":srcIP1,
            "dst-ip":destIP1,
            "nw-proto":l4Protocol1
            }

        print(post("192.168.56.101",flowFirewall,"firewall"))
        if(DPID1==DPID2):
            if(l4Protocol1=="UDP"):
                flowStatic = {
                    "switch":DPID1,
                    "name":"flow_mod-"+str(count),
                    "priority":priority1,
                    "in_port":inPort1,
                    "ipv4_src":srcIP1,
                    "ipv4_dst":destIP1,
                    "eth_type":"0x0800",
                    "ip_proto":"0x11",
                    "actions":"output="+inPort2
                    }
            elif(l4Protocol1=="TCP"):
                flowStatic = {
                    "switch":DPID1,
                    "name":"flow_mod-"+str(count),
                    "priority":priority1,
                    "in_port":inPort1,
                    "ipv4_src":srcIP1,
                    "ipv4_dst":destIP1,
                    "eth_type":"0x0800",
                    "ip_proto":"0x06",
                    "actions":"output="+inPort2
                    }
            elif(l4Protocol1=="ICMP"):
                flowStatic = {
                    "switch":DPID1,
                    "name":"flow_mod-"+str(count),
                    "priority":priority1,
                    "in_port":inPort1,
                    "ipv4_src":srcIP1,
                    "ipv4_dst":destIP1,
                    "eth_type":"0x0800",
                    "ip_proto":"0x01",
                    "actions":"output="+inPort2
                    }

        else:
            if(l4Protocol1=="UDP"):
                flowStatic = {
                    "switch":DPID1,
                    "name":"flow_mod-"+str(count),
                    "priority":priority1,
                    "in_port":inPort1,
                    "ipv4_src":srcIP1,
                    "ipv4_dst":destIP1,
                    "eth_type":"0x0800",
                    "ip_proto":"0x11",
                    "actions":"output=3"
                    }
            elif(l4Protocol1=="TCP"):
                flowStatic = {
                    "switch":DPID1,
                    "name":"flow_mod-"+str(count),
                    "priority":priority1,
                    "in_port":inPort1,
                    "ipv4_src":srcIP1,
                    "ipv4_dst":destIP1,
                    "eth_type":"0x0800",
                    "ip_proto":"0x06",
                    "actions":"output=3"
                    }
            elif(l4Protocol1=="ICMP"):
                flowStatic = {
                    "switch":DPID1,
                    "name":"flow_mod-"+str(count),
                    "priority":priority1,
                    "in_port":inPort1,
                    "ipv4_src":srcIP1,
                    "ipv4_dst":destIP1,
                    "eth_type":"0x0800",
                    "ip_proto":"0x01",
                    "actions":"output=3"
                    }

            if(l4Protocol1=="UDP"):
                count=count+1
                flowStaticReverse = {
                    "switch":DPID1,
                    "name":"flow_mod-"+str(count),
                    "priority":priority1,
                    "in_port":3,
                    "ipv4_src":destIP1,
                    "ipv4_dst":srcIP1,
                    "eth_type":"0x0800",
                    "ip_proto":"0x11",
                    "actions":"output="+inPort1
                    }

            elif(l4Protocol1=="TCP"):
                count=count+1
                flowStaticReverse = {
                    "switch":DPID1,
                    "name":"flow_mod-"+str(count),
                    "priority":priority1,
                    "in_port":3,
                    "ipv4_src":destIP1,
                    "ipv4_dst":srcIP1,
                    "eth_type":"0x0800",
                    "ip_proto":"0x06",
                    "actions":"output="+inPort1
                    }

            elif(l4Protocol1=="ICMP"):
                count=count+1
                flowStaticReverse = {
                    "switch":DPID1,
                    "name":"flow_mod-"+str(count),
                    "priority":priority1,
                    "in_port":3,
                    "ipv4_src":destIP1,
                    "ipv4_dst":srcIP1,
                    "eth_type":"0x0800",
                    "ip_proto":"0x01",
                    "actions":"output="+inPort1
                    }

            count=count+1
            print("flow-mod-"+str(count)+": ")
            print(post("192.168.56.101",flowStaticReverse,"static"))

        count=count+1
        print("flow-mod-"+str(count)+": ")
        print(post("192.168.56.101",flowStatic,"static"))

    elif((ethType1=="0x0806")and(l4Protocol2=="")):
        flowFirewall = {
            "switch":DPID1,
            "priority":priority1,
            "src-ip":srcIP1,
            "dst-ip":destIP1,
            "dl-type":"ARP"
            }        
        print(post("192.168.56.101",flowFirewall,"firewall"))
        flowStaticARP = {
            "switch":DPID1,
            "name":"flow_mod-"+str(count),
            "priority":priority1,
            "eth_type":"0x0806",
            "actions":"output=flood"
            }

        count=count+1
        print("flow-mod-"+str(count)+": ")
        print(post("192.168.56.101",flowStaticARP,"static"))

    if((ethType2=="")and((l4Protocol2=="ICMP")or(l4Protocol2=="UDP")or(l4Protocol2=="TCP"))):
        flowFirewall = {
            "switch":DPID2,
            "priority":priority2,
            "src-ip":destIP2,
            "dst-ip":srcIP2,
            "dl-type":"ARP"
            }

        print(post("192.168.56.101",flowFirewall,"firewall"))
        flowStaticARP = {
            "switch":DPID2,
            "name":"flow_mod-"+str(count),
            "priority":priority2,
            "eth_type":"0x0806",
            "actions":"output=flood"
            }

        count=count+1
        print("flow-mod-"+str(count)+": ")
        print(post("192.168.56.101",flowStaticARP,"static"))

        flowFirewall = {
            "switch":DPID2,
            "priority":priority2,
            "src-ip":destIP2,
            "dst-ip":srcIP2,
            "nw-proto":l4Protocol2
            }
        print(post("192.168.56.101",flowFirewall,"firewall"))

        if(DPID1==DPID2):
            if(l4Protocol2=="UDP"):
                flowStatic = {
                    "switch":DPID2,
                    "name":"flow_mod-"+str(count),
                    "priority":priority2,
                    "in_port":inPort2,
                    "ipv4_src":srcIP2,
                    "ipv4_dst":destIP2,
                    "eth_type":"0x0800",
                    "ip_proto":"0x11",
                    "actions":"output="+inPort1
                    }
            if(l4Protocol2=="TCP"):
                flowStatic = {
                    "switch":DPID2,
                    "name":"flow_mod-"+str(count),
                    "priority":priority2,
                    "in_port":inPort2,
                    "ipv4_src":srcIP2,
                    "ipv4_dst":destIP2,
                    "eth_type":"0x0800",
                    "ip_proto":"0x06",
                    "actions":"output="+inPort1
                    }
            if(l4Protocol2=="ICMP"):
                flowStatic = {
                    "switch":DPID2,
                    "name":"flow_mod-"+str(count),
                    "priority":priority2,
                    "in_port":inPort2,
                    "ipv4_src":srcIP2,
                    "ipv4_dst":destIP2,
                    "eth_type":"0x0800",
                    "ip_proto":"0x01",
                    "actions":"output="+inPort1
                    }

        else:
            if(l4Protocol2=="UDP"):
                flowStatic = {
                    "switch":DPID2,
                    "name":"flow_mod-"+str(count),
                    "priority":priority2,
                    "in_port":inPort2,
                    "ipv4_src":srcIP2,
                    "ipv4_dst":destIP2,
                    "eth_type":"0x0800",
                    "ip_proto":"0x11",
                    "actions":"output=3"
                    }
            elif(l4Protocol2=="TCP"):
                flowStatic = {
                    "switch":DPID2,
                    "name":"flow_mod-"+str(count),
                    "priority":priority2,
                    "in_port":inPort2,
                    "ipv4_src":srcIP2,
                    "ipv4_dst":destIP2,
                    "eth_type":"0x0800",
                    "ip_proto":"0x06",
                    "actions":"output=3"
                    }
            elif(l4Protocol2=="ICMP"):
                flowStatic = {
                    "switch":DPID2,
                    "name":"flow_mod-"+str(count),
                    "priority":priority2,
                    "in_port":inPort2,
                    "ipv4_src":srcIP2,
                    "ipv4_dst":destIP2,
                    "eth_type":"0x0800",
                    "ip_proto":"0x01",
                    "actions":"output=3"
                    }

            if(l4Protocol2=="UDP"):
                count=count+1
                flowStaticReverse = {
                    "switch":DPID2,
                    "name":"flow_mod-"+str(count),
                    "priority":priority2,
                    "in_port":3,
                    "ipv4_src":destIP2,
                    "ipv4_dst":srcIP2,
                    "eth_type":"0x0800",
                    "ip_proto":"0x011",
                    "actions":"output="+inPort2
                    }
            elif(l4Protocol2=="TCP"):
                count=count+1
                flowStaticReverse = {
                    "switch":DPID2,
                    "name":"flow_mod-"+str(count),
                    "priority":priority2,
                    "in_port":3,
                    "ipv4_src":destIP2,
                    "ipv4_dst":srcIP2,
                    "eth_type":"0x0800",
                    "ip_proto":"0x06",
                    "actions":"output="+inPort2
                    }
            elif(l4Protocol2=="ICMP"):
                count=count+1
                flowStaticReverse = {
                    "switch":DPID2,
                    "name":"flow_mod-"+str(count),
                    "priority":priority2,
                    "in_port":3,
                    "ipv4_src":destIP2,
                    "ipv4_dst":srcIP2,
                    "eth_type":"0x0800",
                    "ip_proto":"0x01",
                    "actions":"output="+inPort2
                    }

            count=count+1
            print("flow-mod-"+str(count)+": ")
            print(post("192.168.56.101",flowStaticReverse,"static"))

        count=count+1
        print("flow-mod-"+str(count)+": ")
        print(post("192.168.56.101",flowStatic,"static"))

    elif((ethType2=="0x0806")and(l4Protocol2=="")):
        flowFirewall = {
            "switch":DPID2,
            "priority":priority2,
            "src-ip":destIP2,
            "dst-ip":srcIP2,
            "dl-type":"ARP"
            }

        print(post("192.168.56.101",flowFirewall,"firewall"))
        flowStaticARP = {
            "switch":DPID2,
            "name":"flow_mod-"+str(count),
            "priority":priority2,
            "eth_type":"0x0806",
            "actions":"output=flood"
            }

        count=count+1
        print("flow-mod-"+str(count)+": ")
        print(post("192.168.56.101",flowStaticARP,"static"))

    return actionStatus()

if __name__ == '__main__':
    app.debug = True
    app.run(host='127.0.0.1', port=8888)
