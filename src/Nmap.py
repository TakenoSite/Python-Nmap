import nmap 
import threading
import numpy as np
import time 

class Nmap:
    def __init__(self,**kwargs):

        self.nm = nmap.PortScanner()
        self.ip = kwargs["ip"]
        self.nm.scan(str(self.ip),arguments = kwargs["args"])
        
        self.ScanHis = []
    
    def TCP_REPORT(self):

        self.ScanHis.clear()
        if len(self.nm.all_hosts()) != 0:
            
            for host in self.nm.all_hosts():
                v1 = self.nm[host]
                v1_keys = v1.keys()
                i_a = v1["addresses"]
                i_a_keys = i_a.keys()

                ip_addresses =[i_a[r] for r in i_a_keys][0]
                
                for TCP in v1_keys:
                    if TCP in "tcp":
                        v1 = self.nm[host]
                        v2 = v1["tcp"]
                        v2_keys = v2.keys()
                        
                        port = [ip for ip in list(v2_keys)]

                        for v3 in v2_keys:
                            v4 = v2[v3]
                            v4_keys = v4.keys()
                            v4 =[v4[v6] for v6 in v4_keys]

                            self.ScanHis.append(v4) 
                    else:
                        port = [1]
                        v1 = {"host":0}
                        pass
        else:
                
            ip_addresses = self.ip
            port = [0]
            v1 = {"host":0} 
                
            pass 
        return ip_addresses,port,self.ScanHis,v1

TCPReportList,ALLReportList = [],[]
def RunThread(PROCESS_LIST:list,PROCESS_LIST_LEN:int,IP_LEN:int,ARGS:str):
    
    for IP in PROCESS_LIST:

        print("\033[34m[*]Scaning ... {ip} {op} \033[0m".format(ip=IP,op=ARGS))
        #print("\033[33m[*]Optins ... {op} \033[0m".format(op=ARGS))
        tcpReport = Nmap(ip=IP,args=ARGS).TCP_REPORT()
        
        IP = tcpReport[0]
        PROT = {"port":tcpReport[1]}
        REPORT = {"report":tcpReport[2]}
        ALL_REPORT = tcpReport[3]
        
        print("\033[33m[+] Completed .. {ip}\033[0m".format(ip=IP))
        
        MAIN_REPROT = PROT|REPORT
        DICT_REPORT = {IP:MAIN_REPROT}
        TCPReportList.append(DICT_REPORT)
        ALLReportList.append(ALL_REPORT)

    if IP_LEN == len(TCPReportList):
        Display()
        print("[*] completed")

def Thread(IP:str,ARGS=None,ThreadNum=1,TimeOut=300):
    
    THREAD_NUM = ThreadNum
    IP_LEN = len(IP)
    TIMEOUT = "--host-timeout "+str(TimeOut)
    AddArgs = {

            "timeout":str(TIMEOUT)

            }
    ARGS = str(ARGS) +" "+ str(AddArgs["timeout"])

    THREAD_PROCESS_LIST = np.array_split(IP,ThreadNum)
     
    if len(IP) < THREAD_NUM:
        print("Over Thread .. ")
        return 0

    else:
        for PROCESS_LIST in THREAD_PROCESS_LIST:
            PROCESS_LIST_LEN = len(PROCESS_LIST)     
            TH = threading.Thread(target=RunThread,args=(PROCESS_LIST,PROCESS_LIST_LEN,IP_LEN,ARGS))
            TH.start()
        TH.join() 

def Display():

    report = TCPReportList
    Scan_count = 0

    for v1 in report:
        print('\n\n{f} |{count}|'.format(f='*'*40,count=Scan_count))
        v1_keys = list(v1.keys())
        ip =  list(v1.keys())[0]
        for i in v1_keys:
            v2 = v1[i]
            v2_keys = list(v2.keys())
             
            port = v2['port']
            ScanReport= v2['report']
            ScanPort = port
            Scan_Port_Count = 1

            
            if ScanPort[0] == 0:
                show_info = """"
                \033[33m 

                IP      ===     {ip}
                
                {message}
                    
                \033[0m""".format(ip=ip,message="No Conection...")
                print(show_info)
                
                pass 
            
            elif ScanPort[0] == 1:
                show_info= """
                \033[33m 
                IP    ===      {IP}
                
                {message}
                
                \033[0m""".format(IP = ip, message = "No Open Port ...")
                print(show_info)
                
                pass 
        
            for ScanPort,ScanReport in zip(ScanPort,ScanReport):
                show_info = """
                \033[33m
                IP         ===  {ip}
                COUNT      ===  {count}
                PORT       ===  {port}
                JOB        ===  {job}
                JOBNAME    ===  {jobname}
                JOBVARSION ===  {jobvarsion}

                KEYs       ===  {key}  
                
                \033[0m
                """.format(
                        ip = ip,
                        count = ScanReport[0],
                        port = ScanPort,
                        job = ScanReport[2],
                        jobname = ScanReport[3],
                        jobvarsion =  ScanReport[4],
                        key = v2_keys
                        )
                print(show_info)
                
                for vuln in ScanReport:
                    if type(vuln)  is dict:
                        vuln_info = list(vuln.keys())
                        
                        for vuln_key in vuln_info:
                            print("\033[33m                 {}\033[0m".format(vuln[vuln_key]))
                
                
                if Scan_Port_Count == 15:
                    ScanPortLen = len(list(port))
                    print("\033[33m\n\nOutLine ... Remaining Line are {}\033[0m".format(ScanPortLen))

                    break

                Scan_Port_Count += 1
                
        Scan_count += 1


