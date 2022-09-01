# Module

1: Nmap.Thread
      
      IP:str,       # Target host in list only
      ARGS:str,     # Nmap option
      ThreadNum:int # Thread Select
      TimeOut:int   # TimeOut Count
      
  
# Execution
      
      [*]Scaning ... 192.168.2.103 -sV -O --host-timeout 300 
      [*]Scaning ... 192.168.2.141 -sV -O --host-timeout 300 
      [+] Completed .. 192.168.2.103
      [+] Completed .. 192.168.2.141


      **************************************** |0|


                      IP    ===      192.168.2.103

                      No Open Port ...




                      IP         ===  192.168.2.103
                      COUNT      ===  open
                      PORT       ===  1
                      JOB        ===  ftp
                      JOBNAME    ===  vsftpd
                      JOBVARSION ===  3.0.3

                      KEYs       ===  ['port', 'report']  





      **************************************** |1|


                      IP    ===      192.168.2.141

                      No Open Port ...




                      IP         ===  192.168.2.141
                      COUNT      ===  open
                      PORT       ===  1
                      JOB        ===  ftp
                      JOBNAME    ===  Microsoft ftpd
                      JOBVARSION ===  

                      KEYs       ===  ['port', 'report']  
                
                
                
    [*] completed
