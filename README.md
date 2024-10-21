# Development Individual Project : Code Development
# By: Cristhian M. Faria-Sancehz
# GitHub Link: https://github.com/crxs1/IoT-Hypothesis
# Hypthesis: " Can an anomaly/behaviour based IPS be used to defend an IoT System against commmon vulnerabilties as well as unforseen changes in behaviour?"

# The idea of this project was for me to investigate the above hypothesis in a modeled IoT client and controller simulation, ideally modelling a simple Home security distributed system. This was following the group system modelling exercise that was completed with vulnerabilities being identified and modeled in an AD tree, severity being assess using CVSS and then assesing potential mitigations. 

# This project was done using two python files with one being used to simulate an IoT Server (Server.py) with the other script being used to simulate common IoT Client functions one would expect from an embedded/realtime operating system. These functions include sending sensore data, changing configuration details, reading status information and querying information. While these functions could be the limit to what is seen with edge computng, I also opted to add a vulnerable logon portal for testing.

# For this project I attempted to use common anomaly and behaviour based detections to mitigate sone vulnerabilities listed in the AD tree. These vulnerabilities included exploiting default credentials, exploiting open ports and exploiting weak authentication methods. These alligned with certain top 10 OWASP entries for IoT systems like password-brute forcing. I also took into consideration the emerging security category with new behaviours and capabilities that may arise from these systems. With Anomaly based detection, I envisioned that any anomalous activity could be blocked while allowing for learned "good" behaviour being allowed.

# With this project I attempted using the Client to tests the connections which successfully blocked anomalous behaviour and brute force login attempts. The server was made intentionally vulnerable for testing.

# Vulnerabilities identified included default credentials, insecure communications(HTTP), Port Sniffing using wireshark, Machine in the Middle attacks and static credentials within the program.

# In conclusion, I believe that Anomaly Based IPS systems or modern NIDS systems can be a great way to protect IoT Systems such as the one I modeled. In this scenario, my program was very limited. It is also true that malicious activity could be learned, but paired with other security solutions such as heuristic and signature based blocking as well as others security configurations in a thorough Defense-in-Depth solution, this can be a very useful method to prevent emerging threats.

#In order to execute the code, the files need to be extracted and "Server.py" needs to be run. This will likely request networking permissions which are need. This will start the server which can be interacted with on a web client. In order to run the testing scripts and simulate a client, "client.py" can be run afterwards.
