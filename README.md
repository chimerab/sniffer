# redis-sniffer
a tool to parse redis tcpdump and analysis time consumed for each command.

single cpu core could handle approximate 600 packets/s 

## How to use it 

### Install it 

yum install git 
git clone https://github.com/chimerab/sniffer 
cd sniffer 
pip3 install virtualenv 
virtualenv -p /usr/bin/python3.7 venv 
. venv/bin/activate 
pip install -r requirements.txt 
deactivate
### Run it  
sudo su -
cd sniffer
. venv/bin/activate 
python capture.py eth0 <s3path> 

### Analyze the result

Athena table used to analysis the output 

CREATE EXTERNAL TABLE `redis`( 
  `time` string,  
  `src_ip` string,  
  `src_port` bigint,  
  `dst_ip` string, 
  `op` string,  
  `obj` string, 
  `key_len` bigint, 
  `value_len` bigint, 
  `timeconsumed` float) 
ROW FORMAT DELIMITED  
  FIELDS TERMINATED BY ','  
STORED AS INPUTFORMAT  
  'org.apache.hadoop.mapred.TextInputFormat'  
OUTPUTFORMAT  
  'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat' 
LOCATION 
  '<s3path>' 

