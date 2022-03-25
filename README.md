# sniffer
a tool to parse redis tcpdump and analysis time consumed for each command.

single cpu core could handle approximate 600 packets/s 

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
