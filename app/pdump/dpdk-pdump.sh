#!/bin/bash
PDUMP_BIN=./dpdk-pdump.ofp
OFP_NETDEV="0000:b8:00.0"
PDUMP_FILE_PATH=/home/haizhi/pcap/pdump
RX_DEV_NAME=${PDUMP_FILE_PATH}/rxtx.pcap
TX_DEV_NAME=${PDUMP_FILE_PATH}/rxtx.pcap

useage()
{
	def_mac="00:0C:29:86:3B:09"
	def_ip="10.88.20.127"
	def_port="2154"
	def_proto="udp"
	str_title="************************************dpdk抓包工具使用说明********************************************************"
	str_t_end="****************************************************************************************************************"
	str1="【参数说明】"
	str1_1="\t1.运行时若没有添加任何参数，则默认抓取网口[ $OFP_NETDEV ]的所有数据包。 按Ctrl+c停止抓包。"
	str1_2="\t2.参数-pcieid用来指定抓包网口。"
	str1_3="\t3.支持MAC地址、IP地址、端口和协议名过滤抓包。"
	str1_3_1="\t  3.1 MAC地址过滤参数格式：（三选一）\n\t\t -ether    <mac1>/.../<mac8>  : 指定MAC地址列表，最多8个，MAC间用符号\"/\"分隔。 \n\t\t -ether_src <mac1>/.../<mac8> : 指定源MAC地址列表，最多8个，MAC间用符号\"/\"分隔。 \n\t\t -ether_dst <mac1>/.../<mac8> : 指定目的MAC地址列表，最多8个，MAC间用符号\"/\"分隔。"
	str1_3_2="\t  3.2 IP地址过滤参数格式：（三选一）\n\t\t -host     <ip1>/.../<ip8> : 指定IP地址列表，最多8个，IP地址间用符号\"/\"分隔。\n\t\t -host_src <ip1>/.../<ip8> : 指定源IP地址列表，最多8个，IP地址间用符号\"/\"分隔。\n\t\t -host_dst <ip1>/.../<ip8> : 指定目的IP地址列表，最多8个，IP地址间用符号\"/\"分隔。"
	str1_3_3="\t  3.3 端口过滤参数格式：（三选一）\n\t\t -port     <port1>/.../<port8> : 指定端口列表，最多8个，端口间用符号\"/\"分隔。\n\t\t -port_src <port1>/.../<port8>  : 指定源端口列表，最多8个，端口间用符号\"/\"分隔。\n\t\t -port_dst <port1>/.../<port8>  : 指定目的端口列表，最多8个，端口间用符号\"/\"分隔。"
	str1_3_4="\t  3.4 协议名过滤参数格式：        \n\t\t -proto  <arp>/<icmp>/<tcp>/<udp> : 指定协议列表，最多8个，协议间用符号\"/\"分隔。"
	str1_4="\t4.支持按数据包个数和抓取数据总大小：（二选一）\n\t\t -c <count>       : 指定抓取的数据包个数。\n\t\t -s <size><K/M/G> : 指定抓取的数据总大小。"
	str2="【示    例】"
	str_example1="\t[01] ./dpdk-pdump.sh -pcieid $OFP_NETDEV -c 1000  #从网口[ $OFP_NETDEV ]抓取1000个数包。"
	str_example2="\t[02] ./dpdk-pdump.sh -pcieid $OFP_NETDEV -s 100M  #从网口[ $OFP_NETDEV ]抓取100MB数据。"
	str_example3="\t[03] ./dpdk-pdump.sh -pcieid $OFP_NETDEV -ether $def_mac  #从网口[ $OFP_NETDEV ]抓取源MAC或目的MAC地址是$def_mac的数据包。"
	str_example4="\t[04] ./dpdk-pdump.sh -pcieid $OFP_NETDEV -ether_src $def_mac  #从网口[ $OFP_NETDEV ]抓取源MAC地址是$def_mac的数据包。"
	str_example5="\t[05] ./dpdk-pdump.sh -pcieid $OFP_NETDEV -ether_dst $def_mac  #从网口[ $OFP_NETDEV ]抓取源MAC地址是$def_mac的数据包。"
	str_example6="\t[06] ./dpdk-pdump.sh -pcieid $OFP_NETDEV -host $def_ip  #从网口[ $OFP_NETDEV ]抓取IP地址$def_ip的数据包。"
	str_example7="\t[07] ./dpdk-pdump.sh -pcieid $OFP_NETDEV -host_src $def_ip  #从网口[ $OFP_NETDEV ]抓取源IP地址$def_ip的数据包。"
	str_example8="\t[08] ./dpdk-pdump.sh -pcieid $OFP_NETDEV -host_dst $def_ip  #从网口[ $OFP_NETDEV ]抓取目的IP地址$def_ip的数据包。"
	str_example9="\t[09] ./dpdk-pdump.sh -pcieid $OFP_NETDEV -port $def_port  #从网口[ $OFP_NETDEV ]抓取端口$def_port的数据包。"
	str_example9="\t[09] ./dpdk-pdump.sh -pcieid $OFP_NETDEV -port $def_port  #从网口[ $OFP_NETDEV ]抓取端口$def_port的数据包。"
	str_example10="\t[10] ./dpdk-pdump.sh -pcieid $OFP_NETDEV -port_src $def_port  #从网口[ $OFP_NETDEV ]抓取源端口$def_port的数据包。"
	str_example11="\t[11] ./dpdk-pdump.sh -pcieid $OFP_NETDEV -port_src $def_port  #从网口[ $OFP_NETDEV ]抓取目的端口$def_port的数据包。"
	str_example12="\t[12] ./dpdk-pdump.sh -pcieid $OFP_NETDEV -proto $def_proto  #从网口[ $OFP_NETDEV ]抓取UDP数据包。"
	str_example13="\t[13] ./dpdk-pdump.sh -pcieid $OFP_NETDEV -c 1000 -ether "00:01:13:11:22:33/00:ab:ac:1a:1b:bb" -host "10.88.20.127/10.88.20.98" -port "2154/1235/9999" -proto "udp"
			#抓取MAC地址是00:01:13:11:22:33或00:ab:ac:1a:1b:bb，且IP是10.88.20.127或10.88.20.98，且端口是2154或1235或9999的UDP报文，共抓取1000个包。"
	str_example14="\t[14] ./dpdk-pdump.sh -pcieid $OFP_NETDEV -s 500M -ether "00:01:13:11:22:33/00:ab:ac:1a:1b:bb" -host "10.88.20.127/10.88.20.98" -port "2154/1235/9999" -proto "udp"
			#抓取MAC地址是00:01:13:11:22:33或00:ab:ac:1a:1b:bb，且IP是10.88.20.127或10.88.20.98，且端口是2154或1235或9999的UDP报文，共抓取500Mo数据。"

	echo -e "\033[36m $str_title \033[0m"
	echo ""
	echo -e "\033[36m $str1 \033[0m"
	echo -e "\033[36m $str1_1 \033[0m"
	echo -e "\033[36m $str1_2 \033[0m"
	echo -e "\033[36m $str1_3 \033[0m"
	echo -e "\033[36m $str1_3_1 \033[0m"
	echo -e "\033[36m $str1_3_2 \033[0m"
	echo -e "\033[36m $str1_3_3 \033[0m"
	echo -e "\033[36m $str1_3_4 \033[0m"
	echo -e "\033[36m $str1_4 \033[0m"
	echo ""
	echo -e "\033[36m $str2 \033[0m"
	echo -e "\033[36m $str_example1 \033[0m"
	echo -e "\033[36m $str_example2 \033[0m"
	echo -e "\033[36m $str_example3 \033[0m"
	echo -e "\033[36m $str_example4 \033[0m"
	echo -e "\033[36m $str_example5 \033[0m"
	echo -e "\033[36m $str_example6 \033[0m"
	echo -e "\033[36m $str_example7 \033[0m"
	echo -e "\033[36m $str_example8 \033[0m"
	echo -e "\033[36m $str_example9 \033[0m"
	echo -e "\033[36m $str_example10 \033[0m"
	echo -e "\033[36m $str_example11 \033[0m"
	echo -e "\033[36m $str_example12 \033[0m"
	echo -e "\033[36m $str_example13 \033[0m"
	echo -e "\033[36m $str_example14 \033[0m"
	echo ""
	echo -e "\033[36m $str_t_end \033[0m"
 }

note_info()
{
	echo -e "\033[1;42;37m Dump NIC: ${OFP_NETDEV}, save rxtx file: ${RX_DEV_NAME}\033[0m"
	echo -e "\033[1;42;37m run cmd: $0 -help to show readme.\033[0m"

}
run_pdump()
{
    #${PDUMP_BIN} -w ${OFP_NETDEV} --file-prefix ofp -- --pdump "port=0,queue=0,rx-dev=${RX_DEV_NAME},tx-dev=${TX_DEV_NAME},total-num-mbufs=4096"
    arg=$@
    if [ ! -z "$arg" ];then
        echo "run cmd: ${PDUMP_BIN} -w ${OFP_NETDEV} --file-prefix ofp -- --pdump "port=0,queue=0,rx-dev=${RX_DEV_NAME},tx-dev=${TX_DEV_NAME}" --filter "$arg" "
        ${PDUMP_BIN} -w ${OFP_NETDEV} --file-prefix ofp -- --pdump "port=0,queue=0,rx-dev=${RX_DEV_NAME},tx-dev=${TX_DEV_NAME}" --filter "$arg"
    else
        ${PDUMP_BIN} -w ${OFP_NETDEV} --file-prefix ofp -- --pdump "port=0,queue=0,rx-dev=${RX_DEV_NAME},tx-dev=${TX_DEV_NAME}"
    fi
}

help_shell()
{
    result=$(echo $1 |grep -E '-help')
    if [ ! -z "$result" ];then
        useage;
		exit 0
    fi
}

main()
{
    filter=""
    c=""
    s=""
    help_shell $@

    while echo $1 | grep -q ^-; do
        eval $( echo $1 | sed 's/^-//' )=$2
        shift
        shift
    done

	if [ ! -d "${PDUMP_FILE_PATH}" ];then
		mkdir -p ${PDUMP_FILE_PATH}
	fi

    if [ ! -z "$pcieid" ];then
        if [[ ! -z $(echo $pcieid | grep ":" ) ]] && [[ ! -z $(echo $pcieid | grep "\." ) ]]  ;then
            OFP_NETDEV=$pcieid
        fi
    fi

	note_info;

    if [[ ! -z "$c" ]] && [[ ! -z "$s" ]];then
        echo -e "\033[031m [Error] argument [ -c , -s ] can't be set at the same time!\033[0m"
        exit -1;
    fi

    if [ ! -z "$c" ];then
        filter+="count=$c"
        filter+=","
    fi
    if [ ! -z "$s" ];then
        filter+="size=$s"
        filter+=","
    fi

    if [ ! -z "$split" ];then
        filter+="split=$split"
        filter+=","
    fi

    if [ ! -z "$ether" ];then
        filter+="ether=$ether"
        filter+=","
    fi

    if [ ! -z "$ether_src" ];then
        filter+="ether_src=$ether_src"
        filter+=","
    fi

    if [ ! -z "$ether_dst" ];then
        filter+="ether_dst=$ether_dst"
        filter+=","
    fi

    if [ ! -z "$host" ];then
        filter+="host=$host"
        filter+=","
    fi

    if [ ! -z "$host_dst" ];then
        filter+="host_dst=$host_dst"
        filter+=","
    fi

    if [ ! -z "$host_src" ];then
        filter+="host_src=$host_src"
        filter+=","
    fi

    if [ ! -z "$net" ];then
        filter+="net=$net"
        filter+=","
    fi

    if [ ! -z "$net_src" ];then
        filter+="net_src=$net_src"
        filter+=","
    fi

    if [ ! -z "$net_dst" ];then
        filter+="net_dst=$net_dst"
        filter+=","
    fi

    if [ ! -z "$port" ];then
        filter+="port=$port"
        filter+=","
    fi

    if [ ! -z "$port_src" ];then
        filter+="port_src=$port_src"
        filter+=","
    fi

    if [ ! -z "$port_dst" ];then
        filter+="port_dst=$port_dst"
        filter+=","
    fi

    if [ ! -z "$proto" ];then
        filter+="proto=$proto"
        filter+=","
    fi

    run_pdump $filter
}

main $@;
