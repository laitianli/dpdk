#include <netinet/in.h>
#include <rte_kvargs.h>
#include <rte_pdump.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include "pdump_filter.h"

#define PDUMP_FILTER_DELIM  "/"

struct proto_name {
    unsigned short proto;
    const char* name;
} proto_n[] = {
    {
        .proto = IPPROTO_ICMP,
        .name = "icmp",
    },
    {
        .proto = IPPROTO_TCP,
        .name = "tcp",
    },
    {
        .proto = IPPROTO_UDP,
        .name = "udp",
    },
    {
        .proto = RTE_ETHER_TYPE_ARP,
        .name = "arp",
    },
    {
        .proto = 0,
        .name = NULL,
    },
};

struct parse_filter_val {
    uint64_t min;
    uint64_t max;
    uint64_t val;
};

static const char * const valid_pdump_filter_arguments[] = {
    FILTER_COUNT,
    FILTER_SIZE,
    FILTER_ETHER,
    FILTER_ETHER_SRC,
    FILTER_ETHER_DST,
    FILTER_HOST,
    FILTER_HOST_SRC,
    FILTER_HOST_DST,
    FILTER_NET,
    FILTER_NET_SRC,
    FILTER_NET_DST,
    FILTER_PORT,
    FILTER_PORT_SRC,
    FILTER_PORT_DST,
    FILTER_PROTO,
    NULL
};

struct pdump_filter* dp_filter = NULL;

static void dump_pdump_filter(struct pdump_filter* pf)
{
    int i = 0;
    printf("->filter flags: 0x%016"PRIx64"\n", pf->filter_flags);
    if (pf->filter_flags & FILTER_COUNT_FLAGS) {
        printf("->filter count: %u\n", pf->cs.count);
    }
    if (pf->filter_flags & FILTER_SIZE_FLAGS) {
        printf("->filter size: %u\n", pf->cs.size);
    }
    if (pf->filter_flags & FILTER_ETHER_FLAGS) {
        printf("->filter ether: ");
        for (i = 0; i < pf->ether.s; i++) {
            printf("%02x:%02x:%02x:%02x:%02x:%02x, ",
                pf->ether.eths[i].mac[0], pf->ether.eths[i].mac[1],
                pf->ether.eths[i].mac[2], pf->ether.eths[i].mac[3],
                pf->ether.eths[i].mac[4], pf->ether.eths[i].mac[5]);
        }
        printf("\n");
    }
    if (pf->filter_flags & FILTER_ETHER_SRC_FLAGS) {
        printf("->filter ether_src: ");
        for (i = 0; i < pf->ether_src.s; i++) {
            printf("%02x:%02x:%02x:%02x:%02x:%02x, ",
                pf->ether_src.eths[i].mac[0], pf->ether_src.eths[i].mac[1],
                pf->ether_src.eths[i].mac[2], pf->ether_src.eths[i].mac[3],
                pf->ether_src.eths[i].mac[4], pf->ether_src.eths[i].mac[5]);
        }
        printf("\n");
    }
    if (pf->filter_flags & FILTER_ETHER_DST_FLAGS) {
        printf("->filter ether_dst: ");
        for (i = 0; i < pf->ether_dst.s; i++) {
            printf("%02x:%02x:%02x:%02x:%02x:%02x, ",
                pf->ether_dst.eths[i].mac[0], pf->ether_dst.eths[i].mac[1],
                pf->ether_dst.eths[i].mac[2], pf->ether_dst.eths[i].mac[3],
                pf->ether_dst.eths[i].mac[4], pf->ether_dst.eths[i].mac[5]
                );
        }
        printf("\n");
    }
    uint32_t ip = 0;
    if (pf->filter_flags & FILTER_HOST_FLAGS) {
        printf("->filter host: ");
        for (i = 0; i < pf->host.s; i++) {
            ip = pf->host.ips[i];
            printf("%d.%d.%d.%d, ", ip & 0xFF, (ip  & 0x0000FF00) >> 8, (ip & 0x00FF0000) >> 16 , (ip & 0xFF000000) >> 24);
        }
        printf("\n");
    }
    if (pf->filter_flags & FILTER_HOST_SRC_FLAGS) {
        printf("->filter host_src: ");
        for (i = 0; i < pf->h_src.s; i++) {
            ip = pf->h_src.ips[i];
            printf("%d.%d.%d.%d, ", ip & 0xFF, (ip  & 0x0000FF00) >> 8, (ip & 0x00FF0000) >> 16 , (ip & 0xFF000000) >> 24);
        }
        printf("\n");
    }
    if (pf->filter_flags & FILTER_HOST_DST_FLAGS) {
        printf("->filter host_dst: ");
        for (i = 0; i < pf->h_dst.s; i++) {
            ip = pf->h_dst.ips[i];
            printf("%d.%d.%d.%d, ", ip & 0xFF, (ip  & 0x0000FF00) >> 8, (ip & 0x00FF0000) >> 16 , (ip & 0xFF000000) >> 24);
        }
        printf("\n");
    }
    if (pf->filter_flags & FILTER_NET_FLAGS) {
        printf("->filter net: ");
        for (i = 0; i < pf->net.s; i++) {
            ip = pf->net.ips[i];
            printf("%d.%d.%d.%d, ", ip & 0xFF, (ip  & 0x0000FF00) >> 8, (ip & 0x00FF0000) >> 16 , (ip & 0xFF000000) >> 24);
        }
        printf("\n");
    }
    if (pf->filter_flags & FILTER_NET_SRC_FLAGS) {
        printf("->filter net_src: ");
        for (i = 0; i < pf->n_src.s; i++) {
            ip = pf->n_src.ips[i];
            printf("%d.%d.%d.%d, ", ip & 0xFF, (ip  & 0x0000FF00) >> 8, (ip & 0x00FF0000) >> 16 , (ip & 0xFF000000) >> 24);
        }
        printf("\n");
    }
    if (pf->filter_flags & FILTER_NET_DST_FLAGS) {
        printf("->filter net_dst: ");
        for (i = 0; i < pf->n_dst.s; i++) {
            ip = pf->n_dst.ips[i];
            printf("%d.%d.%d.%d, ", ip & 0xFF, (ip  & 0x0000FF00) >> 8, (ip & 0x00FF0000) >> 16 , (ip & 0xFF000000) >> 24);
        }
        printf("\n");
    }
    if (pf->filter_flags & FILTER_PORT_FLAGS) {
        printf("->filter port: ");
        for (i = 0; i < pf->port.s; i++) {
            printf("%d, ", pf->port.ports[i]);
        }
        printf("\n");
    }
    if (pf->filter_flags & FILTER_PORT_SRC_FLAGS) {
        printf("->filter port_src: ");
        for (i = 0; i < pf->port_src.s; i++) {
            printf("%d, ", pf->port_src.ports[i]);
        }
        printf("\n");
    }
    if (pf->filter_flags & FILTER_PORT_DST_FLAGS) {
        printf("->filter port_src: ");
        for (i = 0; i < pf->port_dst.s; i++) {
            printf("%d, ", pf->port_dst.ports[i]);
        }
        printf("\n");
    }
    if (pf->filter_flags & FILTER_PROTO_FLAGS) {
        printf("->filter proto: ");
        for (i = 0; i < pf->protos.s; i++) {
            printf("%d, ", pf->protos.pro[i]);
        }
        printf("\n");
    }
}

static int
__parse_uint_value(const char *key, const char *value, void *extra_args)
{
    struct parse_filter_val *v;
    unsigned long t;
    char *end;
    int ret = 0;

    errno = 0;
    v = extra_args;
    t = strtoul(value, &end, 10);

    if (errno != 0 || end[0] != 0 || t < v->min || t > v->max) {
        printf("invalid value:\"%s\" for key:\"%s\", "
            "value must be >= %"PRIu64" and <= %"PRIu64"\n",
            value, key, v->min, v->max);
        ret = -EINVAL;
    }
    if (ret != 0)
        return ret;

    v->val = t;
    return 0;
}

static int
__parse_size(const char *key __rte_unused, const char *value,
        void *extra_args)
{
    const char* str_size = NULL;
    char* p = NULL;
    char *end;
    //int ret = 0;
    int size = 0;
    struct pdump_filter *pf = extra_args;

    str_size = strdup(value);
    if ((p = strchr(str_size, 'K')) || (p = strchr(str_size, 'k'))) {
        size = strtoul(str_size, &end, 10) * 1024;
    }
    else if ((p = strchr(str_size, 'M')) || (p = strchr(str_size, 'm'))) {
        size = strtoul(str_size, &end, 10) * 1024 * 1024;
    }   
    else if ((p = strchr(str_size, 'G')) || (p = strchr(str_size, 'g'))) {
        size = strtoul(str_size, &end, 10) * 1024 * 1024 * 1024;
    }
    else {
        size = strtoul(str_size, &end, 10);
    }
    pf->cs.size = (uint32_t)size;
    return 0;
}
static int 
__check_is_mac(const char* mac, unsigned char *a, unsigned char* b, unsigned char* c,
        unsigned char* d, unsigned char* e, unsigned char* f)
{
    int len = sscanf(mac, "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX", a, b, c, d, e, f);
    if(len != 6) {
        printf("[Error]| %s | (len:%d) is not mac address.\n", mac, len);
        return -1;
    }
    return 0;
}


static int 
__check_is_ip(const char* ip, unsigned char *a, unsigned char* b, unsigned char* c,
        unsigned char* d)
{
    int len = sscanf(ip, "%hhu.%hhu.%hhu.%hhu", a, b, c, d);
    printf("===strip: %s, ip: %d.%d.%d.%d\n", ip, *a, *b, *c, *d);
    if(len != 4) {
        printf("[Error]| %s | (len:%d) is not ip address.\n", ip, len);
        return -1;
    }
    return 0;
}


static int __parse_mac(const char* val, void* arg)
{
    char *str_mac = strdup(val);
    if (!str_mac) {
        printf("[Error] strdup error\n");
        return -1;
    }
    struct ether_info* info = (struct ether_info*)arg;
    char* p = NULL;
    char* cur = str_mac;
    int ret = 0;
    int i = 0;
    while (cur && (p = strstr(cur, PDUMP_FILTER_DELIM))) {
        *p = '\0';
        ret = __check_is_mac(cur, &info->eths[i].mac[0], &info->eths[i].mac[1], &info->eths[i].mac[2], 
            &info->eths[i].mac[3], &info->eths[i].mac[4], &info->eths[i].mac[5]);
        if(!ret) {
            i++;
        }
        cur = p + 1;
    }

    if (cur && *cur != '\0') {
        ret = __check_is_mac(cur, &info->eths[i].mac[0], &info->eths[i].mac[1], &info->eths[i].mac[2], 
            &info->eths[i].mac[3], &info->eths[i].mac[4], &info->eths[i].mac[5]);
        if(!ret) {
            i++;
        }
    }
    info->s = i;
    free(str_mac);
    return i;
}

static int __parse_ip(const char* val, void* arg)
{
    char *str_mac = strdup(val);
    if (!str_mac) {
        printf("[Error] strdup error\n");
        return -1;
    }
    struct ip_info* info = (struct ip_info*)arg;
    char* p = NULL;
    char* cur = str_mac;
    int ret = 0;
    int i = 0;
    unsigned char a, b, c, d;
    while (cur && (p = strstr(cur, PDUMP_FILTER_DELIM))) {
        *p = '\0';
        ret = __check_is_ip(cur, &a, &b, &c, &d);
        if(!ret) {
            info->ips[i] = ((d << 24) | (c << 16) | (b << 8) | a);
            i++;
        }
        cur = p + 1;
    }

    if (cur && *cur != '\0') {
        ret = __check_is_ip(cur, &a, &b, &c, &d);
        if(!ret) {
            info->ips[i] = ((d << 24) | (c << 16) | (b << 8) | a);
            i++;
        }
    }
    info->s = i;
    free(str_mac);
    return i;
}       

static int
__parse_ether(const char *key __rte_unused, const char *value,
        void *extra_args)
{
    __parse_mac(value, extra_args);
    return 0;
}

static int
__parse_ips(const char *key __rte_unused, const char *value,
        void *extra_args)
{
    __parse_ip(value, extra_args);
    return 0;
}

static int
__parse_net_ips(const char *key __rte_unused, const char *value,
        void *extra_args)
{
    printf("\033[31m [Warning]=TODO:====\033[0m\n");
    __parse_ip(value, extra_args);
    return 0;
}

static int
__parse_ports(const char *key __rte_unused, const char *value,
        void *extra_args)
{
    char *str_mac = strdup(value);
    if (!str_mac) {
        printf("[Error] strdup error\n");
        return -1;
    }
    struct port_info* info = (struct port_info*)extra_args;
    char* p = NULL;
    char* cur = str_mac;
    int i = 0;
    unsigned short port = 0;
    while (cur && (p = strstr(cur, PDUMP_FILTER_DELIM))) {
        *p = '\0';
        port = atoi(cur);
        if (port) {
            info->ports[i] = port;
            i++;
        }
        cur = p + 1;
    }

    if (cur && *cur != '\0') {
        port = atoi(cur);
        if (port) {
            info->ports[i] = port;
            i++;
        }
    }
    info->s = i;
    free(str_mac);
    return 0;
}

static int
__parse_proto(const char *key __rte_unused, const char *value,
        void *extra_args)
{
    char *str_mac = strdup(value);
    if (!str_mac) {
        printf("[Error] strdup error\n");
        return -1;
    }
    struct proto_info* info = (struct proto_info*)extra_args;
    char* p = NULL;
    char* cur = str_mac;
    int i = 0, j = 0;
    while (cur && (p = strstr(cur, PDUMP_FILTER_DELIM))) {
        *p = '\0';
        for (j = 0; proto_n[j].name != NULL; j++) {
            if (!strcmp(cur, proto_n[j].name)) {
                info->pro[i] = proto_n[j].proto;
                i++;
            }
        }
        cur = p + 1;
    }
    
    if (cur && *cur != '\0') {
        for (j = 0; proto_n[j].name != NULL; j++) {
            if (!strcmp(cur, proto_n[j].name)) {
                info->pro[i] = proto_n[j].proto;
                i++;
            }
        }
    }
    info->s = i;
    free(str_mac);

    return 0;
}


int pdump_filter_parse(const char* optarg)
{
    struct parse_filter_val v = {0};
    int cnt1 = 0, cnt2 = 0;
    int ret = 0;
    struct rte_kvargs *kvlist;
    kvlist = rte_kvargs_parse(optarg, valid_pdump_filter_arguments);
    if (kvlist == NULL) {
        printf("[Error] --filter=\"%s\": invalid argument passed\n", optarg);
        return -1;
    }
    cnt1 = rte_kvargs_count(kvlist, FILTER_COUNT);
    cnt2 = rte_kvargs_count(kvlist, FILTER_SIZE);
    if (cnt1 & cnt2) {
        printf("--filter=\"-c / -s \": invalid argument passed\n");
        return -1;
    }
    dp_filter = rte_malloc("dpdk_pdump_filter", 
        sizeof(struct pdump_filter), 0);
    if(!dp_filter) {
        printf("[Error] rte_malloc failed!\n");
        return -1;
    }
    memset(dp_filter, 0, sizeof(struct pdump_filter));
    if (cnt1 == 1) {
        v.min = 0;
        v.max = 0xFFFFFFFF;
        ret = rte_kvargs_process(kvlist, FILTER_COUNT, 
                &__parse_uint_value, &v);
        if (ret < 0)
            goto free_kvlist;
        dp_filter->filter_flags |= FILTER_COUNT_FLAGS;
        dp_filter->cs.count = v.val;        
    }
    if (cnt2 == 1) {
        ret = rte_kvargs_process(kvlist, FILTER_SIZE, 
                &__parse_size, dp_filter);
        if (ret < 0)
            goto free_kvlist;
        dp_filter->filter_flags |= FILTER_SIZE_FLAGS;
    }

    cnt1 = rte_kvargs_count(kvlist, FILTER_ETHER);
    if (cnt1 == 1) {
        ret = rte_kvargs_process(kvlist, FILTER_ETHER, 
                &__parse_ether, (void*)&dp_filter->ether);
        if (ret < 0)
            goto free_kvlist;
        dp_filter->filter_flags |= FILTER_ETHER_FLAGS;
    }
    
    cnt1 = rte_kvargs_count(kvlist, FILTER_ETHER_SRC);
    if (cnt1 == 1) {
        ret = rte_kvargs_process(kvlist, FILTER_ETHER_SRC, 
                &__parse_ether, (void*)&dp_filter->ether_src);
        if (ret < 0)
            goto free_kvlist;
        dp_filter->filter_flags |= FILTER_ETHER_SRC_FLAGS;
    }

    cnt1 = rte_kvargs_count(kvlist, FILTER_ETHER_DST);
    if (cnt1 == 1) {
        ret = rte_kvargs_process(kvlist, FILTER_ETHER_DST, 
                &__parse_ether, (void*)&dp_filter->ether_dst);
        if (ret < 0)
            goto free_kvlist;
        dp_filter->filter_flags |= FILTER_ETHER_DST_FLAGS;
    }

    cnt1 = rte_kvargs_count(kvlist, FILTER_HOST);
    if (cnt1 == 1) {
        ret = rte_kvargs_process(kvlist, FILTER_HOST, 
                &__parse_ips, (void*)&dp_filter->host);
        if (ret < 0)
            goto free_kvlist;
        dp_filter->filter_flags |= FILTER_HOST_FLAGS;
    }
    
    cnt1 = rte_kvargs_count(kvlist, FILTER_HOST_DST);
    if (cnt1 == 1) {
        ret = rte_kvargs_process(kvlist, FILTER_HOST_DST, 
                &__parse_ips, (void*)&dp_filter->h_dst);
        if (ret < 0)
            goto free_kvlist;
        dp_filter->filter_flags |= FILTER_HOST_DST_FLAGS;
    }

    cnt1 = rte_kvargs_count(kvlist, FILTER_HOST_SRC);
    if (cnt1 == 1) {
        ret = rte_kvargs_process(kvlist, FILTER_HOST_SRC, 
                &__parse_ips, (void*)&dp_filter->h_src);
        if (ret < 0)
            goto free_kvlist;
        dp_filter->filter_flags |= FILTER_HOST_SRC_FLAGS;
    }

    cnt1 = rte_kvargs_count(kvlist, FILTER_NET);
    if (cnt1 == 1) {
        ret = rte_kvargs_process(kvlist, FILTER_NET, 
                &__parse_net_ips, (void*)&dp_filter->net);
        if (ret < 0)
            goto free_kvlist;
        dp_filter->filter_flags |= FILTER_NET_FLAGS;
    }
    
    cnt1 = rte_kvargs_count(kvlist, FILTER_NET_SRC);
    if (cnt1 == 1) {
        ret = rte_kvargs_process(kvlist, FILTER_NET_SRC, 
                &__parse_net_ips, (void*)&dp_filter->n_src);
        if (ret < 0)
            goto free_kvlist;
        dp_filter->filter_flags |= FILTER_NET_SRC_FLAGS;
    }
    cnt1 = rte_kvargs_count(kvlist, FILTER_NET_DST);
    if (cnt1 == 1) {
        ret = rte_kvargs_process(kvlist, FILTER_NET_DST, 
                &__parse_net_ips, (void*)&dp_filter->n_dst);
        if (ret < 0)
            goto free_kvlist;
        dp_filter->filter_flags |= FILTER_NET_DST_FLAGS;
    }
    
    cnt1 = rte_kvargs_count(kvlist, FILTER_PORT);
    if (cnt1 == 1) {
        ret = rte_kvargs_process(kvlist, FILTER_PORT, 
                &__parse_ports, (void*)&dp_filter->port);
        if (ret < 0)
            goto free_kvlist;
        dp_filter->filter_flags |= FILTER_PORT_FLAGS;
    }

    cnt1 = rte_kvargs_count(kvlist, FILTER_PORT_DST);
    if (cnt1 == 1) {
        ret = rte_kvargs_process(kvlist, FILTER_PORT_DST, 
                &__parse_ports, (void*)&dp_filter->port_dst);
        if (ret < 0)
            goto free_kvlist;
        dp_filter->filter_flags |= FILTER_PORT_DST_FLAGS;
    }

    cnt1 = rte_kvargs_count(kvlist, FILTER_PORT_SRC);
    if (cnt1 == 1) {
        ret = rte_kvargs_process(kvlist, FILTER_PORT_SRC, 
                &__parse_ports, (void*)&dp_filter->port_src);
        if (ret < 0)
            goto free_kvlist;
        dp_filter->filter_flags |= FILTER_PORT_SRC_FLAGS;
    }

    cnt1 = rte_kvargs_count(kvlist, FILTER_PROTO);
    if (cnt1 == 1) {
        ret = rte_kvargs_process(kvlist, FILTER_PROTO, 
                &__parse_proto, (void*)&dp_filter->protos);
        if (ret < 0)
            goto free_kvlist;
        dp_filter->filter_flags |= FILTER_PROTO_FLAGS;
    }
    
    dump_pdump_filter(dp_filter);
    return 0;
    
free_kvlist:
    rte_kvargs_free(kvlist);
    return ret;

}


