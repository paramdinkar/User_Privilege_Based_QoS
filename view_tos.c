#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>

static struct nf_hook_ops netfilter_ops_in; /* NF_IP_PRE_ROUTING */
unsigned int src_port =0;
unsigned int dest_port = 0;
unsigned int src_ip =0;
unsigned int dest_ip = 0;

struct udphdr *udp_header;
struct tcphdr *tcp_header;
struct iphdr *ip_header;
struct icmphdr *icmph;


unsigned int main_hook(unsigned int hooknum,
                  struct sk_buff *skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
{

if(!skb)
{
return NF_ACCEPT;
}


//get ip header
ip_header = (struct iphdr *)ip_hdr(skb);
src_ip = ip_header->saddr;
dest_ip = ip_header->daddr;

printk(KERN_ALERT "src ip %d\n", src_ip);
printk(KERN_ALERT "dest ip %d\n", dest_ip);
printk(KERN_ALERT "The tos bits are: %04x\n", (unsigned short) ip_header->check);


return NF_ACCEPT;
}


int init_module1(void)
{
	netfilter_ops_in.hook = main_hook;
	netfilter_ops_in.pf = PF_INET;
	netfilter_ops_in.hooknum = NF_INET_PRE_ROUTING;
	netfilter_ops_in.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&netfilter_ops_in); /* register NF_IP_PRE_ROUTING hook */
	return 0;
}

void cleanup_module1(void)
{
	nf_unregister_hook(&netfilter_ops_in); /*unregister NF_IP_PRE_ROUTING hook*/
}

module_init(init_module1); 
module_exit(cleanup_module1);